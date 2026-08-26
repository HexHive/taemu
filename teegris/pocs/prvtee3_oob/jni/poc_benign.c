// PRVTEE-3 dynamic repro (BENIGN control) — cmd 42754 (0xA702 unwrapGakBlob).
// Same code path as poc.c, but the tag-15 record sits at the START of the
// snapshot and its value actually CONTAINS the blob (req_len = 22 + blob_len),
// with blob_len = 0x100. So memcpy(s, req_tlv+22, 0x100) stays INSIDE the
// TEE_Malloc chunk -> NO redzone touched -> NO out-of-bound read; unwrapGakBlob
// proceeds into prvtee_swbc_decrypt (which fails on the bogus key) and returns
// an error cleanly. The ONLY difference vs poc.c is record placement + a blob
// whose source range is in-bounds => isolates the missing source bound as the
// sole cause of the malicious crash (SVLTKPR-5 / SKPM-3 methodology).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "tee_client_api.h"
#include "repro.h"

TEEC_Result (*TEEC_OpenSession_impl)(TEEC_Context*, TEEC_Session*, const TEEC_UUID*,
                                     uint32_t, const void*, TEEC_Operation*, uint32_t*);
TEEC_Result (*TEEC_InitializeContext_impl)(const char*, TEEC_Context*);
void (*TEEC_FinalizeContext_impl)(TEEC_Context*);
void (*TEEC_CloseSession_impl)(TEEC_Session*);
TEEC_Result (*TEEC_InvokeCommand_impl)(TEEC_Session*, uint32_t, TEEC_Operation*, uint32_t*);
TEEC_Result (*TEEC_RegisterSharedMemory_impl)(TEEC_Context*, TEEC_SharedMemory*);
void (*TEEC_ReleaseSharedMemory_impl)(TEEC_SharedMemory*);

#define CMD_UNWRAP_GAK_BLOB 0xA702u
#define REQ_SZ    0x8100
#define MEMREF_SZ 0x8000u
#define BLOB_LEN  0x100u           /* in-bounds: the value carries the whole blob */

static uint32_t build_benign(uint8_t *buf)
{
    uint32_t cmd = CMD_UNWRAP_GAK_BLOB;
    uint8_t *p = buf + 8;
    uint16_t rec_len   = (uint16_t)(22 + BLOB_LEN);   /* req_len includes the blob => in-bounds */

    p[0] = 0xFE;
    uint16_t total_len = (uint16_t)(3 + rec_len);     /* total_len+3 == payload_len */
    p[1] = total_len & 0xFF; p[2] = (total_len >> 8) & 0xFF;

    /* tag-15 record at cursor 3 (the first/only record) */
    p[3] = 0x0F;
    p[4] = rec_len & 0xFF; p[5] = (rec_len >> 8) & 0xFF;

    uint8_t *iv = p + 6;                  /* req_tlv */
    iv[0]  = 0x02;
    iv[1]  = 0x10; iv[2] = 0x00;          /* IV len 16 */
    memset(iv + 3, 0x00, 16);
    iv[19] = 0x06;
    iv[20] = BLOB_LEN & 0xFF; iv[21] = (BLOB_LEN >> 8) & 0xFF;
    memset(iv + 22, 0x42, BLOB_LEN);      /* blob value lives INSIDE the record (in-bounds) */

    uint32_t payload_len = 6 + rec_len;   /* == total_len+3 */
    memcpy(buf + 0, &cmd, 4);
    memcpy(buf + 4, &payload_len, 4);
    return 8 + payload_len;
}

int main(void)
{
    char *ta = "00000000-0000-0000-0000-505256544545";
    TEEC_UUID *uuid = teegris_uuid(ta);
    uint32_t err_origin = 0;
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;

    load_functions();
    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) { printf("InitContext failed 0x%x\n", res); exit(-1); }
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                                NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("OpenSession failed 0x%x origin 0x%x\n", res, err_origin);
        TEEC_FinalizeContext_impl(&context); exit(-1);
    }
    printf("[poc] session opened to prvtee (PUBLIC login)\n");

    uint8_t *req = malloc(REQ_SZ);
    memset(req, 0, REQ_SZ);
    uint32_t total = build_benign(req);
    printf("[poc] BENIGN: tag-15 rec @ cursor 3, req_len=%u, blob_len=0x%x (source in-bounds)\n",
           22 + BLOB_LEN, BLOB_LEN);

    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = req;
    op.params[0].tmpref.size   = MEMREF_SZ;

    printf("[poc] InvokeCommand cmd=0x%x paramTypes=0x%lx total wire=0x%x\n",
           CMD_UNWRAP_GAK_BLOB, (unsigned long)op.paramTypes, total);
    res = TEEC_InvokeCommand_impl(&session, CMD_UNWRAP_GAK_BLOB, &op, &err_origin);
    printf("[poc] cmd 0x%x returned res=0x%x origin=0x%x  (expected: clean error, NO crash)\n",
           CMD_UNWRAP_GAK_BLOB, res, err_origin);

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    printf("[+] done\n");
    return 0;
}
