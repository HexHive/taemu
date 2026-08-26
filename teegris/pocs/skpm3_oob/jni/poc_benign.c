// SKPM-3 BENIGN CONTROL — identical cmd-10 path, but the TLV chain terminates
// early (in-bounds), so v13 never approaches the keyBlob end and the memcpy
// source stays inside the 10000B buffer.  Same req framing, same dispatch, same
// loop entered — the ONLY difference vs poc.c is the chain does not drive v13 to
// 9996.  Expectation: NO 0xdeadbeef crash (clean return), isolating the OOB read
// in poc.c as caused solely by the missing source bound.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tee_client_api.h"
#include "repro.h"
#include <dlfcn.h>

TEEC_Result (*TEEC_OpenSession_impl)(TEEC_Context*, TEEC_Session*, const TEEC_UUID*,
                                     uint32_t, const void*, TEEC_Operation*, uint32_t*);
TEEC_Result (*TEEC_InitializeContext_impl)(const char*, TEEC_Context*);
void (*TEEC_FinalizeContext_impl)(TEEC_Context*);
void (*TEEC_CloseSession_impl)(TEEC_Session*);
TEEC_Result (*TEEC_InvokeCommand_impl)(TEEC_Session*,uint32_t,TEEC_Operation*,uint32_t*);
TEEC_Result (*TEEC_RegisterSharedMemory_impl)(TEEC_Context*, TEEC_SharedMemory*);

#define REQ_SZ   0x500c
#define KBLOB_SZ 0x2710

static unsigned put_rec(unsigned char *kb, unsigned off, unsigned lenfield)
{
    unsigned v12 = lenfield + 4;
    kb[off+0] = 0x01; kb[off+1] = 0x11;
    kb[off+2] = (lenfield >> 8) & 0xff;
    kb[off+3] = (lenfield     ) & 0xff;
    memset(kb+off+4, 0x41, lenfield);
    return v12;
}

void send_req(TEEC_Context *context, TEEC_Session *session)
{
    unsigned char *req = malloc(REQ_SZ);
    memset(req, 0, REQ_SZ);
    *(unsigned int*)(req + 0x5008) = KBLOB_SZ;
    unsigned k = 1;
    req[8] = 0;
    *(unsigned int*)(req + 9)     = k;
    *(unsigned int*)(req + 8+k+5) = KBLOB_SZ;

    unsigned char *kb = req + 8 + k + 9;
    /* two small in-bounds records, then a tag=0 terminator -> loop breaks. */
    unsigned off = 0;
    off += put_rec(kb, off, 0x10);     /* v13: 0 -> 0x14 */
    off += put_rec(kb, off, 0x10);     /* v13: 0x14 -> 0x28 */
    kb[off] = 0x00;                    /* tag != 1 -> loop break at 0x1448c, no OOB */
    printf("[benign] 2 small records, terminator @ keyBlob offset %u; loop stays in-bounds\n", off);

    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    void *out = malloc(REQ_SZ); memset(out, 0, REQ_SZ);
    op.params[0].tmpref.buffer = req;  op.params[0].tmpref.size = REQ_SZ;
    op.params[1].tmpref.buffer = out;  op.params[1].tmpref.size = REQ_SZ;
    uint32_t err_origin = 0;
    printf("[benign] InvokeCommand cmd=10 paramTypes=0x%lx\n", (unsigned long)op.paramTypes);
    TEEC_Result res = TEEC_InvokeCommand_impl(session, 10, &op, &err_origin);
    printf("[benign] cmd 10 returned res=0x%x origin=0x%x  (clean = no OOB)\n", res, err_origin);
}

int main(int argc, char **argv)
{
    char* ta = "00000000-0000-0000-0000-0000534b504d";
    TEEC_UUID *uuid = teegris_uuid(ta);
    uint32_t err_origin; TEEC_Result res;
    TEEC_Context context; TEEC_Session session;
    load_functions();
    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) { printf("InitContext failed 0x%x\n", res); exit(-1); }
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                               NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) { printf("OpenSession failed 0x%x origin 0x%x\n", res, err_origin);
        TEEC_FinalizeContext_impl(&context); exit(-1); }
    send_req(&context, &session);
    printf("[+] done...\n");
    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
