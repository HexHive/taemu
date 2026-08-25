/* Differential-testing POC: runs ONE vector-driven InvokeCommand and prints a
 * JSON "record" (return code/origin + out-direction params) to stdout. Build it
 * the project's two ways from this one source:
 *
 *   emulator: gcc -DEMULATE difftest_poc.c ...   (project shim wires TEEC_* to :1337)
 *   phone:    ndk-build                          (real libTEEC on the device)
 *
 * The vector is baked in via vector.h (generate with `vector.py genheader`).
 * Then `vector.py compare emu.json dev.json` reports any divergence.
 *
 * NOTE: context/session setup (login method, any vendor-specific connect data)
 * mirrors the existing per-TEE POCs -- copy the InitializeContext/OpenSession
 * boilerplate from e.g. beanpod/pocs/0811_exp/jni/poc.c for your target. The
 * vector-driven part below (operation build + record emit) is what's reusable.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "tee_client_api.h"
#include "vector.h"

static void emit_hex(const unsigned char *p, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) printf("%02x", p[i]);
}

/* Build a TEEC_UUID from the 16 big-endian bytes baked in by genheader. */
static TEEC_UUID dt_uuid(void) {
    const unsigned char *b = DT_UUID_BYTES;
    TEEC_UUID u;
    u.timeLow = ((uint32_t)b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
    u.timeMid = (uint16_t)((b[4] << 8) | b[5]);
    u.timeHiAndVersion = (uint16_t)((b[6] << 8) | b[7]);
    memcpy(u.clockSeqAndNode, b + 8, 8);
    return u;
}

/* Scratch buffers for memref params (sized to the vector's declared sizes). */
#ifdef DT_P0_SIZE
static unsigned char p0buf[DT_P0_SIZE];
#endif
#ifdef DT_P1_SIZE
static unsigned char p1buf[DT_P1_SIZE];
#endif
#ifdef DT_P2_SIZE
static unsigned char p2buf[DT_P2_SIZE];
#endif
#ifdef DT_P3_SIZE
static unsigned char p3buf[DT_P3_SIZE];
#endif

int main(void) {
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t origin = 0;
    TEEC_UUID uuid = dt_uuid();

    if (TEEC_InitializeContext(NULL, &ctx) != TEEC_SUCCESS) {
        fprintf(stderr, "InitializeContext failed\n");
        return 1;
    }
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC,
                           NULL, NULL, &origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "OpenSession failed 0x%x origin 0x%x\n", res, origin);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = DT_PARAM_TYPES;

    /* --- load each declared param into the operation --- */
#ifdef DT_P0_DATA
    memcpy(p0buf, DT_P0_DATA, sizeof(DT_P0_DATA));
    op.params[0].tmpref.buffer = p0buf; op.params[0].tmpref.size = DT_P0_SIZE;
#elif defined(DT_P0_A)
    op.params[0].value.a = DT_P0_A; op.params[0].value.b = DT_P0_B;
#endif
#ifdef DT_P1_DATA
    memcpy(p1buf, DT_P1_DATA, sizeof(DT_P1_DATA));
    op.params[1].tmpref.buffer = p1buf; op.params[1].tmpref.size = DT_P1_SIZE;
#elif defined(DT_P1_A)
    op.params[1].value.a = DT_P1_A; op.params[1].value.b = DT_P1_B;
#endif
#ifdef DT_P2_DATA
    memcpy(p2buf, DT_P2_DATA, sizeof(DT_P2_DATA));
    op.params[2].tmpref.buffer = p2buf; op.params[2].tmpref.size = DT_P2_SIZE;
#elif defined(DT_P2_A)
    op.params[2].value.a = DT_P2_A; op.params[2].value.b = DT_P2_B;
#endif
#ifdef DT_P3_DATA
    memcpy(p3buf, DT_P3_DATA, sizeof(DT_P3_DATA));
    op.params[3].tmpref.buffer = p3buf; op.params[3].tmpref.size = DT_P3_SIZE;
#elif defined(DT_P3_A)
    op.params[3].value.a = DT_P3_A; op.params[3].value.b = DT_P3_B;
#endif

    res = TEEC_InvokeCommand(&sess, DT_COMMAND_ID, &op, &origin);

    /* --- emit the record (out-direction params) as JSON --- */
    printf("{\n");
    printf("  \"return_code\": \"0x%x\",\n", res);
    printf("  \"return_origin\": \"0x%x\",\n", origin);
    printf("  \"params_out\": [\n");
    for (int i = 0; i < 4; i++) {
        const char *comma = (i < 3) ? "," : "";
        switch (i) {
#define EMIT_MEMREF(IDX, BUF) \
            printf("    {\"type\":\"memref\",\"size\":%u,\"data_hex\":\"", \
                   (unsigned)op.params[IDX].tmpref.size); \
            emit_hex((unsigned char *)op.params[IDX].tmpref.buffer, \
                     op.params[IDX].tmpref.size); \
            printf("\"}%s\n", comma);
#define EMIT_VALUE(IDX) \
            printf("    {\"type\":\"value\",\"a\":%u,\"b\":%u}%s\n", \
                   op.params[IDX].value.a, op.params[IDX].value.b, comma);
#define EMIT_NONE() printf("    {\"type\":\"none\"}%s\n", comma);
        case 0:
#if defined(DT_P0_DATA)
            EMIT_MEMREF(0, p0buf);
#elif defined(DT_P0_A)
            EMIT_VALUE(0);
#else
            EMIT_NONE();
#endif
            break;
        case 1:
#if defined(DT_P1_DATA)
            EMIT_MEMREF(1, p1buf);
#elif defined(DT_P1_A)
            EMIT_VALUE(1);
#else
            EMIT_NONE();
#endif
            break;
        case 2:
#if defined(DT_P2_DATA)
            EMIT_MEMREF(2, p2buf);
#elif defined(DT_P2_A)
            EMIT_VALUE(2);
#else
            EMIT_NONE();
#endif
            break;
        case 3:
#if defined(DT_P3_DATA)
            EMIT_MEMREF(3, p3buf);
#elif defined(DT_P3_A)
            EMIT_VALUE(3);
#else
            EMIT_NONE();
#endif
            break;
        }
    }
    printf("  ]\n}\n");

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return 0;
}
