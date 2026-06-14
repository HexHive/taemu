# smcdrv_fbleak — uninitialized TEE-stack disclosure via `DISP_IOCTL_SET_FB`

| | |
|---|---|
| **Target TA** | SMCdrv — the `tui_display` framebuffer-manager driver |
| **UUID** | `00000000-0000-0000-0000-000000020081` |
| **Severity** | **MEDIUM** — info leak (uninitialized TEE-stack disclosure; can include TEE pointers → defeats userspace ASLR) |
| **Surface** | TEE-internal TEEGRIS **driver ioctl** (`tui_disp_drv_ioctl @ 0x9664`), file_ops `.ioctl`. The GP `TA_InvokeCommandEntryPoint` is a **stub**. |
| **ioctl** | cmd **16** = `DISP_IOCTL_SET_FB` |
| **Reachability** | **TA-to-TA** — a calling TA that holds a `tui_display` driver fd (not a REE process) |
| **Repro status** | **DEVICE-ONLY / TA-to-TA** — un-modeled driver-client ioctl surface; write-direction leak has no asan signal |
| **Writeups** | [`RE/samsung_teegris/smcdrv.md`](../../../../code/ta-analysis/RE/samsung_teegris/smcdrv.md) finding #1 (lines 29-60); [`RE/emulation/smcdrv.md`](../../../../code/ta-analysis/RE/emulation/smcdrv.md) |

> This POC is a **documented TA-to-TA driver client**, not a runnable REE TEEC
> client. `poc_tata.c` is documentation-grade C: it transcribes the exact ioctl
> request a TUI TA would build. It is kept syntactically clean (compiles `-Wall
> -Wextra` in its documentation build, with the live driver-client calls `#if
> 0`'d out because the TEEGRIS SDK headers are absent on this host) but it does
> **not run against the GP-TEEC emulator**, which speaks `TA_InvokeCommand` and
> does not model the driver-client ioctl transport.

---

## The finding

SMCdrv registers itself as a TEEGRIS driver:

```
TEES_InitDriver("tui_display", &file_ops, 5, ...);     // smcdrv.md:85
```

and the bug lives in the file_ops `.ioctl` handler `tui_disp_drv_ioctl` (cmd 16,
`DISP_IOCTL_SET_FB`). The 176-byte `fbset_cmd` struct `dest` lives at `SP+0x08`
and is **never memset**. The input and output `iov_len` are validated by **two
independent guards**, each only `< 0xB1` (≤ 176), with **no cross-check** that
`output.iov_len ≤ input.iov_len`:

```
input  guard @ 0x96d0 :  CMP X4,#0xB1 / B.CC        accept input.iov_len  ≤ 176   (smcdrv.md:36-37)
    memcpy(&dest, input.buf, input.iov_len)         @ 0x97c8
output guard @ 0x9918 :  CMP X4,#0xB1 / B.CC        accept output.iov_len ≤ 176   (smcdrv.md:38-40)
    memcpy(output.buf, &dest, output.iov_len)       @ 0x9990
```

(Confirmed in the decompiled handler: input len read from `params+8`, checked
`< 0xB1u`; output len read from `params+264`, checked `>= 0xB1u` → error, else
`memcpy(out_buf, &dest, output.iov_len)`. The two error strings —
`'input.iov_len' is greater than 'sizeof(fbset_cmd)'` and the `'output.iov_len'`
twin — are present byte-for-byte in the corpus build, RE/emulation/smcdrv.md:47-48.)

### Leak mechanism

Because the two lengths are never compared, a caller sets:

* `input.iov_len  = 44`  — just enough to populate the validated fields, with
  `wb = 0` so the else-branch zeroes only `dest+0x30` and validation passes
  (`fb ≠ 0`, `fb_size_aligned` matches `(4·w·h+0xFFF)&~0xFFF`).
* `output.iov_len = 176` — the maximum the output guard accepts.

The copy-back then returns bytes **`[44..175]` of `dest`** — **132 bytes of
uninitialized TEE stack** below the canary (residue of prior
`sub_AF0C`/`memcpy`/`printf` frames, which can include TEE pointers → defeats
userspace ASLR). The copy-back runs **unconditionally** after
`tuiHalDisplayProtectFramebuffer` (`sub_AA40`), so the leak does **not** even
require a valid framebuffer. (smcdrv.md:42-51)

**Fix:** `memset(&dest, 0, 176)` before the input copy, or require
`output.iov_len == input.iov_len` (clamp the copy-back to bytes actually
produced).

> The first-pass "input-side memcpy stack overflow" candidate is **REFUTED** —
> the input length guard is a correct full-64-bit unsigned `≤ 176` compare; no
> off-by-one, no signedness escape. (smcdrv.md:57-60)

---

## `fbset_cmd` struct layout (decompiler-exact; base = `&dest`)

The cmd-16 validator reads exactly these fields; everything else is padding the
copy-back leaks. Offsets verified by `_Static_assert` in `poc_tata.c`.

| Offset | Field | Validation / role |
|--------|-------|-------------------|
| `0x00` | `_pad00[8]` | header/reserved (part of `dest` q-word) |
| `0x08` | `height` (u32) | `CMP > 0x1000` → reject (`ctx`) |
| `0x0C` | `width` (u32) | `CMP > 0x1000` → reject |
| `0x10` | `fb` (u32) | `src`; must be `!= 0` (null-FB check) |
| `0x18` | `fb_size_aligned` (u32) | must `== (4·w·h + 0xFFF) & ~0xFFF` |
| `0x28` | `wb` (u32) | `!= 0` → WB checks; `== 0` → else-branch zeroes `0x30` |
| `0x30` | `wb_size` (u32) | `v28`; zeroed by the else-branch |
| `0x2C..0xAF` | (tail) | **never written → the 132-byte leaked window** |
| total | **176 bytes** (`0xB0` = `sizeof(fbset_cmd)`) | |

The canary (`qword_1B000`) sits **above** the struct (`xbp-8`), not inside
`dest`. `input.iov_len = 44 (0x2C)` covers `[0x00..0x2B]` — through the 4-byte
`wb` field at `0x28` — which is exactly the validated set, so 44 is the minimal
populate length. (smcdrv.md:42-44)

### ioctl argument block (`params`, a3)

```
input  iov:  buf @ params+0x000,  len @ params+0x008   ("params+8")
output iov:  buf @ params+0x100,  len @ params+0x108   ("params+264")
```

Two GP-style `{ptr,len}` iovecs 256 bytes apart (decompiler-exact).

---

## TA-to-TA reachability — which TAs hold a `tui_display` fd

The driver is registered under `TEES_InitDriver("tui_display", ...)` with **no
UUID allowlist** and **no per-TA ACL** — the only gate is the open-state check
`atomic_load(&dword_1C01C) == 1` (set by the driver's own `.open`). Any TEEGRIS
TA with driver-client access reaches the ioctl. (smcdrv.md:106-107, 189-190)

The TUI-subsystem TAs in the S921B corpus that open `tui_display` via the
TEEGRIS driver-client API (`drv_open_client` + `ioctl`) are:

| UUID (suffix) | Decoded | Role |
|---|---|---|
| `…0000020081` | (SMCdrv) | the **registrant** of `tui_display` (itself) |
| `…0053545354ab` | `STST` | **MPSTUI** — the TUI session TA |
| `…4b45594d5354` | `KEYMST` | keymaster — uses TUI for protected confirmation |
| `…54496473706c` | `TIdspl` | `tuill_dispdrv` — the lower-level DECON companion |

(The MPSTUI/STST TA demonstrably uses the `drv_open_client` + `ioctl`
driver-client pattern — observed in its `/dev/iccc_driver` strings — i.e. the
exact API this POC documents for opening `tui_display`.)

---

## REPRO-STATUS — DEVICE-ONLY / TA-to-TA

**CONFIRMED-IN-BINARY (static) + dynamically BLOCKED.** Three independent walls,
any one of which alone blocks reproduction in the emulator (RE/emulation/smcdrv.md):

1. **Boot-dies.** SMCdrv's `TA_CreateEntryPoint` registers the driver and calls
   the **un-modeled** `TEES_RegisterDriverDestructor` → `default_func` → HALT.
   The TA never reaches a command. (emulation lines 59-94)
2. **Un-modeled surface.** The bug is on the file_ops `.ioctl` path — a TEEGRIS
   driver-client ioctl channel. The emulator speaks GP `TA_InvokeCommand`, not
   the driver-client transport. (emulation lines 96-99)
3. **No asan signal.** The leak is a **write-direction / read-too-much**
   disclosure with no corruption — nothing is over-written, so even on a
   reachable happy path asan (heap redzones only; no uninitialized-stack
   tripwire) raises no event. Same blind spot as HDCP cmd 0x94 / the SEMeSE
   off-by-8. (emulation lines 100-114)

The confirmation is therefore intrinsically **static**: the missing
`memset(&dest, 0, …)` plus the two **independent** `iov_len ≤ 176` guards with
no cross-check, present byte-for-byte in the corpus build (the two guard error
strings are the fingerprint). The finding is valid against the S921B binary;
real reproduction is **device-only**, driven by a TUI TA that holds a
`tui_display` fd.

---

## Files

* **`poc_tata.c`** — byte-precise transcription of the `DISP_IOCTL_SET_FB`
  request a calling TUI TA (MPSTUI/STST or KEYMST) would issue: build the
  `fbset_cmd` with the validated fields set + `wb = 0`, set `input.iov_len = 44`
  / `output.iov_len = 176`, `drv_open_client("tui_display")` →
  `ioctl(fd, 16, &args)` → `DumpHex(resp, 176)` to reveal `resp[44..175]`. The
  live driver-client calls are `#if 0`'d (SDK headers absent on host); the
  documentation build compiles `-Wall -Wextra` and prints the attack summary.
  Every constant cites a writeup line and is corroborated against the decompiled
  handler.
