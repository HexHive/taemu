# iccdrv_physrw — IcCDrV arbitrary physical READ + WRITE (unbounded `TEE_MemMove`)

Documentation-grade PoC for the two **HIGH** findings in
[`RE/samsung_teegris/iccdrv.md`](../../../../code/ta-analysis/RE/samsung_teegris/iccdrv.md)
(emulation verdict in the iccdrv section of
[`RE/emulation/absent_drivers.md`](../../../../code/ta-analysis/RE/emulation/absent_drivers.md)).

This is the **most severe TEEGRIS finding in the campaign**: a one-call path
to **arbitrary physical memory read *and* write** from inside the secure
world (iccdrv.md L91-104, L113; absent_drivers.md L89-104 "The crown jewel of
the absent set").

## TA

- **Name:** `iccdrv` / `IcCDrV` — the TEEGRIS ICCC ("Inter-Chip
  Communication") **physical-memory driver** TA. Driver name `iccc_driver`,
  registered via `TEES_InitDriver` (iccdrv.md L6, L103). It exposes raw
  `/dev/phys`-backed read/write of an arbitrary, caller-supplied physical
  address to exactly two trusted client TAs (iccdrv.md L9-23).
- **UUID:** `00000000-0000-0000-0000-494363447256` (ASCII tail `IcCDrV`) —
  iccdrv.md L3.
- **Binary:** `tas/samsung_teegris/SM-S921B_*/00000000-0000-0000-0000-494363447256.elf`
  (23 KB) — iccdrv.md L4.

## Finding (HIGH ×2, CONFIRMED-IN-BINARY)

`iccc_ioctl` (`@0x25E4`, the only meaningful file-op — iccdrv.md L30-33)
dispatches two commands. Each takes a **caller-supplied `{phys_addr, length}`
tuple plus a caller buffer** and `TEE_MemMove`s `length` bytes between the
caller buffer and a `/dev/phys` mapping of that physical address — with **no
upper-bound check on `length`**:

- **BUG-1 — arbitrary physical READ** (HIGH).
  `icc_phys_read @0x21C4`: the caller length `a1[1]` is passed **directly,
  unchecked**, as the `size` to `TEE_MemMove @0x2258` — no compare against a
  slot size, page size, or any constant (iccdrv.md L118-131). Decompile
  (iccdrv.md L81-88):
  ```c
  v4 = open("/dev/phys", 3);
  v6 = *a1   & 0xFFFFF000;                 // page-align phys_addr
  v7 = a1[1] + *a1 - v6;                   // page-align length
  v8 = mmap(NULL, v7, 3, 16, v4, v6);      // PROT_R|W, MAP_SHARED
  TEE_MemMove(a2, &v8[*a1 & 0xFFF], a1[1]);// size = a1[1], UNBOUNDED
  ```
  asm (iccdrv.md L124-127): `LDP W8,W2,[X19]` (W8=phys_addr, W2=length) then
  `BL .TEE_MemMove` with `size = W2 = a1[1]`, no bound check.
  → arbitrary-length physical-memory **disclosure** into the caller buffer
  (iccdrv.md L129-131).

- **BUG-2 — arbitrary physical WRITE** (HIGH).
  `icc_phys_write @0x234C`: mirror of BUG-1. `a1[1]` flows to `TEE_MemMove`
  size at `@0x23E0`, `dest = mmap_base + (phys_addr & 0xFFF)`, no check
  anywhere (iccdrv.md L135-148). asm (iccdrv.md L140-143): `LDP W8,W2,[X19]`
  then `BL .TEE_MemMove` (dest = mapping + low-12, size = W2).
  → arbitrary physical-memory **corruption** from a caller-supplied source
  buffer (iccdrv.md L146).

An allowlisted caller passing `length = 0xFFFFFFFF` makes the driver attempt
to move up to **~4 GB** through the physical window; the only ceiling is
whatever `mmap`/`/dev/phys` will back — which the driver **never enforces**
(iccdrv.md L129, L146; absent_drivers.md L15, L91-97). The driver implements
**NO per-type, per-ICCC-slot, or per-address ACL** — it is a raw `/dev/phys`
r/w primitive (iccdrv.md L194-196 "Access-control architecture verdict").

> A third static issue, **BUG-3** (MEDIUM, NEEDS-EXTERNAL-VERIFICATION), is a
> 32-bit integer wraparound in the `mmap` size computation (`ADD W8,W9,W8`
> wraps at `0x1_00000000`) that can make `mmap` smaller than `length`,
> turning the unbounded `TEE_MemMove` into an OOB write past the mapping
> (iccdrv.md L152-169). It is not the headline finding and its
> exploitability depends on `/dev/phys` kernel-side validation, so this PoC
> centers BUG-1/BUG-2.

## The allowlist gate — why this is TA-to-TA, not REE-direct

`iccc_ioctl` calls `iccc_caller_allowlist @0x284C` against the **calling
TA's UUID** before dispatching either command (iccdrv.md L51-64). The check
admits exactly two UUIDs (high qword `== 0`, low qword one of):

| Caller | UUID low qword | ASCII tail | role |
|--------|----------------|-----------|------|
| **STST** | `0xAB54535453000000` | `\x00STST\xab` | ICCC storage / DeviceInfo TA (iccdrv.md L15, L72-75) |
| **ICcGRD** | `0x4452474363490000` | `IcCGRD` | ICCC guard runner TA (iccdrv.md L16, L60-62, L76) |

Any other caller hits "Caller TA is not in the allowlist" and is rejected
(iccdrv.md L63, L209). The caller UUID is **supplied by TEEGRIS, not
caller-spoofable** — so this primitive is reachable **only** from STST or
ICcGRD: it is a **TA-to-TA driver-client** path, **never** a standalone-REE /
TEEC client one (absent_drivers.md L74, L80-85). The PoC `poc_tata.c` is
therefore framed as the **driver-client code one of those allowlisted TAs
would itself run** — not a TEEC REE client like the other corpus PoCs (no
`tee_client_api.h`, no emulator socket transport).

## ioctl numbers + request struct (all writeup-cited)

| ioctl | value | handler | citation |
|-------|-------|---------|----------|
| `TZ_SECURE_MEM_READ` | `0x70041` (458817) | `icc_phys_read @0x21C4` | iccdrv.md L40, L43-46 |
| `TZ_SECURE_MEM_WRITE` | `0x70042` (458818) | `icc_phys_write @0x234C` | iccdrv.md L41, L43-46 |

> **ioctl-value provenance:** the values were *previously misrecorded* as
> `0x70001`/`0x70002`; the "Correction 2026-06-07" (iccdrv.md L43-46) shows
> the dispatch decompile `icc_ioctl_dispatch@0x25E4` doing
> `MOV W8,#0x70042`/`#0x70041` with `a2==458818→write`, `a2==458817→read`,
> confirming `0x70041` (READ) / `0x70042` (WRITE). Grounded, not invented.

**Request struct** read through `a1` by both handlers — two consecutive `u32`s
(iccdrv.md L49, L81-88, L124-127):

```c
struct icc_phys_req {        /* carried inside the size-24 iov; a3[1] == 24 */
    uint32_t phys_addr;      /* a1[0] / *a1 : page-aligned via *a1 & 0xFFFFF000 */
    uint32_t length;         /* a1[1]       : -> TEE_MemMove size, UNBOUNDED   */
};
```

Direction / framing the handler requires before dispatch (iccdrv.md L48-49):
- inner iov size **`a3[1] == 24`** (the `{phys_addr,length}` tuple),
- caller buffer **`a3[2] != NULL`** (passed separately as `a2` to the handler
  = `TEE_MemMove` destination for READ, source for WRITE).

**The `TEE_MemMove` sink:** READ → `TEE_MemMove(caller_buf, mapping +
(phys_addr & 0xFFF), length)` at `0x2258`; WRITE → `TEE_MemMove(mapping +
(phys_addr & 0xFFF), src_buf, length)` at `0x23E0`. In both, `length` is the
unchecked attacker-controlled `a1[1]` (iccdrv.md L121, L138, L86, L146).

## Attack scenario (TEE-wide compromise)

`/dev/phys` is the TEEGRIS kernel device that maps an **arbitrary
caller-supplied physical address** (iccdrv.md L90-91). The defenses are
exactly three (iccdrv.md L91-99): (1) the 2-UUID **caller allowlist**, (2)
**TZASC** (TZ-protected DRAM is not mapped through `/dev/phys`), and (3) the
**REE memory model** for NWd-backed pages. Crucially the **driver itself has
no range check** — it trusts STST/ICcGRD to constrain target addresses
(iccdrv.md L113, L196).

So a **compromised STST (or ICcGRD)** — the threat model the writeup calls out
explicitly (iccdrv.md L113 "If STST were ever compromised, this driver is a
one-call path to arbitrary physical R/W") — issues:

1. `TZ_SECURE_MEM_READ(0x70041)` with an attacker `phys_addr` + large
   `length` → siphons any physical memory `/dev/phys` will back into a
   buffer it controls (secret disclosure across the whole physical map the
   driver can reach).
2. `TZ_SECURE_MEM_WRITE(0x70042)` with an attacker `phys_addr` + source
   buffer → plants arbitrary bytes at an arbitrary physical address. The
   writeup's concrete target is the **DualDAR Root-of-Trust DWORD at phys
   `0xBF200594`**: a TEE-side write of `0` there forges trusted-boot state
   that dulDAR (`verify_trusted_boot @0x810C`, requires `== 0`) and KEYMST
   (`get_trustboot_flag`, bakes into every key-attestation cert) consume
   (iccdrv.md L148; stst_iccc_save/README.md L20-31, L45-46).

Net effect: a single compromised allowlisted TA chains through iccdrv into
**full TZASC-protected physical read/write** — i.e. **TEE-wide compromise**
(read any secure secret, corrupt any integrity-critical config). This is the
campaign's highest-severity primitive (absent_drivers.md L89-92, L208-209).

## REPRO-STATUS — DEVICE-ONLY / NOT REPRODUCIBLE IN EMULATOR

**CONFIRMED-IN-BINARY** (both BUG-1 and BUG-2): the missing length clamp on
`TEE_MemMove` is a static code property of the captured S921B binary
(iccdrv.md L118-148; absent_drivers.md L98, L193-194). The finding's validity
rests entirely on the static decompile, **not on a run** (absent_drivers.md
L103-104).

**Dynamic = NOT REPRODUCIBLE in the emulator**, for three independent reasons
(absent_drivers.md L89-104, L193-194, L200-210):

1. **Binary ABSENT from corpus.** A scan of the bundled 34-TA TEEGRIS corpus
   for `494363447256` returns **ABSENT** (absent_drivers.md L33). There is
   nothing to load, drive, or crash.
2. **Driver-init death class.** Even if the `.ta` were dropped in, iccdrv is
   a TEEGRIS *driver* TA: it opens kernel resources (`/dev/phys`) in/around
   `TA_CreateEntryPoint`, exactly like the in-corpus drivers `smcdrv` /
   `spidrv` / `stst` that **boot-die during `TA_CreateEntryPoint`** on an
   un-modeled driver-init primitive (absent_drivers.md L45-63, L99-100).
3. **`/dev/phys` ioctl un-modeled + not REE-direct.** The surface is a
   TEEGRIS driver-client `ioctl` on `/dev/iccc_driver` backed by a
   `/dev/phys` mmap of physical memory — the GP-`InvokeCommand`-speaking
   emulator (`:1337`) models none of it, and there is no physical memory for
   it to over-read/over-write (absent_drivers.md L65-85, L98-104). It is
   reachable **only** from STST/ICcGRD (TA-to-TA), and the very STST
   front-end that would reach it **boot-dies on the un-modeled ICCC `ioctl`**
   in-corpus (absent_drivers.md L80-85, L171-173).

**No compile / no run here.** `poc_tata.c` deliberately does **not** build on
this analysis host: the real TEEGRIS driver-client headers/libs are absent,
so the secure-world entry points (`TEES_DriverOpen` / `TEES_DriverIoctl` /
`TEES_DriverClose`) are shown as prototypes + inert weak stubs. The file is
clean C provided for **reading** — it constructs the byte-exact ioctl requests
(numbers + `{phys_addr,length}` struct + caller buffer) that trigger BUG-1 and
BUG-2 on a real device, and nothing more.
