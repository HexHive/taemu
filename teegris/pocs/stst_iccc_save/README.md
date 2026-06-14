# stst_iccc_save — REE `ICCC_save_data` (cmd 2) writes the DualDAR Root-of-Trust cell

PoC for the cross-TA **HIGH** finding in
[`RE/samsung_teegris/stst.md`](../../../../code/ta-analysis/RE/samsung_teegris/stst.md)
(emulation verdict in
[`RE/emulation/stst.md`](../../../../code/ta-analysis/RE/emulation/stst.md)).

## TA

- **Name:** `stst` (`STST` / Samsung Knox **ICCC DeviceInfo** TA — the TEEGRIS-side
  ICCC authority that owns `/dev/iccc_driver`).
- **UUID:** `00000000-0000-0000-0000-0053545354ab` (ASCII tail `\x00STST\xab`) — stst.md L3.

## Finding (HIGH, cross-TA)

STST's **REE-facing** `ICCC_save_data` (cmd 2, `@0xA8A8`) gates the write *type*
through a **loose** ACL — `(type & 0xFFF00000) != 0xFF000000` plus a single
`0xFF000002` exception (stst.md L94, L245, L306, L536-548; emu L11-15). Type
**`0xFF200001`** has prefix `0xFF200000` → **passes**. The inner
`Iccc_Core_SaveData_TA` (`@0xA5E0`) then `Iccc_phys_write`s block 2 at phys
**`0xBF200594`** — the *same* DWORD that:

- **dulDAR** `verify_trusted_boot` (`@0x810C`) reads and requires `== 0` to release
  the at-rest DualDAR keys (stst.md L311, L598; emu L18-21); and
- **KEYMST** reads as `get_trustboot_flag` (signed id `-14680063 == 0xFF200001`) and
  bakes into the `KNOX_TEE_PROPERTIES integrity_status` of every hardware
  key-attestation cert (stst.md L599).

A REE write of `0` there satisfies DualDAR's trusted-boot gate and forges KEYMST's
attested integrity bit, collapsing the SVB root of trust to a software-locked,
REE-writable config slot. Critically, the cmd is reachable **without** the caller
binding: the REE path (cmd 2..7 via `iccc_ree_dispatcher @0x5924`) needs no per-TA
UUID match — that binding only guards the TA-from-TA path (cmd 8..10), and **no TA
can write `0xFF200001` through it** (stst.md L294). REE cmd 2 is the **only**
in-binary write vector for this cell (stst.md L295, L604).

## Wire format (all constants writeup-cited)

| field | value | citation |
|-------|-------|----------|
| `commandID` | `2` (`ICCC_save_data`) | stst.md L94, L344; emu L80 |
| `paramTypes` | `103` == `0x67` = `TEEC_PARAM_TYPES(MEMREF_TEMP_INOUT, MEMREF_TEMP_OUTPUT, NONE, NONE)` | stst.md L51 (log `TEE_PARAM_TYPES: 103`), L54 (gate) |
| buffers | `params[0]`=request(in/out), `params[1]`=response(out), each **≥ 8220 B** (gate `size>>2 >= 0x807`) | stst.md L54, L66, L89-90; emu L11 |
| request body | `{cmd_id(4)@+0 + status(4)@+4 + body(8192)@+8}` | stst.md L88-90 |
| body `type` | `0xFF200001` (the RoT cell selector → block-2 `0xBF200594`) | stst.md L94, L306, L311; emu L11-15 |
| body `value` | `0` (satisfies dulDAR's `DWORD == 0` gate) | stst.md L311, L322; emu L18-21 |

The `cmd_id + status` framing is the canonical QSEE/TEEGRIS ICCC TLC header; the
`type`/`value` pair is the `ICCC_save_data, type = %x, value = %d` banner
(stst.md L94). `type` is placed as the leading body field and `value` immediately
after — the two load-bearing in-body constants (`0xFF200001`, `0`) are
writeup-grounded; their leading TLC placement is conventional (the writeup nails the
`{cmd_id+status+body}` outer framing but does not further fix the in-body
sub-offset).

## Trigger

1. `TEEC_InitializeContext`.
2. `TEEC_OpenSession` with `TEEC_LOGIN_PUBLIC` (no credentials —
   `TA_OpenSessionEntryPoint @0x5830` enforces no allowlist, stst.md L79).
3. Build the request buffer above and `TEEC_InvokeCommand(session, 2, &op, …)`.

## Build / run

```sh
make emulator      # gcc -DEMULATE -> ./poc  (x86-64 ELF for the emulator host)
./poc              # connects to the TEEGRIS emulator on 127.0.0.1:1337
```

> The `emulator`/`docker` recipes carry `-Wno-incompatible-pointer-types`. That flag
> only restores the **pre-gcc-16 default** (it was a warning when the corpus POCs were
> authored); it is required solely because the *verbatim, shared* `jni/repro.h` assigns
> a `TEEC_TempMemoryReference*` into the `TEEC_SharedMemory* shm_p[]` slot in
> `allocate_param_mem()`, which gcc 16 promotes to a hard error. It changes no build
> semantics; the rest of the Makefile is verbatim from `gatekeeper_throttle`.

## Repro status — DEVICE-ONLY

Per [`RE/emulation/stst.md`](../../../../code/ta-analysis/RE/emulation/stst.md):

- **CONFIRMED-IN-BINARY**: the loose REE ACL admitting `0xFF200001`, and the block-2
  phys-write to the same `0xBF200594` cell dulDAR reads, are static code properties
  present in the emulator's own S9BYH2 build (emu L46-51, L123-126). The cmd is
  **reachable** and the ACL **admits** the RoT type.
- **dynamic BLOCKED (DEVICE-ONLY)**: the actual cell WRITE goes through
  `Iccc_phys_write` → a TEEGRIS driver-client `ioctl` to the kernel `/dev/iccc_driver`
  (`0x70042`) over **physical** TZASC memory at `0xBF200000` — none of which a
  user-space TA emulator models (emu L73-103). STST even **boot-dies** on that
  un-modeled ICCC `ioctl` during init (emu L53-71). The emulator can demonstrate the
  cmd is reachable and the ACL admits the type; it **cannot** show the physical write
  effect.
- **EXTERNAL caveat (hardware/bootloader)**: whether TZASC permits the REE write, and
  whether the bootloader pre-locks `0xFF200001` before REE can call STST, decide the
  real-world impact and live outside the TA corpus (stst.md L325-331, L640-651; emu
  L97-119). The lock is **write-once** (`iccc_set_lock_bit` only ORs in, never clears —
  stst.md L630-639), so the exposure is an early-boot race: first unlocked REE cmd-2
  write wins and locks the cell to the forged value.

This is the TEEGRIS-side mirror of the QSEE `tz_iccc` SVB-clear surface — both bottom
out on the same ICCC/SVB config cell in TZASC-reserved storage (emu L104-119).
