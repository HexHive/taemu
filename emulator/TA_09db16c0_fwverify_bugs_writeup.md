# Vulnerability writeup — DJI OP-TEE TA `09db16c0-873b-4fed-b87e-a5d2b86293a2`

**Target:** Trusted Application `09db16c0-873b-4fed-b87ea5d2b86293a2.elf` (DJI Mavic 3 firmware, MediaTek/OP-TEE).
Statically-linked OP-TEE TA (libutee baked in). AArch64. Image base `0x100000`.
**Role:** DJI secure-boot / firmware-and-model authentication service ("TA_KeyDerivation"). It owns the device's derived keys + key repository and gates every firmware/model image behind hardware-rooted signature verification + AES decryption before the normal world is allowed to run it.
**Attacker model:** a normal-world Client Application (CA) that can open a session and invoke commands. For the signature-gated paths the attacker additionally possesses a legitimately-signed image (their own device firmware) but **no signing keys**.
**Class:** normal-world-triggerable memory corruption in the secure world via double-fetch / missing bounds checks.

**Root cause (shared):** the TA parses and verifies firmware images **in place in normal-world (CA) shared memory** instead of snapshotting them into secure memory first. Length/count fields are read from that shared memory **multiple times** — once for validation/signing and again for the operation — so a second CA core can change them in between (double-fetch / TOCTOU), and some are never bounded against the fixed secure destination at all.

Key secure-world objects involved:

| symbol | addr | size | contents |
|--------|------|------|----------|
| `DAT_001211f8` (verify ctx) | `0x1211f8` | `0x4f8` | streaming verify/decrypt context; header copied to `+0x24`; **plaintext AES scramble key at `+0x476`** |
| `bpoolset` (bget) | `0x1211a8` | — | heap free-list head + `totalloc` (`0x1211c8`) |
| `ta_heap` | `0x122660` | — | TA heap (operation objects, transient key copy) |

---

## Command dispatch & parameter model (context)

`TA_InvokeCommandEntryPoint` (`0x100204`) is a `switch(cmd)`. `__utee_entry` (`0x10a0e4`) unmarshals the 4 GP params into the global `ta_params` (4×16 B) before dispatch, so the *param descriptors* (types/sizes) cannot be raced. `params[]` as a `u64*`: `[0]/[1]`=param0 buf/size, `[2]/[3]`=param1, `[4]/[5]`=param2, `[6]/[7]`=param3.

| cmd | handler | exp. paramTypes | notes |
|----|----|----|----|
|0|`fw_image_verify` (`FUN_001004c0`)|`0x1157`|stateless; sig-gated|
|1|`fw_image_load` (`FUN_001006c0`)|`0x1155`|stateless; sig-gated|
|2|`fw_image_verify_load2ion` (`FUN_00100798`)|`0x1157`|stateless; sig-gated|
|3|`dji_fw_verify_init` (`FUN_00100c30`)|`0x5`|inits `DAT_001211f8`|
|4|`dji_fw_verify_update` (`FUN_00103d40`)|`0x17`|**BUG 1**|
|5|`dji_fw_verify_final` (`FUN_00101148`)|`0x0`|zeroizes ctx|
|6|`dji_fw_verify_init_ext` (`FUN_00100d78`)|`0x1555`|**BUG 2**|

**What is done correctly:** every handler strictly checks `paramTypes == <const>`, so GP type-confusion (VALUE-where-MEMREF) is **not** available. Chunk counts are bounded (`> 0x10` rejected) before the chunk-table copies in `FUN_001004c0/00100798/00103708`, all of which fit a 512-byte buffer. The firmware payload paths are gated behind RSA/ECC signature verification (`image_verify_header`, `FUN_00103194`) with a keyrepo/ROM auth key. OP-TEE core guarantees memref buffers point only at CA memory, so these bugs corrupt/read **secure-world internal memory**, not via the memref pointer itself.

The image format: magic `"IM*H"` (`0x482a4d49`); header fields used below — `header_size` @ `+0x10`, `signature_size` @ `+0x14`, `payload_size` @ `+0x18`, `auth_alg` @ `+0x24/0x26`, `auth_key_id` @ `+0x28`, `enc_key_id` @ `+0x2c`, wrapped scramble key @ `+0x30` (16 B), `chunk_count` @ `+0x9c`, chunk table @ `+0xc0`.

---

## BUG 1 ★ — `dji_image_verify_update` (cmd `4`, `FUN_00103d40`)
### Double-fetch of `header_size` → secure-world `.bss` buffer overflow of the verify context

**Reachability:** open session → cmd 3 (`dji_fw_verify_init`) or cmd 6 to set state `DAT_001216e8 == 1` → cmd 4 with `paramTypes == 0x17` (param0 = MEMREF_INOUT image, param1 = VALUE_INPUT). The image buffer (`param0.buffer`) stays in CA shared memory the entire time.

**First-update path (header parse):**
```c
// param_2 = image (CA shared mem);  param_3 = param0.size (trusted marshalled copy)
// param_1 = &DAT_001211f8 (fixed 0x4f8-byte global ctx)

if (param_3 < 0xc0) return -2;
if (param_3 < (uint)(*(int*)(param_2+0x14) + *(int*)(param_2+0x10)))  // ldr @0x103e3c  (header_size read #1)
    return -2;                                                        //  ⇒ header_size <= param_3 - sig_size
...
image_verify_common(...);                       // structural checks (magic/sizes/alg), NOT signature
iVar6 = FUN_00103194(param_2, ctx_flags);        // SIGNATURE verify; hashes header_size bytes, RSA/ECC at image+header_size
if (iVar6 != 0) return -0xe;
...
iVar2 = *(int*)(param_2 + 0x10);                 // ldr w25,[x22,#0x10] @0x103f74  (header_size read #2)
iVar6 = *(int*)(param_2 + 0x14);
FUN_0010c170(param_1 + 0x24, param_2, iVar2);    // memcpy(ctx+0x24, image, header_size)   <-- SINK
```

**Two independent defects in the sink:**

1. **No upper bound vs the destination.** The destination `ctx+0x24` lies in the `0x4f8`-byte global; only `0x4f8 - 0x24 = 0x4d4` (1236) bytes are available. `header_size` is a 32-bit field constrained only by a *lower* bound (`>= 0xc0`) and "fits in the image" (`header_size + sig_size <= param0.size`). There is **no check `header_size <= 0x4d4`**.

2. **Double-fetch (confirmed at instruction level).** `header_size` is loaded from CA shared memory at `0x103e3c` (the size-validation), used inside `FUN_00103194` to bound the hashed/signed region, and **re-loaded at `0x103f74`** for the `memcpy` length — with non-inlined calls (`image_verify_common`, `image_verify_header`) in between. A second CA core can present a small, correctly-signed `header_size` (signature passes), then enlarge it to an arbitrary value before `0x103f74` reads it.

**Impact:** linear overflow of the secure `.bss` global `DAT_001211f8` (and beyond) with attacker-controlled image bytes → secure-world memory corruption / TA compromise from the normal world. Because this TA *is* the firmware root-of-trust, this is a step toward defeating the secure-boot chain it enforces. Severity **High**.

**Exploitability:** requires (a) any validly-signed image — the attacker has their own device firmware — and (b) winning the double-fetch race (practical on these multi-core SoCs). Even single-fetch, any signed image whose header field exceeds 1236 bytes overflows. Layout is static (no ASLR in the TA).

**What the overflow reaches (static `.bss` map):**
```
0x1211f8  DAT_001211f8  verify ctx (0x4f8)        memcpy dest = +0x24 ; scramble key = +0x476 (0x12166e)
0x1216f0  ... other .bss globals ...
0x122660  ta_heap        TA heap base             reached at header_size ≳ 0x1444 (image ≳ 5 KB)
```

**Note on key disclosure.** The overflow is a *write* primitive; the TA has **no secure→CA copy path whose source is the verify context** (all output bytes are sourced from the attacker's own image buffer), so it cannot copy the key out directly. Two caveats shape escalation:
- Several ctx fields after the sink (`+0x476` key, `+0x490/0x498` digest op, `+0x4c0/0x4c8` cipher op, `+0x4d0` key_data ptr, `+0x4f0` state) are **re-initialized later in the same first-update call**, so clobbering them is undone. The durable corruption is in non-reinitialized accumulators and, above all, **adjacent `.bss` past `+0x4f8` and the `ta_heap`**.
- The TA heap holds a **copy of the scramble key** (a `TEE_TYPE_AES` transient object created by `keymgr_build_aes_handle`). The bget allocator has free-list/boundary-tag integrity **asserts that panic on corruption**, so a key-leak chain favors overwriting **object data / handles** (data-only) or forging consistent tags, rather than naive free-list unlink, to obtain an arbitrary read of `0x12166e` (or the heap key copy).

**Fix:** snapshot the image header into secure memory once, then validate/parse the copy; reject `header_size > sizeof(ctx) - 0x24`; load `header_size` into a single local and reuse it for the hash span, the signature offset, and the copy length.

---

## BUG 2 — `dji_fw_verify_init_ext` (cmd `6`, `FUN_00100d78`)
### Unvalidated CA memref pointers dereferenced as C-strings

**Reachability:** cmd 6 with `paramTypes == 0x1555` (param0/1/2 = MEMREF_INPUT, param3 = VALUE_INPUT), state `DAT_001216e8 == 0`.

```c
pcVar6 = (char*)params[2];        // param1.memref.buffer (CA shared mem)
pcVar7 = (char*)params[4];        // param2.memref.buffer (CA shared mem)
uVar1  = *(u32*)(params + 6);     // param3.value.a
...
if (*pcVar6 != '\0')              // deref attacker pointer, no size check
    inject_key_from_keyrepo(pcVar6, uVar1, 0x4b414455, 2, 0x20);   // pcVar6 used as %s key name
if (*pcVar7 != '\0')
    inject_key_from_keyrepo(pcVar7, uVar2, 0x45494455, 1, 8);
```

The corresponding memref **sizes (`param1.size`, `param2.size`) are never validated** before the buffers are read as NUL-terminated strings (and passed to `keyrepo` lookup as `%s` names). A zero-length or unterminated buffer leads to out-of-bounds reads of adjacent CA shared memory (string runs past the declared memref). Impact is confined to normal-world memory (no secure corruption / no key material crosses the boundary), hence **Low/Medium**.

**Fix:** require `size > 0`, bound the name length to the keyrepo maximum, and copy + NUL-terminate into a secure stack buffer before use.

---

## BUG 3 (systemic) — in-place processing of CA shared memory (TOCTOU by design)

The entire verify/load pipeline (`FUN_001004c0`, `FUN_00100798`, `FUN_00103708`, `FUN_00103d40`) reads header fields, chunk counts/offsets/sizes, and computes hashes/signatures **directly out of CA shared memory** rather than snapshotting into secure memory first. BUG 1 is the cleanly-exploitable instance, but the pattern is the root cause: any field re-read after `image_verify_header` (e.g. `signature_size` @ `+0x14`, chunk descriptors used post-verification) is a candidate double-fetch.

(For contrast, the chunk-count read in `FUN_00103708` is **not** vulnerable: disassembly shows `ldr w5,[x19,#0x9c]` executes **once** at `0x103958` and the value is reused, so that bounds check cannot be raced.)

**Fix (general):** "fetch once into secure memory, then validate, then use." Copy the header (and any field that gates a size/offset) into TA-private memory before parsing; never re-dereference the shared buffer for a value that was already validated.

---

## BUG 4 ★ — `fw_image_verify_load2ion` (cmd `2`, `FUN_00100798`)
### Double-fetch of `chunk_count` (`+0x9c`) → unbounded `strlen`/`memcpy` of the image *name* into a 32-byte stack buffer

**Reachability:** open session → cmd 2 with `paramTypes == 0x1157` (param0 = MEMREF_INOUT image, param1 = MEMREF_INPUT, param2/3 = VALUE_INPUT). The sink runs **before** `image_verifiy_decrypt` — i.e. **before any signature check** — so it is **unauthenticated** (only a one-time `TA_KeyDerivation` precedes it, which always succeeds on HW).

```c
// param_1 = image (CA shared mem); local_28 = 32-byte stack buffer; local_8 = canary
uVar1 = *(uint *)(param_1 + 0x9c);                 // chunk_count   FETCH #1 of +0x9c  (ldr @0x10089?)
if ((param_5 == 0) || (uVar1 < 2)) {
    if (0x10 < uVar1) return -5;                   // the ONLY cap that reads +0x9c
    memcpy(local_228, param_1 + 0xc0, uVar1 << 5); // chunk table (fits 512B, single-fetch)
    len = strlen(param_1 + 0x40);                  // 0x1008c4: walk name (crosses +0x9c)  FETCH #2
    memcpy(local_28, param_1 + 0x40, len);         // 0x1008dc SINK: 32-byte dst, len UNBOUNDED
    ...
    image_verifiy_decrypt(...);                    // signature/structural verify is AFTER the overflow
}
```

**Two independent defects:**

1. **No upper bound on the copy length.** `len = strlen(name)` is copied straight into the `0x20`-byte `local_28`; there is no `min(len, sizeof)`. Any name longer than 32 bytes smashes the stack canary, saved registers and the caller frame. The name is **read twice** from shared memory (`strlen` to measure at `0x1008c4`, `memcpy` to copy at `0x1008dc`).

2. **Double-fetch of `+0x9c` defeats the only cap.** Because the name starts at `+0x40`, the *only* thing capping the name at `0x5c` (92) bytes is that a longer name forces `image[0x9c] != 0` → `chunk_count > 0x10` → "too many chunks" rejection. `+0x9c` is read once as `chunk_count` (FETCH #1, the `<= 16` cap) and again while `strlen` walks the name across offset `0x9c` (FETCH #2). A second CA core that presents `image[0x9c] == 0` during FETCH #1 (cap passes) and `!= 0` before FETCH #2 (the name keeps going to a far NUL) gets an **unbounded** copy. Single-fetch already overflows (92 > 32); the race lifts the 92-byte ceiling to arbitrary length.

**Impact:** unauthenticated secure-world **stack** buffer overflow with attacker bytes — canary/return-address corruption, secure-world code-exec potential. Severity **High** (higher reach than BUG 1: no signed image required). Confirmed in the emulator: the deterministic 92-byte copy smashes the canary (TA wedges in `__stack_chk_fail`); winning the `+0x9c` race produces an unbounded copy that faults inside `memcpy` (`pc=0x10c1dc`, caught as `0xffff0000`) — the TA's own header dump shows `+0x9c` holding the racer's `0xffffffff` *after* the chunk-count cap passed with `0`. PoC: `pocs/09db_verify_load2ion_name_stackov/`.

**Fix:** bound the name copy (`min(strlen, sizeof(local_28)-1)`); snapshot the header into secure memory before parsing; read `+0x9c` once into a local reused for the cap and any later use.

> Note on `0x1039b4`: the chunk-table `memcpy` in `image_verifiy_decrypt` (`FUN_00103708`) is **not** the vulnerable site — `chunk_count` is loaded once at `0x103958` and that single register drives both the `<= 16` bound and the copy length, and the destination exactly fits 16 chunks. The genuine raceable **stack** double-fetch is BUG 4 above (cmd 2, the name field).

---

## Summary

| # | location | trigger | class | gated by sig? | severity |
|---|----------|---------|-------|---------------|----------|
| 1 | `dji_image_verify_update` `0x103f74` (cmd 4) | CA + signed image + race | double-fetch → secure `.bss`/heap overflow | yes (raceable) | **High** |
| 2 | `dji_fw_verify_init_ext` (cmd 6) | CA, unauthenticated | unvalidated memref ptr/len → OOB read (NW) | no | Low/Med |
| 3 | whole verify/load pipeline | CA + signed image | in-place shared-mem TOCTOU (root cause) | yes | — |
| 4 | `fw_image_verify_load2ion` `0x1008dc` (cmd 2) | CA, unauthenticated (+ race for unbounded) | unbounded `strlen`/`memcpy` of name + `+0x9c` double-fetch → secure stack overflow | **no** | **High** |

The TA gets the easy controls right (strict param typing, chunk-count caps, signature gating). The exploitable weakness is structural: it trusts length/count fields read repeatedly from attacker-controlled shared memory after validation. **BUG 1** is the priority — it converts the firmware-verify path into a secure-world memory-corruption primitive whose blast radius includes the live firmware decryption key in `.bss` and the TA heap.
