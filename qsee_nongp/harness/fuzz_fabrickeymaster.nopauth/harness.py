from typing import TYPE_CHECKING
import pwn
from qiling import Qiling
from pathlib import Path


if TYPE_CHECKING:
    from emulator.emulate.non_gp.qsee.params import QseeCommandParams, setup_qsee_fuzz
else:
    from emulate.non_gp.qsee.params import QseeCommandParams, setup_qsee_fuzz

filename = Path(__file__).stem.replace("_fuzz", "")

REQ_CAP = 0x80000
RSP_LEN = 0x1000

def take_padded(buf: bytes, off: int, n: int) -> tuple[bytes, int]:
    chunk = buf[off:off + n]
    return chunk.ljust(n, b"\x00"), off + len(chunk)

def build_valid_body(raw: bytes, max_body: int = REQ_CAP - 8) -> bytes:
    """
    Build a body that always satisfies validate_msg_length():

      req[1] = body_len
      body is a sequence of records:
        type 1: 3-byte item/tag prefix, 0x01, u32 value    => 8 bytes
        type 2: 3-byte item/tag prefix, 0x02, u32(len), payload
                                                           => 8 + len bytes

    The TA only checks the high byte in validate_msg_length(), but
    deserialize_msg() consumes the lower 24 bits as part of the item tag.
    Limit references from the TA:
      - validate_msg_length() accepts body_len up to 0x7fff8
      - get_msg_length() returns body_len + 8 and treats values above 0x80000
        as invalid

    We derive record structure from AFL bytes, but force consistency.
    """
    out = bytearray()
    i = 0

    while i < len(raw) and len(out) + 8 <= max_body:
        ctrl = raw[i]
        i += 1

        # validate_msg_length() only cares about the 4th byte, but the first
        # three bytes still flow into deserialize_msg() as the low 24 bits of
        # the item/tag identifier.
        hdr3, i = take_padded(raw, i, 3)

        # Bit 0 chooses record kind
        want_type2 = ((ctrl & 1) == 0)

        if want_type2:
            # Use a full u32 length selector so the harness can reach the same
            # payload sizes the TA accepts, bounded by remaining room.
            wanted_bytes, i = take_padded(raw, i, 4)
            wanted = int.from_bytes(wanted_bytes, "little")

            room = max_body - len(out) - 8
            take = min(wanted, room, len(raw) - i)
            payload = raw[i:i + take]
            i += take

            out += hdr3
            out += b"\x02"
            out += pwn.p32(len(payload))
            out += payload
        else:
            tail4, i = take_padded(raw, i, 4)
            out += hdr3
            out += b"\x01"
            out += tail4

        # Let AFL also influence record count.
        # High bit means “stop here” once we have at least one record.
        if (ctrl & 0x80) and len(out) >= 8:
            break

    # If AFL gives us almost nothing, still emit one valid record
    if not out:
        out += b"\x00\x00\x00\x01" + b"\x00" * 4

    return bytes(out)

def place_input_callback(ql: Qiling, input: bytes, iters: int):
    del iters  # We are not using pers iters
    ql.log.info("%s custom harness!!!! Placing input: %s", filename.upper(), input[:10])

    # Example setup
    RSP_LEN = 0x1000
    if not input:
        return False

    cmds = [
        1,
        2,
        3,
        4,
        100,  # Test handler!
    ]
    cmd = cmds[input[0] % len(cmds)]

    body = build_valid_body(input[1:])
    req = pwn.flat({0: pwn.p32(cmd), 4: pwn.p32(len(body)), 8: body,})

    cmd_params = QseeCommandParams(req, req_len=len(req), rsp_len=RSP_LEN)

    setup_qsee_fuzz(ql, cmd_params, input)
    return True
