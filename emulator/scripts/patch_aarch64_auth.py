#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile


AARCH64_NOP = b"\x1f\x20\x03\xd5"
AARCH64_RET = b"\xc0\x03\x5f\xd6"

NOP_MNEMONICS = {
    "bti",
    "bti.c",
    "btic",
    "pacda",
    "pacdb",
    "pacia",
    "paciasp",
    "pacia1716",
    "pacib",
    "pacibsp",
    "pacib1716",
    "autda",
    "autdb",
    "autia",
    "autiasp",
    "autia1716",
    "autib",
    "autibsp",
    "autib1716",
    "xpaclri",
}

RET_MNEMONICS = {
    "retab",
    "retaa",
}


@dataclass(frozen=True)
class Instruction:
    file_offset: int
    vaddr: int
    mnemonic: str
    op_str: str

    @property
    def text(self) -> str:
        return f"{self.mnemonic} {self.op_str}".strip()


@dataclass(frozen=True)
class Patch:
    file_offset: int
    vaddr: int
    insn: Instruction
    replacement: bytes
    prev_insn: Instruction | None
    next_insn: Instruction | None


def executable_segments(elf: ELFFile):
    for seg in elf.iter_segments():
        if seg["p_type"] != "PT_LOAD":
            continue
        if (seg["p_flags"] & 0x1) == 0:
            continue
        yield seg


def find_patches(elf_path: Path) -> list[Patch]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False
    patches: list[Patch] = []
    with elf_path.open("rb") as f:
        elf = ELFFile(f)
        for seg in executable_segments(elf):
            data = seg.data()
            print(f"Segment: {seg['p_vaddr']:#010x} - {seg['p_offset']:#x}")
            seg_vaddr = seg["p_vaddr"]
            seg_offset = seg["p_offset"]
            instructions: list[Instruction] = []
            for insn in md.disasm(data, seg_vaddr):
                if insn.size != 4:
                    continue
                instructions.append(
                    Instruction(
                        file_offset=seg_offset + (insn.address - seg_vaddr),
                        vaddr=insn.address,
                        mnemonic=insn.mnemonic.lower(),
                        op_str=insn.op_str,
                    )
                )

            for idx, insn in enumerate(instructions):
                #if insn.mnemonic in NOP_MNEMONICS:
                #    replacement = AARCH64_NOP
                #el
                if insn.mnemonic in RET_MNEMONICS:
                    replacement = AARCH64_RET
                else:
                    continue

                patches.append(
                    Patch(
                        file_offset=insn.file_offset,
                        vaddr=insn.vaddr,
                        insn=insn,
                        replacement=replacement,
                        prev_insn=instructions[idx - 1] if idx > 0 else None,
                        next_insn=instructions[idx + 1] if idx + 1 < len(instructions) else None,
                    )
                )

    return patches


def apply_patches(src: Path, dst: Path, patches: list[Patch]) -> None:
    blob = bytearray(src.read_bytes())
    for patch in patches:
        blob[patch.file_offset : patch.file_offset + 4] = patch.replacement
    dst.write_bytes(blob)


def build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output path. Defaults to <input>.nopauth",
    )
    parser.add_argument(
        "-i",
        "--in-place",
        action="store_true",
        help="Modify the input file in place.",
    )
    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="Only report candidate patches.",
    )
    return parser


def triplet_key(patch: Patch) -> tuple[str, str, str]:
    prev_text = patch.prev_insn.text if patch.prev_insn else "<START>"
    curr_text = patch.insn.text
    next_text = patch.next_insn.text if patch.next_insn else "<END>"
    return (prev_text, curr_text, next_text)


def print_patch_report(patches: list[Patch]) -> None:
    if not patches:
        return

    triplet_counts = Counter(triplet_key(p) for p in patches)
    print("Triplet stats:")
    for triplet, count in sorted(triplet_counts.items(), key=lambda item: (-item[1], item[0])):
        prev_text, curr_text, next_text = triplet
        print(f"  {count}x")
        print(f"    -4: {prev_text}")
        print(f"     0: {curr_text}")
        print(f"    +4: {next_text}")

def main():
    args = build_argparser().parse_args()
    input_path = args.input.resolve()

    if args.in_place and args.output is not None:
        raise SystemExit("--in-place and --output are mutually exclusive")

    output_path = input_path if args.in_place else (
        args.output.resolve() if args.output else input_path.with_name(f"{input_path.name}.nopauth")
    )

    patches = find_patches(input_path)

    print(f"{input_path}: {len(patches)} patch candidate(s)")
    for mnemonic, count in sorted(Counter(p.insn.mnemonic for p in patches).items()):
        print(f"  {mnemonic}: {count}")
    print_patch_report(patches)

    if args.dry_run:
        return

    if not patches:
        print("No changes written.")
        return

    apply_patches(input_path, output_path, patches)
    print(f"Wrote patched ELF to {output_path}")


if __name__ == "__main__":
    main()
