#!/usr/bin/env python3
"""Extract symbols from the TA json/yaml and save them to a gdb-importable format.

Arguments:
    ta_path: Path to the TA file.
    output: Path to the output file.

Output:
    A file containing the symbols in gdb-importable format.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

try:
    from emulator.emulate.ta_info import load_ta_adjacent_info
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from emulator.emulate.ta_info import load_ta_adjacent_info

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("ta_path", type=Path)
    parser.add_argument("--output", "-o", type=Path, default=None, required=False)
    args = parser.parse_args()

    output_path = args.output or args.ta_path.with_suffix(".sym-elf")

    ta_info = load_ta_adjacent_info(args.ta_path)
    with tempfile.TemporaryDirectory(prefix="extract-symbols-") as tmp_dir:
        tmp_dir_path = Path(tmp_dir)
        asm_path = tmp_dir_path / "symbols.S"
        intermediate_path = tmp_dir_path / "symbols.o"

        with asm_path.open("w") as asm_file:
            # .text_addr = 0x555555554000
            asm_file.write(".section .text, \"ax\"\n")
            asm_file.write(".org 0\n")

            func_starts = [(func_name[:-6], addr) for func_name, addr in  ta_info.items() if func_name.endswith("_start")]

            for name, addr in sorted(func_starts, key=lambda x: x[1]):
                print(f"Adding function {name} at {addr:#0x}", file=sys.stderr)
                asm_file.write(f".globl {name}\n")
                asm_file.write(f".type {name}, %function\n")
                asm_file.write(f".org {addr:#0x}\n{name}:\n\n")
        # needs 'apt-get install binutils-aarch64-linux-gnu
        try:
            subprocess.run(
                ["aarch64-linux-gnu-as", "-o", str(intermediate_path), str(asm_path)],
                check=True,
            )
        except subprocess.CalledProcessError as e:
            with open(asm_path, "r") as f:
                print(f.read(), file=sys.stderr)
            print("========", file=sys.stderr)
            print(f"Error assembling {asm_path}: {e}", file=sys.stderr)
            exit(1)
        subprocess.run(
            ["aarch64-linux-gnu-ld", "-o", str(output_path), str(intermediate_path)],
            check=True,
        )
