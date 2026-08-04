#!/usr/bin/env python3
import os
import struct

EI_CLASS = 4
EI_DATA = 5

ET_DYN = 3


def is_loader(path):
    try:
        with open(path, "rb") as f:
            ident = f.read(16)
            if ident[0:4] != b"\x7fELF":
                return False

            elf_class = ident[EI_CLASS]
            endian = ident[EI_DATA]

            # endian format
            if endian == 1:  # little endian
                fmt16 = "<H"
                fmt32 = "<I"
                fmt64 = "<Q"
            elif endian == 2:  # big endian
                fmt16 = ">H"
                fmt32 = ">I"
                fmt64 = ">Q"
            else:
                return False

            # read type (e_type) and entry (e_entry)
            f.seek(16)
            if elf_class == 1:  # 32-bit
                e_type = struct.unpack(fmt16, f.read(2))[0]
                f.seek(24)
                e_entry = struct.unpack(fmt32, f.read(4))[0]
            elif elf_class == 2:  # 64-bit
                e_type = struct.unpack(fmt16, f.read(2))[0]
                f.seek(24)
                e_entry = struct.unpack(fmt64, f.read(8))[0]
            else:
                return False

            # Heuristic: loader is ET_DYN with a non-zero entry point
            return e_type == ET_DYN and e_entry != 0
    except Exception:
        return False


def find_loaders(directory):
    for root, _, files in os.walk(directory):
        for f in files:
            path = os.path.join(root, f)
            if is_loader(path):
                print("Loader candidate:", path)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <directory>")
        sys.exit(1)

    find_loaders(sys.argv[1])
