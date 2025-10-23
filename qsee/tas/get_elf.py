import sys
import argparse
import tempfile
import os
import shutil
import io
import tarfile
import logging
import pexpect
import struct
import fs
import zipfile
import lz4


def unify_tas(file_chunk_dir: str, fw_out_dir: str):

    # unify .mdt and .bXX to ELF
    # https://github.com/pandasauce/unify_trustlet/blob/master/unify_trustlet.py

    for filename in os.listdir(file_chunk_dir):
        if filename.endswith(".mdt"):
            chunk_path = os.path.join(file_chunk_dir, filename)
            filetype = pexpect.run(f"file -b {chunk_path}").decode()
            if filetype.startswith("data"):
                continue
            bitness = filetype.split(",")[0].split(" ")[1].split("-")[0]
            arch = filetype.split(",")[1]
            if "arm" not in arch.lower():
                print(f"Arch of {filename} is not arm, it is {arch}")
                continue

            trustlet_name = filename[:-4]

            if bitness == "32":
                print("bitness of %s is %s" % (filename, bitness))
                ELF_HEADER_SIZE = 0x34
                E_PHNUM_OFFSET = 0x2C
                PHDR_SIZE = 0x20
                P_FILESZ_OFFSET = 0x10
                P_OFFSET_OFFSET = 0x4

            elif bitness == "64":
                print("bitness of %s is %s" % (filename, bitness))
                ELF_HEADER_SIZE = 0x40
                E_PHNUM_OFFSET = 0x38
                PHDR_SIZE = 0x38
                P_FILESZ_OFFSET = 0x20
                P_OFFSET_OFFSET = 0x8
            else:
                print("bitness of %s is %s" % (filename, bitness))
                return

            # Reading the ELF header from the ".mdt" file
            mdt = open(os.path.join(chunk_path), "rb")
            elf_header = mdt.read(ELF_HEADER_SIZE)
            phnum = struct.unpack(
                "<H", elf_header[E_PHNUM_OFFSET : E_PHNUM_OFFSET + 2]
            )[0]
            print("[+] Found %d program headers in %s" % (phnum, trustlet_name))

            # Reading each of the program headers and copying the relevant chunk
            output_file_path = os.path.join(fw_out_dir, f"{trustlet_name}.elf")
            output_file = open(output_file_path, "wb")
            for i in range(0, phnum):

                # Reading the PHDR
                # print "[+] Reading PHDR %d" % i
                phdr = mdt.read(PHDR_SIZE)
                p_filesz = struct.unpack(
                    "<I", phdr[P_FILESZ_OFFSET : P_FILESZ_OFFSET + 4]
                )[0]
                p_offset = struct.unpack(
                    "<I", phdr[P_OFFSET_OFFSET : P_OFFSET_OFFSET + 4]
                )[0]
                # print "[+] Size: 0x%08X, Offset: 0x%08X" % (p_filesz, p_offset)

                if p_filesz == 0:
                    # print "[+] Empty block, skipping"
                    continue  # There's no backing block

                # Copying out the data in the block
                block = open(
                    os.path.join(file_chunk_dir, f"{trustlet_name}.b{i:02d}"),
                    "rb",
                ).read()
                output_file.seek(p_offset, 0)
                output_file.write(block)

            output_file.close()
            mdt_file_path = os.path.join(fw_out_dir, filename)
            mdt.seek(0)
            print(f"dumping mdt to {mdt_file_path}")
            with open(mdt_file_path, "wb") as f:
                f.write(mdt.read())
            mdt.close()
        if filename.endswith(".mbn"):
            chunk_path = os.path.join(file_chunk_dir, filename)
            filetype = pexpect.run(f"file -b {chunk_path}").decode()
            if filetype.startswith("data"):
                print(f"Filetype data of {filename}")
                continue
            bitness = filetype.split(",")[0].split(" ")[1].split("-")[0]
            arch = filetype.split(",")[1]
            if "arm" not in arch.lower():
                print(f"Arch of {filename} is not arm, it is {arch}")
                continue
            mdn_file_path = os.path.join(fw_out_dir, filename)
            mdn = open(os.path.join(chunk_path), "rb")
            print(f"dumping mdn to {mdn_file_path}")
            with open(mdn_file_path, "wb") as f:
                f.write(mdn.read())
            mdn.close()


unify_tas(".", ".")
