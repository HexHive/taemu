import sys
import os


def is_not_elf(filename):
    if filename.endswith(".so"):
        return False
    elif filename.endswith(".cfg"):
        return True
    elif filename.endswith(".txt"):
        return True
    elif filename.endswith(".cert"):
        return True
    elif filename.endswith(".kv"):
        return True
    elif filename.startswith("sst."):
        return True
    elif filename.endswith(".crt"):
        return True
    elif filename.endswith(".der"):
        return True
    elif "key_custom" in filename:
        return True
    else:
        return False


def extract_zero_terminated_strings(data):
    strings = []
    current_string = b""

    for byte in data:
        if byte == 0:
            if current_string:
                print(current_string)
                strings.append(current_string.decode("utf-8"))
                current_string = b""
        else:
            current_string += bytes([byte])

    if current_string:
        strings.append(current_string.decode("utf-8"))

    return strings


soter = open(sys.argv[1], "rb").read()

# TODO: Fix the offsets depending on the soter file
soter_filenames_bytes = soter[0x00000698:0xCBC]
filenames = extract_zero_terminated_strings(soter_filenames_bytes)
print("nr files:", len(filenames))
filenames_new = []
for f in filenames:
    if f.startswith("moe"):
        f1, f2 = f.split(" ")
        filenames_new.append(f1)
        filenames_new.append(f2)
    else:
        filenames_new.append(f)
filenames = filenames_new
for i, f in enumerate(filenames):
    print(f"{i}: {f}")
lib_names = [lib_name for lib_name in filenames if lib_name.endswith("so")]
for i, f in enumerate(lib_names):
    print(f"{i}: {f}")
print("nr libs so ending", len(lib_names))

curr_elf_start = 0x1000
out_path = "soter_dump"
os.system(f"mkdir -p {out_path}")
nr_ = 0

elf_files = [a for a in filenames if not is_not_elf(a)]
for i, f in enumerate(elf_files):
    print(f"{i}: {f}")

for k in range(0x1000, len(soter), 0x1000):
    # print(soter[k:k+4].hex())
    if soter[k : k + 4] == b"\x7fELF":
        # print("dumping lib")
        if curr_elf_start - k != 0:
            open(f"{out_path}/{elf_files[nr_]}", "wb").write(soter[curr_elf_start:k])
            nr_ += 1
        curr_elf_start = k
open(f"{out_path}/{elf_files[nr_]}", "wb").write(soter[curr_elf_start:k])


print("nr elf headers:", nr_)

# print(len([a for a in lib_]))
