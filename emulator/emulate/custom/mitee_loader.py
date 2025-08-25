import subprocess
import sys
import re

def mitee_read_relocs(ta_path):
    raw = subprocess.check_output(f'readelf -r --use-dynamic --wide {ta_path}', shell=True).decode()
    raw = raw[raw.find("'PLT' relocation section"):]
    lines = raw.split('\n')
    lines = lines[2:]
    out = []
    for l in lines:
        mtch = re.match(r'([0-9a-z]+) +([0-9a-z]+) +R_AARCH64_JUMP_SLOT +0000000000000000 +([a-zA-Z_]+) \+', l)
        if not mtch:
            continue
        out.append((mtch.group(3), int(mtch.group(1),16)))
    return out

if __name__ == "__main__":
    mitee_read_relocs(sys.argv[1])
    