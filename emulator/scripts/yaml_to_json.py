#!/usr/bin/env python3

import json
from pathlib import Path
import sys

import yaml

try:
    from emulator.emulate.ta_info import load_yml_info
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from emulator.emulate.ta_info import load_yml_info


def main():
    if len(sys.argv) != 3:
        print("usage: yaml_to_json.py <input.yml> <output.json>", file=sys.stderr)
        raise SystemExit(1)

    in_path, out_path = Path(sys.argv[1]), Path(sys.argv[2])
    if not in_path.exists():
        raise FileNotFoundError(f"YAML file {in_path} not found")
    if out_path.exists():
        out_path.unlink()
    ta_info = load_yml_info(in_path)
    with out_path.open("w") as outfile:
        json.dump(ta_info, outfile, indent=2)
        outfile.write("\n")

if __name__ == "__main__":
    main()
