#!/usr/bin/env python3

import json
import sys

import yaml


def normalize_metadata(raw):
    out = {}
    for key, value in raw.items():
        if isinstance(value, dict):
            if "start" in value:
                out[f"{key}_start"] = value["start"]
            if "end" in value:
                out[f"{key}_end"] = value["end"]
        else:
            out[key] = value
    return out


def main():
    if len(sys.argv) != 3:
        print("usage: yaml_to_json.py <input.yml> <output.json>", file=sys.stderr)
        raise SystemExit(1)

    in_path, out_path = sys.argv[1], sys.argv[2]
    with open(in_path, "r") as infile:
        raw = yaml.safe_load(infile)
    normalized = normalize_metadata(raw)
    with open(out_path, "w") as outfile:
        json.dump(normalized, outfile, indent=2)
        outfile.write("\n")


if __name__ == "__main__":
    main()
