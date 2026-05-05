import json
from pathlib import Path

import yaml


def load_yml_info(yml_path: Path):
    with yml_path.open("r") as f:
        yml_info = yaml.safe_load(f)
    ta_info = {}
    for k, v in yml_info.items():
        if not isinstance(v, dict):
            continue
        if not {"start", "end"} <= set(v):
            continue
        ta_info[f"{k}_start"] = v["start"]
        ta_info[f"{k}_end"] = v["end"]
    return ta_info
    
def load_json_info(json_path: Path):
    return json.loads(json_path.read_text())

def load_ta_adjacent_info(ta_path: Path):
    yml_path = ta_path.with_suffix(".yml")
    if yml_path.exists():
        return load_yml_info(yml_path)

    json_path = ta_path.with_suffix(".json")
    if json_path.exists():
        return load_json_info(json_path)

    raise FileNotFoundError(f"JSON/YAML file for {ta_path} not found")
