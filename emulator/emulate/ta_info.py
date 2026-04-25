import json
from pathlib import Path

import yaml


def load_ta_adjacent_info(ta_path: Path):
    yml_path = ta_path.with_suffix(".yml")
    if yml_path.exists():
        with yml_path.open("r") as f:
            yml_info = yaml.safe_load(f)
        ta_info = {}
        for k, v in yml_info.items():
            ta_info[f"{k}_start"] = v["start"]
            ta_info[f"{k}_end"] = v["end"]
        return ta_info

    json_path = ta_path.with_suffix(".json")
    if not json_path.exists():
        raise FileNotFoundError(f"JSON/YAML file for {ta_path} not found")

    return json.loads(json_path.read_text())
