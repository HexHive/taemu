from qiling.os.const import STRING, INT, BYTE, POINTER

def parse_fmt_str(format_param, final_params):
    format_dict = []
    i = 0
    while i < len(format_param):
        if format_param[i] == "%":
            next_char = format_param[i + 1]
            if next_char == "s":
                format_dict.append(f"s")
                i += 2
            else:
                format_dict.append(f"d")
                i += 2
        else:
            i += 1
    for i, fm in enumerate(format_dict):
        if fm == "s":
            final_params[f"{i}"] = STRING
        else:
            final_params[f"{i}"] = INT
    return final_params

