from qiling.os.const import STRING, INT, BYTE, POINTER


def read_c_str(ql, addr):
    read = b""
    while True:
        b = ql.mem.read(addr, 1)
        if b == b"\x00":
            break
        else:
            read += b
            addr += 1
    return read


def fixup_format(format_param):
    import re as _re
    format_param = format_param.replace("%p", "0x%x")
    format_param = format_param.replace("%llu", "%u")
    format_param = format_param.replace("%zu", "%u")
    format_param = format_param.replace("%zd", "%d")
    format_param = format_param.replace("%#zx", "%#x")
    # Strip C99 size/length modifiers (z / ll / l / h / hh) that precede a
    # conversion Python's % accepts (X x d i u o), keeping any flags/width
    # (e.g. mitee hexdump "%04zX" -> "%04X", "%zd" -> "%d", "%lx" -> "%x").
    format_param = _re.sub(r"%([0-9.#+ -]*)(?:hh|h|ll|l|z|j|t)([XxdiuoeEfgG])",
                           r"%\1\2", format_param)
    return format_param


def parse_fmt_str(ql, format_param, final_params, func_name, arg=None):
    format_dict = []
    i = 0
    while i < len(format_param):
        if format_param[i] == "%":
            next_char = format_param[i + 1]
            if next_char == "s":
                format_dict.append(f"s")
                i += 2
            elif format_param[i : i + 4] == "%-*s" or format_param[i : i + 4] == "%.*s":
                format_dict.append(f"d")
                format_dict.append(f"s")
                i += 4
            else:
                format_dict.append(f"d")
                i += 2
        else:
            i += 1
    if func_name == "vsnprintf":
        # TODO fix!!
        arg_ptr = ql.mem.read_ptr(arg + 2 * ql.arch.pointersize)  # ???
        params = {}
        for i, fm in enumerate(format_dict):
            # read c string
            if fm == "s":
                if not ql.mem.is_mapped(ql.mem.read_ptr(arg_ptr), 1):
                    arg_ptr += ql.arch.pointersize
                params[f"{i}"] = read_c_str(ql, ql.mem.read_ptr(arg_ptr)).decode(
                    "utf-8", errors="replace"
                )
            else:
                params[f"{i}"] = ql.mem.read_ptr(arg_ptr)
            arg_ptr += ql.arch.pointersize
        return params
    else:
        for i, fm in enumerate(format_dict):
            if fm == "s":
                final_params[f"{i}"] = STRING
            else:
                final_params[f"{i}"] = INT
        params = ql.os.resolve_fcall_params(final_params)
        # Keep only the positional conversion args ("0".."N-1"); drop whatever
        # fixed named params this wrapper had (format / s / n / log_level /
        # filename / ...). This is robust for ANY printf-family wrapper without
        # per-function-name registration -- previously an unregistered name
        # (e.g. qsee_log, the capital-P TEE_LogPrintf) hit emu_stop and left the
        # named keys in, so the caller's range(len(params)) KeyError'd.
        params = {k: v for k, v in params.items() if k.isdigit()}
        # resolve_fcall_params can surface fewer positional args than the format
        # has conversions (more %-specifiers than the calling convention exposed,
        # or garbage args under fuzzing). Backfill each with a type-appropriate
        # default so callers can iterate range(len(params)) and the `%` apply
        # won't raise.
        for i, fm in enumerate(format_dict):
            params.setdefault(f"{i}", "" if fm == "s" else 0)
    return params

