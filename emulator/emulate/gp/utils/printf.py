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
    format_param = format_param.replace("%p", "0x%x")
    format_param = format_param.replace("%llu", "%u")
    format_param = format_param.replace("%zu", "%u")
    format_param = format_param.replace("%#zx", "%#x")
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
            elif format_param[i:i+4] == "%-*s" or format_param[i:i+4] == "%.*s":
                format_dict.append(f"d")
                format_dict.append(f"s")
                i += 4
            else:
                format_dict.append(f"d")
                i += 2
        else:
            i += 1
    if func_name == "vsnprintf":
        #TODO fix!!
        arg_ptr = ql.mem.read_ptr(arg+2*ql.arch.pointersize)  # ???
        params = {} 
        for i, fm in enumerate(format_dict):
            # read c string
            if fm == "s":
                if(not ql.mem.is_mapped(ql.mem.read_ptr(arg_ptr),1)):
                    arg_ptr += ql.arch.pointersize
                params[f"{i}"] = read_c_str(ql, ql.mem.read_ptr(arg_ptr)).decode('utf-8', errors='replace')
            else:
                params[f"{i}"] = ql.mem.read_ptr(arg_ptr)
            arg_ptr  += ql.arch.pointersize
        return params
    else:
        for i, fm in enumerate(format_dict):
            if fm == "s":
                final_params[f"{i}"] = STRING
            else:
                final_params[f"{i}"] = INT
        params = ql.os.resolve_fcall_params(final_params)
        if func_name == "TEE_Logprintf" or func_name == "printf" or func_name == "msee_ta_printf_va":
            del params["format"]
        elif func_name == "snprintf":
            del params["format"]
            del params["s"]
            del params["n"]
        elif func_name == "sprintf":
            del params["format"]
            del params["s"]
        else:
            ql.log.error(f"unkown printf format resolving function: {func_name}")
            ql.emu.stop()
    return params 

