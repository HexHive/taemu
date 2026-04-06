from typing import TYPE_CHECKING
from pathlib import Path
import hashlib
import functools

from .gp.utils.err import TEE_SUCCESS


if TYPE_CHECKING:
    from .ta_mgr import TAEMU

CACHE_PATH = Path(".snapshots")
CACHE_PATH.mkdir(parents=True, exist_ok=True)

def ql_cached_call(func):
    """Caches the ql state after the call to a function in TA, so we don't have to re-run it.
    If we are debugging, the caching is disabled. 
    """
    def distinct_filename(taemu:'TAEMU', fn_name:str, args, kwargs):
        return Path(f"{taemu.ta_name}_"+hashlib.md5(taemu.ta_path.read_bytes()).hexdigest()) / f"{fn_name}_arg:{hashlib.md5((str(args) + str(kwargs)).encode()).hexdigest()}.bin"
    
    @functools.wraps(func)
    def wrapper(self:'TAEMU', *args, **kwargs):
        nonlocal distinct_filename
        fn = CACHE_PATH / distinct_filename(self, func.__name__, args, kwargs)

        should_load = self.use_cache and fn.exists() and not self.ql.debugger
        if should_load:
            try:
                self.ql.restore(snapshot=fn)
                self.ql.log.warning("Loaded snapshot of %s(%s, %s) from %s", func.__name__, args, kwargs, fn)
                # As per our assumption, the ret_val is TEE_SUCCESS
                return TEE_SUCCESS
            except Exception as e:
                self.ql.log.warning("Re-running, as failed to load snapshot of %s(%s, %s) from %s: %s", func.__name__, args, kwargs, fn, e)

        fn.parent.mkdir(parents=True, exist_ok=True)
        ret = func(self, *args, **kwargs)
        fn_ret = self.ql.os.fcall.cc.getReturnValue()
        assert ret == fn_ret, f"ret != fn_ret: {ret} != {fn_ret}"
        if fn_ret == TEE_SUCCESS:
            self.ql.save(snapshot=fn)
            self.ql.log.info("Last call was successful, saving snapshot of %s", func.__name__)
        else:
            self.ql.log.warning("Last call was %#0x, not saving snapshot of %s", fn_ret, func.__name__)
        return ret
    return wrapper
