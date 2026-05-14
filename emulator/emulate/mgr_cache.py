from typing import TYPE_CHECKING
from pathlib import Path
import hashlib
import functools
import pickle

from .gp.utils.err import TEE_SUCCESS
from .non_gp.qsee.models import restore_active_qsee_state, save_active_qsee_state


if TYPE_CHECKING:
    from .ta_mgr import TAEMU

CACHE_PATH = Path(".snapshots")
CACHE_PATH.mkdir(parents=True, exist_ok=True)

"""
Changes:
before v1: we save only ql state.
with v1: we save ql state and emu HEAP state.
"""
class TAEMU_State:
    VERSION="v2"
    def __init__(self, taemu: 'TAEMU'):
        self.taemu = taemu
    
    def save(self, filename: Path):
        emu_state = {
            "HEAP": self.taemu.HEAP,
            "ASAN": self.taemu.asan.save(),
            "QL": self.taemu.ql.save(),
            "QSEE": save_active_qsee_state(self.taemu),
        }
        with filename.open("wb") as f:
            pickle.dump(emu_state, f)
    
    def load(self, filename: Path):
        with filename.open("rb") as f:
            saved_states = pickle.load(f)
        self.taemu.ql.restore(saved_states=saved_states["QL"])
        self.taemu.asan.restore(saved_states["ASAN"])
        self.taemu.HEAP = saved_states["HEAP"]
        restore_active_qsee_state(self.taemu, saved_states.get("QSEE"))
    
    def get_unique_filename(self, fn_name:str, args, kwargs):
        t = self.taemu
        return Path(f"{t.ta_name}_"+hashlib.md5(t.ta_path.read_bytes()).hexdigest()) / f"{fn_name}_arg:{hashlib.md5((str(args) + str(kwargs)).encode()).hexdigest()}.{self.VERSION}.bin"

def ql_cached_call(func):
    """Caches the ql state after the call to a function in TA, so we don't have to re-run it.
    If we are debugging, the caching is disabled. 
    """

    @functools.wraps(func)
    def wrapper(self:'TAEMU', *args, **kwargs):
        state = TAEMU_State(self)
        filename = CACHE_PATH / state.get_unique_filename(func.__name__, args, kwargs)
        should_load = self.use_cache and not self.ql.debugger
        if not filename.exists():
            self.ql.log.warning("No snapshot found for %s(%s, %s), running.", func.__name__, args, kwargs)
        elif not should_load:
            self.ql.log.warning("Cache disabled for (existing) %s(%s, %s), running.", func.__name__, args, kwargs)
        else:
            try:
                state.load(filename)
                self.ql.log.warning("Loaded snapshot of %s(%s, %s) from %s", func.__name__, args, kwargs, filename)
                # As per our assumption, the ret_val is TEE_SUCCESS
                return TEE_SUCCESS
            except Exception as e:
                self.ql.log.warning("Rerunning. Failed to load snapshot of %s(%s, %s) from %s: %s", func.__name__, args, kwargs, filename, e)

        filename.parent.mkdir(parents=True, exist_ok=True)
        ret = func(self, *args, **kwargs)
        fn_ret = self.ql.os.fcall.cc.getReturnValue()
        assert ret == fn_ret, f"ret != fn_ret: {ret} != {fn_ret}"
        if fn_ret == TEE_SUCCESS:
            state.save(filename)
            self.ql.log.info("Last call was successful, saving snapshot of %s", func.__name__)
        else:
            self.ql.log.warning("Last call was %#0x, not saving snapshot of %s", fn_ret, func.__name__)
        return ret
    return wrapper
