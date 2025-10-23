from qiling import Qiling
from multiprocessing import shared_memory
import threading
import time
import os
import pickle


def require_class_attr(param_name, attr_name):
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            if param_name in kwargs:
                val = kwargs[param_name]

            if val != getattr(self, attr_name):
                raise ValueError(
                    f"{param_name}={val} does not match self.{attr_name}={getattr(self, attr_name)}"
                )
            return func(self, *args, **kwargs)

        return wrapper

    return decorator


class QilingWithCache(Qiling):
    def __init__(
        self,
        *args,
        cache_max_items=10000,
        shm_name="shared_memory_cache",
        shm_size=1024 * 1024,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._shm_lock = threading.RLock()
        self.shm_name = shm_name
        self.shm_size = shm_size

        # only visiable for one thread (separate copy on the process level)
        self.curr_key = None
        self._cache_meta = {}
        self._cache_lock = threading.RLock()
        self._cache_max_items = cache_max_items

        # shared memory across forked processes
        try:
            self.shm_shared = shared_memory.SharedMemory(
                create=True, size=shm_size, name=shm_name
            )
            self._write_shm({})
            self._cache = {}
        except FileExistsError:
            self.shm_shared = shared_memory.SharedMemory(name=shm_name)
            self._cache = self._read_shm()

    @staticmethod
    def _serialize(data):
        return pickle.dumps(data)

    @staticmethod
    def _deserialize(buf):
        try:
            return pickle.loads(bytes(buf).rstrip(b"\x00"))
        except Exception:
            return {}

    def _read_shm(self):
        with self._shm_lock:
            return self._deserialize(self.shm_shared.buf)

    def _write_shm(self, data):
        with self._shm_lock:
            raw = self._serialize(data)
            if len(raw) > self.shm_size:
                raise MemoryError("Shared memory too small")
            self.shm_shared.buf[: len(raw)] = raw
            self.shm_shared.buf[len(raw) :] = b"\x00" * (self.shm_size - len(raw))

    def set_curr_key(self, key):
        self.curr_key = key

    def get_curr_key(self):
        return self.curr_key

    # @require_class_attr("key", "curr_key")
    def get_cache(self, key):
        with self._cache_lock:
            return self._cache.get(key)

    # @require_class_attr("key", "curr_key")
    def set_cache(self, key, value):
        # self.log.info(
        #     f"[set_cache] Cache len: {len(self._cache)} at key {key}, thread id: {threading.get_ident()}, os process id: {os.getpid()}"
        # )
        with self._cache_lock:
            if len(self._cache) >= self._cache_max_items:
                # simple LRU eviction
                oldest = min(self._cache_meta, key=lambda k: self._cache_meta[k])
                del self._cache[oldest]
                del self._cache_meta[oldest]
                self.log.info(f"[set_cache] Evicted oldest cache item: {oldest}")

            self._cache[key] = value
            self._cache_meta[key] = time.time()

    # @require_class_attr("key", "curr_key")
    def update_cache(self, key, value, op):
        with self._cache_lock:
            if key in self._cache:
                self._cache[key] = op(self._cache[key], value)
                self._cache_meta[key] = time.time()
            else:
                self.set_cache(key, value)

    def set_shared_cache(self, key, value):
        with self._shm_lock:
            data = self._read_shm()
            data[key] = {"value": value, "last_accessed": time.time()}
            self._write_shm(data)

    def update_shared_cache(self, key, value, op):
        with self._shm_lock:
            data = self._read_shm()
            if key in data:
                data[key]["value"] = op(data[key]["value"], value)
                data[key]["last_accessed"] = time.time()
            else:
                data[key] = {"value": value, "last_accessed": time.time()}
            self._write_shm(data)

    def get_shared_cache(self, key):
        with self._shm_lock:
            data = self._read_shm()
            return data.get(key)

    def shared_cache_information(self):
        with self._shm_lock:
            data = self._read_shm()
            return {"num_items": len(data), "keys": list(data.keys())}

    def cache_information(self):
        with self._cache_lock:
            return {
                "num_items": len(self._cache),
                "keys": list(self._cache.keys()),
                "details": {
                    k: {"last_accessed": self._cache_meta[k]}
                    for k in self._cache.keys()
                },
            }

    def cache_clear(self):
        with self._cache_lock:
            self._cache.clear()
            self._cache_meta.clear()

    def close_shm(self):
        if hasattr(self, "shm_shared") and self.shm_shared is not None:
            self.shm_shared.close()
            try:
                self.shm_shared.unlink()
            except FileNotFoundError:
                pass
            self.shm_shared = None

    def __del__(self):
        self.close_shm()
        self.cache_clear()
