from qiling import Qiling
from multiprocessing import shared_memory
import threading
import time
import os
import pickle


class QilingWithCache(Qiling):
    def __init__(
        self,
        *args,
        cache_max_items=10000,
        shm_name="shared_memory_cache",
        shm_size=1024 * 1024,
        **kwargs
    ):
        super().__init__(*args, **kwargs)
        self._shm_lock = threading.RLock()
        self.shm_name = shm_name
        self.shm_size = shm_size

        try:
            self.shm = shared_memory.SharedMemory(
                create=True, size=shm_size, name=shm_name
            )
            self._write_shm({})
        except FileExistsError:
            self.shm = shared_memory.SharedMemory(name=shm_name)

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
            return self._deserialize(self.shm.buf)

    def _write_shm(self, data):
        with self._shm_lock:
            raw = QilingWithCache._serialize(data)
            if len(raw) > self.shm_size:
                raise MemoryError("Shared memory too small")
            self.shm.buf[: len(raw)] = raw
            self.shm.buf[len(raw) :] = b"\x00" * (self.shm_size - len(raw))

    def set_cache(self, key, value):
        with self._shm_lock:
            data = self._read_shm()
            data[key] = {"value": value, "last_accessed": time.time()}
            self._write_shm(data)

    def update_cache(self, key, value, op):
        with self._shm_lock:
            data = self._read_shm()
            if key in data:
                data[key]["value"] = op(data[key]["value"], value)
                data[key]["last_accessed"] = time.time()
            else:
                data[key] = {"value": value, "last_accessed": time.time()}
            self._write_shm(data)

    def get_cache(self, key):
        with self._shm_lock:
            data = self._read_shm()
            return data.get(key)

    def cache_information(self):
        with self._shm_lock:
            data = self._read_shm()
            return {"num_items": len(data), "keys": list(data.keys())}

    def close_shm(self):
        if hasattr(self, "shm") and self.shm is not None:
            self.shm.close()
            try:
                self.shm.unlink()
            except FileNotFoundError:
                pass
            self.shm = None

    def __del__(self):
        self.close_shm()
