from qiling import Qiling
import threading
import time

class QilingWithCache(Qiling):
    def __init__(self, *args, cache_max_items=10000, **kwargs):
        super().__init__(*args, **kwargs)
        self._cache = {}
        self._cache_meta = {}            # for timestamps / LRU
        self._cache_lock = threading.RLock()
        self._cache_max_items = cache_max_items

    def cache_get(self, key):
        with self._cache_lock:
            val = self._cache.get(key)
            if val is not None:
                self._cache_meta[key] = time.time()
            return val

    def cache_set(self, key, value):
        with self._cache_lock:
            if len(self._cache) >= self._cache_max_items:
                # simple LRU eviction
                oldest = min(self._cache_meta, key=lambda k: self._cache_meta[k])
                del self._cache[oldest]
                del self._cache_meta[oldest]
            self._cache[key] = value
            self._cache_meta[key] = time.time()
        self.log.info(f"Cache set: {key}")
    
    def cache_clear(self):
        with self._cache_lock:
            self._cache.clear()
            self._cache_meta.clear()
    
    def cache_update(self, key, value, op):
        with self._cache_lock:
            if key in self._cache:
                self._cache[key] = op(self._cache[key], value)
                self._cache_meta[key] = time.time()
            else:
                self.cache_set(key, value)