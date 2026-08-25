import os
import json
import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Empty
import sys
from emulate.redis_queue import RedisQueue
from dataclasses import dataclass
from typing import Optional, Callable, Dict, Any, List, Tuple
from enum import Enum
import hashlib

class Status(Enum):
    FUZZING = 1
    REPLAYING = 2
    INTERACTIVE = 3
    DF_FUZZING = 4
    DF_REPLAY = 5
    DF_VALIDATE = 6

@dataclass
class Record:
    addr: int
    size: Optional[int] = None
    regs: Optional[Dict[str, Any]] = None
    is_second_fetch: bool = False


class Recorder:
    def __init__(
        self,
        q: RedisQueue,
        record_seed_dir,
        record_meta_dir = None,
        log: logging.Logger = None,
        *,
        batch_size: int = 50,
        max_workers: int = 4,
    ):
        self.q = q
        self.record_seed_dir = record_seed_dir
        self.record_meta_dir = record_meta_dir
        self._log = log or logging.getLogger(__name__)
        self._log.info(
            "[+] Recorder is enabled and working on queue: {}".format(
                getattr(self.q, "queue_name", None)
            )
        )
        if not log:
            self._log.handlers = [logging.StreamHandler(sys.stdout)]
            # self._log.setLevel(logging.INFO)
        self._batch_size = batch_size
        self._max_workers = max_workers
        self._batch_items = []
        self._executor = None
        self._batch_processing = False
        self._batch_lock = threading.Lock()
        self._last_processing = time.time()

    def start(self):
        self._consume_records()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._log.info(
            f"[{__name__}] cleanup context manager and process the final batch of {len(self._batch_items)} items"
        )
        self._dump_info()
        self._trigger_batch_processing()
        self._log.info(f"[{__name__}] Recorder process exited gracefully")
        return False  # don't suppress exceptions

    def _consume_records(self):
        self._log.info(
            f"[{__name__}] Starting recorder for directory {self.record_seed_dir}"
        )

        self._batch_items = []

        if not os.path.exists(self.record_seed_dir):
            os.makedirs(self.record_seed_dir)
        if self.record_meta_dir is not None and not os.path.exists(self.record_meta_dir):
            os.makedirs(self.record_meta_dir)
        
        while True:
            try:
                item = self.q.get(timeout=8.0)

                if item == "STOP":
                    self._log.info(f"[{__name__}] Received STOP message, exiting...")
                    break

                if self._should_trigger_batch_processing():
                    self._trigger_batch_processing()

                with self._batch_lock:
                    if self._filter_handler(item):
                        self._batch_items.append(item)

            except Empty:
                self._trigger_batch_processing()
                continue
            except Exception as e:
                self._log.error(f"[{__name__}] Error processing item: {e}")
                continue
            
            
    def _unfold_record(self, item: Dict[str, Any]) -> Tuple[bytes, str, List, Dict[str, Any]]:
        input_data = item.get("input", b"")
        key = item.get("key", "")
        records = item.get("records", [])
        meta = item.get("meta", {})
        return input_data, key, records, meta
    

    def _batch_process_items(self, items: list):
        if not items:
            return

        def process_single_item(item):
            try:
                
                input_data, key, records, meta  = self._unfold_record(item)

                if not key:
                    return False, f"Empty key for item"

                # save input data file
                file_path = os.path.join(self.record_seed_dir, key)
                try:
                    with open(file_path, "wb") as f:
                        if isinstance(input_data, bytes):
                            f.write(input_data)
                        else:
                            f.write(str(input_data).encode("utf-8"))
                except Exception as e:
                    return False, f"Error saving file {file_path}: {e}"

                # save metadata file
                metadata_file = os.path.join(self.record_seed_dir, f"{key}.meta")
                try:
                    metadata = {
                        "key": key,
                        "meta": meta,
                        "updated_at": time.time(),
                        "full_to_replay": meta.get("full_record", False),
                        "records": records,
                    }
                    with open(metadata_file, "w") as f:
                        json.dump(metadata, f, indent=2)
                except Exception as e:
                    return False, f"Error saving metadata to {metadata_file}: {e}"

                return True, f"Successfully processed item"

            except Exception as e:
                return False, f"Error processing item: {e}"

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = [executor.submit(process_single_item, item) for item in items]

            success_count = 0
            error_count = 0

            for future in as_completed(futures):
                try:
                    success, message = future.result()
                    if success:
                        success_count += 1
                    else:
                        error_count += 1
                        self._log.error(
                            f"[{__name__}] Batch processing error: {message}"
                        )
                except Exception as e:
                    error_count += 1
                    self._log.error(f"[{__name__}] Future execution error: {e}")

            self._log.info(
                f"[{__name__}] Batch processing completed: {success_count} success, {error_count} errors"
            )

    def _should_trigger_batch_processing(self):
        with self._batch_lock:
            return (
                (len(self._batch_items) >= self._batch_size or time.time() - self._last_processing > 60)
                and not self._batch_processing
            )

    def _trigger_batch_processing(self):
        with self._batch_lock:
            self._dump_info()
            if self._batch_processing or not self._batch_items:
                return
            self._batch_processing = True
            self._last_processing = time.time()
            items_to_process = self._batch_items.copy()
            self._batch_items.clear()

        # use a separate thread to process the items
        def batch_worker():
            try:
                self._batch_process_items(items_to_process)
            finally:
                with self._batch_lock:
                    self._batch_processing = False

        threading.Thread(target=batch_worker).start()

    def _filter_handler(self, item) -> bool:
        return True

    def _dump_info(self):
        pass

class SimpleFilterRecorder(Recorder):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._seen_addresses = set()
        self._seen_addresses_2_count = {}
        self._seen_addresses_2_data = {}
        
    
    def _calc_control_flow_hash(self, records: List[Record]) -> str:
        filtered = [
            # remove reg_hash and size from the records
            {**record, "size": None, "regs": {k: v for k, v in record.get("regs", {}).items() if k != "reg_hash"}}
            if isinstance(record, dict) and "regs" in record
            else record
            for record in records
        ]
        return hashlib.sha256(json.dumps(filtered, sort_keys=True).encode()).hexdigest()

    def _filter_handler(self, item) -> bool:
        _, _, records, _ = self._unfold_record(item)
        control_flow_hash = self._calc_control_flow_hash(records)
        
        if control_flow_hash in self._seen_addresses:
            self._seen_addresses_2_count[control_flow_hash] += 1
            self._log.info(f"[{__name__}] Skipping duplicate control flow hash: {control_flow_hash}")
            return False
        
        self._log.info(f"[{__name__}] Adding suspicious records to the disk: {control_flow_hash}")
        self._seen_addresses.add(control_flow_hash)
        self._seen_addresses_2_count[control_flow_hash] = 1
        self._seen_addresses_2_data[control_flow_hash] = records
        return True

    def _dump_info(self):
        if self.record_meta_dir is not None:
            open(os.path.join(self.record_meta_dir, f'{os.getpid()}_hash2count.json'),'w+').write(json.dumps(self._seen_addresses_2_count, indent=2))
            open(os.path.join(self.record_meta_dir, f'{os.getpid()}_hash2data.json'),'w+').write(json.dumps(self._seen_addresses_2_data, indent=2))
