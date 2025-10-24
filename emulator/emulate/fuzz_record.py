from multiprocessing import Queue
import os
import json
import threading
import time
import signal
import logging


class Recorder:
    def __init__(self, q: Queue, record_seed_dir, log: logging.Logger):
        self.q = q
        self.record_seed_dir = record_seed_dir
        self.log = log or logging.getLogger(__name__)

    def start(self):
        self._consume_records()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        print(f"[{__name__}] Context manager cleanup...")
        return False  # Don't suppress exceptions

    def _consume_records(self):
        print(f"[{__name__}] Starting recorder for directory {self.record_seed_dir}")

        # Set up signal handlers for graceful shutdown
        shutdown_requested = threading.Event()

        def signal_handler(signum, _):
            self.log.info(f"[{__name__}] Received signal {signum}, initiating shutdown...")
            shutdown_requested.set()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        if not os.path.exists(self.record_seed_dir):
            os.makedirs(self.record_seed_dir)

        while not shutdown_requested.is_set():
            try:
                # Use timeout to allow checking shutdown signal
                item = self.q.get(timeout=3.0)
                self.log.info(f"[{__name__}] Queue item is {item}. Queue size is {self.q.qsize()}")

                # Handle special stop message
                if item == "STOP":
                    self.log.info(f"[{__name__}] Received STOP message, exiting...")
                    break

                input_data = item.get("input", b"")
                key = item.get("key", "")
                records = item.get("records", [])
                meta = item.get("meta", {})

                if not key:
                    self.log.warning(f"[{__name__}] Warning: Empty key, skipping item")
                    continue

                file_path = os.path.join(self.record_seed_dir, key)
                try:
                    with open(file_path, "wb") as f:
                        if isinstance(input_data, bytes):
                            f.write(input_data)
                        else:
                            f.write(str(input_data).encode("utf-8"))
                except Exception as e:
                    self.log.error(f"[{__name__}] Error saving file {file_path}: {e}")
                    continue

                # Create individual metadata file for this item
                metadata_file = os.path.join(self.record_seed_dir, f"{key}.meta")
                self._update_metadata(metadata_file, key, meta, records)

            except Exception as e:
                self.log.error(f"[{__name__}] Error processing item: {e}")
                continue

        self.log.info(f"[{__name__}] Recorder process exiting gracefully")

    def _update_metadata(self, metadata_file: str, key: str, meta: dict, records: list):
        metadata = {
            "key": key,
            "meta": meta,
            "updated_at": time.time(),
            "full_to_replay": meta.get("full_record", False),
            "records": records,
        }

        try:
            with open(metadata_file, "w") as f:
                json.dump(metadata, f, indent=2)
        except Exception as e:
            self.log.error(f"[{__name__}] Error saving metadata to {metadata_file}: {e}")
