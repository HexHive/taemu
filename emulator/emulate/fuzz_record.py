from multiprocessing import Queue
import os
import json
import threading
import time
import signal


def recorder(q: Queue, record_seed_dir):
    print(f"[recorder] Starting recorder for directory {record_seed_dir}")

    # Set up signal handlers for graceful shutdown
    shutdown_requested = threading.Event()

    def signal_handler(signum, frame):
        print(f"[recorder] Received signal {signum}, initiating shutdown...")
        shutdown_requested.set()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if not os.path.exists(record_seed_dir):
        os.makedirs(record_seed_dir)

    while not shutdown_requested.is_set():
        try:
            # Use timeout to allow checking shutdown signal
            item = q.get(timeout=3.0)

            # Handle special stop message
            if item == "STOP":
                print("[recorder] Received STOP message, exiting...")
                break

            input_data = item.get("input", b"")
            key = item.get("key", "")
            records = item.get("records", [])
            meta = item.get("meta", {})

            if not key:
                print("[recorder] Warning: Empty key, skipping item")
                continue

            file_path = os.path.join(record_seed_dir, key)
            try:
                with open(file_path, "wb") as f:
                    if isinstance(input_data, bytes):
                        f.write(input_data)
                    else:
                        f.write(str(input_data).encode("utf-8"))
                print(f"[recorder] Saved input data to {file_path}")
            except Exception as e:
                print(f"[recorder] Error saving file {file_path}: {e}")
                continue

            # Create individual metadata file for this item
            metadata_file = os.path.join(record_seed_dir, f"{key}.meta")
            update_metadata(metadata_file, key, meta, records)

        except Exception as e:
            print(f"[recorder] Error processing item: {e}")
            continue

    print("[recorder] Recorder process exiting gracefully")


def update_metadata(
    metadata_file: str, key: str, meta: dict, records: list
):
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
        print(f"[update_metadata] Error saving metadata to {metadata_file}: {e}")
