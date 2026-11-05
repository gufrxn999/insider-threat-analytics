from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

EVENT_TYPES = ["login", "file_access", "download", "web_access", "external_email", "usb_copy", "privilege_change"]
WEIGHTS = [14, 54, 10, 13, 5, 2, 2]
RESOURCES = ["project/docs", "engineering/source_code", "finance/payroll", "customer_data/reports", "public/wiki", "operations/tickets"]


def generate_demo(output: Path, seed: int = 7) -> int:
    random.seed(seed)
    users = [
        (f"employee-{i:02d}", random.choice(["Engineering", "Finance", "Sales", "Operations"]))
        for i in range(1, 11)
    ]
    start = datetime(2025, 1, 6, tzinfo=timezone.utc)
    output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["timestamp", "user_id", "event_type", "resource", "bytes_transferred", "device_id", "department"])
        for day_index in range(35):
            for user_id, department in users:
                count_for_day = random.randint(18, 34)
                is_demo_anomaly = user_id == "employee-07" and day_index == 30
                for _ in range(count_for_day):
                    event_type = random.choices(EVENT_TYPES, weights=WEIGHTS, k=1)[0]
                    if is_demo_anomaly and random.random() < 0.42:
                        event_type = random.choice(["usb_copy", "external_email", "download", "file_access"])
                    hour = random.randint(20, 23) if is_demo_anomaly and random.random() < 0.65 else random.randint(8, 18)
                    minute = random.randint(0, 59)
                    second = random.randint(0, 59)
                    resource = random.choice(RESOURCES)
                    if is_demo_anomaly and event_type in {"download", "usb_copy"}:
                        resource = "restricted/customer_data/reports"
                    byte_count = random.choice([0, 0, 0, 1024, 8192, 65536, 250000])
                    if is_demo_anomaly and event_type in {"download", "usb_copy"}:
                        byte_count = random.randint(2_000_000, 12_000_000)
                    device_id = f"device-{random.randint(1, 2)}"
                    if is_demo_anomaly and random.random() < 0.7:
                        device_id = f"device-{random.randint(3, 6)}"
                    timestamp = start + timedelta(days=day_index, hours=hour, minutes=minute, seconds=second)
                    writer.writerow([
                        timestamp.isoformat(), user_id, event_type, resource,
                        byte_count, device_id, department,
                    ])
                    count += 1
                if is_demo_anomaly:
                    for special_type in ["usb_copy", "privilege_change", "external_email"]:
                        timestamp = start + timedelta(days=day_index, hours=22, minutes=random.randint(0, 59))
                        writer.writerow([
                            timestamp.isoformat(), user_id, special_type,
                            "restricted/customer_data/reports", 5_000_000,
                            "device-5", department,
                        ])
                        count += 1
    return count


if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parents[2]
    destination = repo_root / "data" / "demo_events.csv"
    total = generate_demo(destination)
    print(f"Wrote {total:,} synthetic events to {destination}")
