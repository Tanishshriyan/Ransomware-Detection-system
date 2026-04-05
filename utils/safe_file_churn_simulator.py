"""
Benign file-churn simulator for ransomware-detection testing.

This script does NOT encrypt or damage data. It only creates, renames,
and deletes files inside a dedicated temp/test folder.
"""

import argparse
import os
import random
import string
import time
from pathlib import Path


def random_name(length: int = 10) -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def run_simulation(
    target_dir: Path,
    duration_seconds: int,
    batch_size: int,
    rename_ext: str,
    create_ransom_note: bool,
) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    end_at = time.time() + duration_seconds

    print(f"[SIM] Starting benign file churn in: {target_dir}")
    print(
        f"[SIM] Duration: {duration_seconds}s | Batch size: {batch_size} "
        f"| Rename ext: {rename_ext}"
    )

    created = []
    while time.time() < end_at:
        # Create files with random bytes
        for _ in range(batch_size):
            p = target_dir / f"{random_name()}.txt"
            p.write_bytes(os.urandom(2048))
            created.append(p)

        # Rename subset to suspicious-looking extension (still benign data)
        for p in created[-max(1, batch_size // 2):]:
            if p.exists():
                p.rename(p.with_suffix(rename_ext))

        # Create a benign "ransom-note-like" file name to trigger pattern checks.
        if create_ransom_note:
            note_name = f"README_TO_DECRYPT_{random_name(5)}.txt"
            note_path = target_dir / note_name
            note_path.write_text(
                "Simulation only. No encryption. No data loss.",
                encoding="utf-8",
            )

        # Delete small subset to emulate churn
        for p in created[-max(1, batch_size // 4):]:
            if p.exists():
                p.unlink(missing_ok=True)

        time.sleep(0.2)

    print("[SIM] Completed normally")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-dir", type=str, required=True)
    parser.add_argument("--duration", type=int, default=120)
    parser.add_argument("--batch-size", type=int, default=30)
    parser.add_argument("--rename-ext", type=str, default=".lockbit")
    parser.add_argument("--create-ransom-note", action="store_true")
    args = parser.parse_args()

    rename_ext = args.rename_ext if args.rename_ext.startswith(".") else f".{args.rename_ext}"

    run_simulation(
        target_dir=Path(args.target_dir),
        duration_seconds=args.duration,
        batch_size=args.batch_size,
        rename_ext=rename_ext,
        create_ransom_note=args.create_ransom_note,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
