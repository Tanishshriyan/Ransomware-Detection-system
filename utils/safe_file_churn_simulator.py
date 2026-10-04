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


def cleanup_simulation_artifacts(target_dir: Path, rename_ext: str = ".lockbit") -> dict:
    """Restore/remove artifacts created only by the benign Process Lab demo.

    The simulator never encrypts bytes; it renames temporary ``.txt`` files to
    a ransomware-looking extension. Cleanup is deliberately restricted to the
    dedicated demo directory passed by the backend.
    """
    target_dir = Path(target_dir)
    if not target_dir.exists() or not target_dir.is_dir():
        return {"restored_files": 0, "removed_notes": 0}

    normalized_ext = str(rename_ext or ".lockbit").strip().lower()
    if not normalized_ext.startswith("."):
        normalized_ext = f".{normalized_ext}"

    restored_files = 0
    removed_notes = 0
    for path in sorted(target_dir.iterdir()):
        if not path.is_file():
            continue

        if path.name.upper().startswith("README_TO_DECRYPT_"):
            try:
                path.unlink()
                removed_notes += 1
            except OSError:
                continue
            continue

        if path.suffix.lower() != normalized_ext:
            continue

        restored = path.with_suffix(".txt")
        if restored.exists():
            restored = path.with_name(f"{path.stem}_restored.txt")
        try:
            path.rename(restored)
            restored_files += 1
        except OSError:
            continue

    return {"restored_files": restored_files, "removed_notes": removed_notes}


def run_simulation(
    target_dir: Path,
    duration_seconds: int,
    batch_size: int,
    rename_ext: str,
    create_ransom_note: bool,
    seed_count: int = 0,
) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    end_at = time.time() + duration_seconds

    print(f"[SIM] Starting benign file churn in: {target_dir}")
    print(
        f"[SIM] Duration: {duration_seconds}s | Batch size: {batch_size} "
        f"| Rename ext: {rename_ext}"
    )

    created = []
    # Optional controlled seed set for damage-aware experiments.  These files
    # contain random bytes only and are still renamed/deleted by this benign
    # simulator; no encryption or destructive malware behavior is added.
    for index in range(max(0, int(seed_count))):
        seed_path = target_dir / f"eligible_{index:05d}.txt"
        seed_path.write_bytes(os.urandom(2048))
        created.append(seed_path)
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
    parser.add_argument("--seed-count", type=int, default=0)
    args = parser.parse_args()

    rename_ext = args.rename_ext if args.rename_ext.startswith(".") else f".{args.rename_ext}"

    run_simulation(
        target_dir=Path(args.target_dir),
        duration_seconds=args.duration,
        batch_size=args.batch_size,
        rename_ext=rename_ext,
        create_ransom_note=args.create_ransom_note,
        seed_count=args.seed_count,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
