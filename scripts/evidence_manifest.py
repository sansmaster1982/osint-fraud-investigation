"""Create a local evidence hash manifest without following reparse points."""

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import stat
import sys


def utc(timestamp=None):
    value = datetime.now(timezone.utc) if timestamp is None else datetime.fromtimestamp(timestamp, timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def reparse(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def inside(path, root):
    return path == root or root in path.parents


def signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def create_manifest(directory, output):
    root = Path(directory).absolute()
    if not root.exists() or not root.is_dir():
        raise ValueError("Evidence directory does not exist or is not a directory.")
    if reparse(root.lstat()):
        raise ValueError("Evidence root must not be a symlink or reparse point.")
    root = root.resolve(strict=True)
    target = Path(output).absolute()
    if os.path.lexists(target):
        raise ValueError("Output already exists; overwriting is prohibited.")
    parent = target.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError("Output parent must be an existing directory.")
    target = parent / target.name
    if inside(target, root):
        raise ValueError("Output must be outside the evidence directory.")
    if os.path.lexists(target):
        raise ValueError("Output already exists; overwriting is prohibited.")
    rows = []
    skipped = 0
    pending = [root]
    while pending:
        folder = pending.pop()
        if reparse(folder.lstat()) or not inside(folder.resolve(strict=True), root):
            raise ValueError("Evidence directory changed during traversal.")
        with os.scandir(folder) as entries:
            for entry in entries:
                path = Path(entry.path)
                before = path.lstat()
                if reparse(before):
                    skipped += 1
                    continue
                if not inside(path.resolve(strict=True), root):
                    raise ValueError("Evidence path resolves outside its root.")
                if stat.S_ISDIR(before.st_mode):
                    pending.append(path)
                    continue
                if not stat.S_ISREG(before.st_mode):
                    skipped += 1
                    continue
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    opened = os.fstat(stream.fileno())
                    if signature(opened) != signature(before) or reparse(path.lstat()):
                        raise ValueError("Evidence file changed before hashing: " + str(path))
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                    after_open = os.fstat(stream.fileno())
                after = path.lstat()
                if reparse(after) or signature(before) != signature(after) or signature(before) != signature(after_open):
                    raise ValueError("Evidence file changed during hashing: " + str(path))
                if not inside(path.resolve(strict=True), root):
                    raise ValueError("Evidence file moved outside its root.")
                rows.append({"path": path.relative_to(root).as_posix(), "size_bytes": before.st_size,
                             "mtime_utc": utc(before.st_mtime), "sha256": digest.hexdigest(),
                             "hashed_at_utc": utc()})
    print(f"Skipped symlinks, reparse points, or non-regular entries: {skipped}", file=sys.stderr)
    if not rows:
        raise ValueError("No regular evidence files remain; manifest was not created.")
    rows.sort(key=lambda row: row["path"])
    with target.open("x", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["path", "size_bytes", "mtime_utc", "sha256", "hashed_at_utc"])
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_directory", help="Explicit local directory containing evidence")
    parser.add_argument("--output", required=True, help="New CSV file outside the evidence directory")
    args = parser.parse_args()
    try:
        count = create_manifest(args.evidence_directory, args.output)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")
    print(f"Manifest created: {count} files.")


if __name__ == "__main__":
    main()
