#!/usr/bin/env python3
"""
mini_av.py — a tiny educational signature-based file scanner.

What it does:
  1. Walks a directory tree.
  2. Computes the SHA-256 of every file.
  3. Flags files whose hash appears in a known-malware blocklist.
  4. (Optional) Runs YARA rules for byte-pattern matching, if yara-python
     is installed and a rules file is provided.

This is a LEARNING tool. It is not a replacement for a real antivirus:
no real-time monitoring, no kernel hooks, no auto-updating threat feed.

Usage:
    python mini_av.py /path/to/scan
    python mini_av.py /path/to/scan --hashes blocklist.txt
    python mini_av.py /path/to/scan --hashes blocklist.txt --yara rules.yar

The blocklist is a plain text file: one lowercase SHA-256 hash per line.
Lines starting with '#' are treated as comments. You can build one from
free research feeds like abuse.ch's MalwareBazaar.
"""

import argparse
import hashlib
import os
import sys

# yara is optional — the scanner still works on hashes alone without it.
try:
    import yara  # pip install yara-python
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False


def sha256_of_file(path, chunk_size=65536):
    """Stream the file in chunks so large files don't blow up memory."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                h.update(chunk)
    except (PermissionError, OSError) as e:
        # On every OS you'll hit files you can't read (in use, locked,
        # permission denied). Skip them rather than crashing.
        return None, str(e)
    return h.hexdigest(), None


def load_blocklist(path):
    """Read a file of one-hash-per-line into a set for O(1) lookups."""
    blocklist = set()
    if not path:
        return blocklist
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip().lower()
            if line and not line.startswith("#"):
                blocklist.add(line)
    return blocklist


def walk_files(root):
    """Yield every file path under root."""
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            yield os.path.join(dirpath, name)


def main():
    parser = argparse.ArgumentParser(
        description="Tiny educational signature-based file scanner."
    )
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument(
        "--hashes",
        help="Path to a blocklist file (one SHA-256 hash per line)",
    )
    parser.add_argument(
        "--yara",
        help="Path to a YARA rules file (requires yara-python)",
    )
    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"Error: '{args.target}' does not exist.")
        sys.exit(1)

    blocklist = load_blocklist(args.hashes)
    print(f"Loaded {len(blocklist)} known-bad hashes.")

    yara_rules = None
    if args.yara:
        if not HAVE_YARA:
            print("YARA rules supplied but yara-python is not installed.")
            print("Install it with: pip install yara-python")
            sys.exit(1)
        try:
            yara_rules = yara.compile(filepath=args.yara)
            print(f"Compiled YARA rules from {args.yara}.")
        except yara.SyntaxError as e:
            print(f"Error compiling YARA rules: {e}")
            sys.exit(1)

    # Build the list of files to scan.
    if os.path.isfile(args.target):
        files = [args.target]
    else:
        files = list(walk_files(args.target))

    print(f"Scanning {len(files)} file(s)...\n")

    scanned = 0
    skipped = 0
    detections = 0

    for path in files:
        digest, err = sha256_of_file(path)
        if digest is None:
            skipped += 1
            continue
        scanned += 1

        # 1. Hash check.
        if digest in blocklist:
            detections += 1
            print(f"[MALWARE - hash match] {path}")
            print(f"    sha256: {digest}")

        # 2. YARA check.
        if yara_rules is not None:
            try:
                matches = yara_rules.match(path)
                if matches:
                    detections += 1
                    rule_names = ", ".join(m.rule for m in matches)
                    print(f"[SUSPICIOUS - yara] {path}")
                    print(f"    matched rules: {rule_names}")
            except yara.Error:
                # File unreadable by YARA, skip quietly.
                pass

    print("\n--- Scan complete ---")
    print(f"Scanned:    {scanned}")
    print(f"Skipped:    {skipped} (unreadable / locked)")
    print(f"Detections: {detections}")
    if detections == 0:
        print("No known threats found.")


if __name__ == "__main__":
    main()
