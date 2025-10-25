#!/usr/bin/env python3
"""
web_fim.py — simple file integrity monitor for web/site files
- Uses SHA-256 to build baseline
- Compares current state to baseline and logs additions/removals/modifications via syslog
- Designed to be run by root (for access to /var/www and config files)
- Author: (you)
"""

from __future__ import annotations
import argparse
import hashlib
import json
import logging
import logging.handlers
import os
import sys
import time
from pathlib import Path
from typing import Dict, Tuple, List, Set

# --- CONFIG: change these paths to match what you want monitored ---
DEFAULT_PATHS = [
    "/var/www/html",
    "/etc/apache2/*.conf",
    "/etc/apache2/sites-*/",
    # Add other paths/patterns here, e.g.
    "/var/www/vhosts/*"
]

# Baseline file location (should be in a secure place, readable only by root)
BASELINE_FILE = "/var/lib/web_fim/baseline.json"
LOCAL_LOG = "/var/log/web_fim.log"

# Hash settings
HASH_ALGO = "sha256"
READ_CHUNK = 8192

# File patterns to skip
SKIP_DIRS = {"/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp"}
SKIP_SUFFIXES = (".swp", "~")  # editors temp files


# --- Helpers ---
def sha256_of_file(path: Path) -> str:
    h = hashlib.new(HASH_ALGO)
    with path.open("rb") as f:
        while True:
            chunk = f.read(READ_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def resolve_paths(patterns: List[str]) -> List[Path]:
    """Expand globs and return a unique list of existing directories/files."""
    resolved_paths: Set[Path] = set()
    for pat in patterns:
        # Handle glob patterns
        if "*" in pat or "?" in pat:
            # Use Path.glob starting from root
            root = Path("/")
            # Use lstrip to make the pattern relative to root for glob
            for match in root.glob(pat.lstrip("/")):
                if match.exists():
                    resolved_paths.add(match.resolve())
        else:
            # Handle non-glob paths
            p = Path(pat)
            if p.exists():
                resolved_paths.add(p.resolve())
    return sorted(list(resolved_paths))


def walk_files(paths: list[Path]) -> Dict[str, Dict]:
    """
    Walk given paths and return dict: {absolute_path: {"hash":..., "size":..., "mtime":...}}
    """
    files = {}
    for p in paths:
        path_str = str(p)
        if path_str in SKIP_DIRS:
            continue
            
        if p.is_file():
            try:
                if p.suffix in SKIP_SUFFIXES:
                    continue
                stat = p.stat()
                files[path_str] = {
                    "hash": sha256_of_file(p),
                    "size": stat.st_size,
                    "mtime": int(stat.st_mtime),
                }
            except (PermissionError, OSError) as e:
                logger.warning("Cannot read file %s: %s", p, e)
        elif p.is_dir():
            for root, dirs, filenames in os.walk(p, followlinks=False):
                # prune skip dirs
                dirs[:] = [d for d in dirs if os.path.join(root, d) not in SKIP_DIRS]
                
                # *** CRITICAL FIX: This block was previously unindented ***
                # It must be INSIDE the os.walk loop
                for fname in filenames:
                    if fname.endswith(SKIP_SUFFIXES):
                        continue
                    fpath = Path(root) / fname
                    
                    try:
                        if not fpath.is_file():
                            continue
                        stat = fpath.stat()
                        files[str(fpath)] = {
                            "hash": sha256_of_file(fpath),
                            "size": stat.st_size,
                            "mtime": int(stat.st_mtime),
                        }
                    except (PermissionError, OSError) as e:
                        logger.warning("Cannot read file %s: %s", fpath, e)
        else:
            logger.debug("Skipping non-file, non-dir path: %s", p)
    return files


# --- Logging & syslog setup ---
logger = logging.getLogger("web_fim")
logger.setLevel(logging.INFO)

def setup_logging():
    # Ensure local log directory exists
    try:
        Path(LOCAL_LOG).parent.mkdir(parents=True, exist_ok=True)
        # File handler
        fh = logging.FileHandler(LOCAL_LOG)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
        logger.addHandler(fh)
    except Exception as e:
        # Fail gracefully if we can't write to the log file
        sys.stderr.write(f"Warning: Could not open local log file {LOCAL_LOG}: {e}\n")

    # Syslog handler (Linux: /dev/log). If unavailable fallback to UDP localhost:514
    try:
        sh = logging.handlers.SysLogHandler(address="/dev/log")
    except Exception:
        try:
            sh = logging.handlers.SysLogHandler(address=("localhost", 514))
        except Exception as e:
            # Fail gracefully if syslog isn't available either
            sys.stderr.write(f"Warning: Could not connect to syslog: {e}\n")
            return
            
    sh.setFormatter(logging.Formatter("%(name)s: %(levelname)s: %(message)s"))
    logger.addHandler(sh)


# --- Baseline persistence ---
def load_baseline(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        logger.error("Failed to load baseline %s: %s", path, e)
        return {}


def atomic_write(path: str, data: dict):
    tmp = f"{path}.tmp"
    Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# --- Comparison and reporting ---
def compare_states(baseline: dict, current: dict) -> Tuple[list, list, list]:
    baseline_keys = set(baseline.keys())
    current_keys = set(current.keys())
    added = sorted(list(current_keys - baseline_keys))
    removed = sorted(list(baseline_keys - current_keys))
    modified = []
    for k in sorted(baseline_keys & current_keys):
        b = baseline[k]
        c = current[k]
        # If hash changed, it's modified.
        if b.get("hash") != c.get("hash"):
            modified.append((k, b.get("hash"), c.get("hash")))
    return added, removed, modified


def report(added, removed, modified):
    # Report via syslog and local log
    if not (added or removed or modified):
        logger.info("Integrity check: no changes detected.")
        return

    if added:
        for p in added:
            msg = f"FILE ADDED: {p}"
            logger.warning(msg)
    if removed:
        for p in removed:
            msg = f"FILE REMOVED: {p}"
            logger.warning(msg)
    if modified:
        # *** CRITICAL FIX: This block was previously unindented ***
        # It must be INSIDE the for loop to log all modified files
        for p, oldh, newh in modified:
            msg = f"FILE MODIFIED: {p} old_hash={oldh} new_hash={newh}"
            logger.critical(msg)


# --- CLI / main ---
def main():
    parser = argparse.ArgumentParser(description="Simple file integrity monitor for web files (SHA256).")
    parser.add_argument("--init", action="store_true", help="Create baseline from monitored paths (write baseline file).")
    parser.add_argument("--update", action="store_true", help="Update baseline (overwrite) with current state — use when changes are legitimate.")
    parser.add_argument("--check", action="store_true", help="Perform one integrity check against baseline (default if no flags).")
    parser.add_argument("--loop", type=int, metavar="SECS", help="Run in loop and check every SECS seconds (alternative to cron).")
    parser.add.argument("--baseline", default=BASELINE_FILE, help="Baseline file path.")
    parser.add.argument("--paths", nargs="*", help="Additional paths or globs to monitor.")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    setup_logging()

    # Combine default and provided paths
    all_patterns = list(DEFAULT_PATHS)
    if args.paths:
        all_patterns.extend(args.paths)
        
    paths = resolve_paths(all_patterns)
    logger.info("Monitoring paths: %s", ", ".join(str(p) for p in paths))

    def do_scan_and_compare(is_update_or_init=False):
        current = walk_files(paths)
        
        if is_update_or_init:
            # Create backup of existing baseline
            old = load_baseline(args.baseline)
            if old:
                bak = args.baseline + ".bak"
                atomic_write(bak, old)
                logger.info("Wrote baseline backup to %s", bak)
            
            atomic_write(args.baseline, current)
            logger.info("Baseline written to %s (entries=%d)", args.baseline, len(current))
            return

        baseline = load_baseline(args.baseline)
        if not baseline:
            logger.error("No baseline found at %s. Run with --init to create one.", args.baseline)
            return
            
        added, removed, modified = compare_states(baseline, current)
        report(added, removed, modified)

    # Decide action
    is_baseline_write = args.init or args.update
    if args.init:
        logger.info("Initializing baseline: %s", args.baseline)
    elif args.update:
        logger.info("Updating baseline (overwrite): %s", args.baseline)
        
    if args.loop:
        if is_baseline_write:
            logger.error("--init or --update cannot be used with --loop")
            return
            
        logger.info("Entering loop mode; checking every %d seconds", args.loop)
        try:
            while True:
                do_scan_and_compare()
                time.sleep(args.loop)
        except KeyboardInterrupt:
            logger.info("Loop terminated by user.")
    else:
        # This handles --init, --update, and default --check
        do_scan_and_compare(is_update_or_init=is_baseline_write)


if __name__ == "__main__":
    main()
