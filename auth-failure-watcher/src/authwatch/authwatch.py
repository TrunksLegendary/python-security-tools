from __future__ import annotations

import argparse
import json
import re
import sys
import time
import os
import msvcrt
import ctypes
from time import monotonic
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional, TextIO
from collections import Counter

IP_RE = re.compile(r"\bfrom\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")
USER_RE = re.compile(r"\bfor\s+(?:invalid user\s+)?(?P<user>[A-Za-z0-9._-]+)\b")
SEV_RANK = {"low": 1, "med": 2, "high": 3}

@dataclass(frozen=True)
class Rule:
      name: str
      pattern: re.Pattern
      severity: str   # 'low' 'med' 'high'
      
def severity_ok(sev: str, min_sev: str) -> bool:
    return SEV_RANK.get(sev, 0) >= SEV_RANK.get(min_sev, 0)

def extract_user(line: str) -> Optional[str]:
    m = USER_RE.search(line)
    return m.group("user") if m else None

def infer_service(line: str) -> Optional[str]:
    s = line.lower()
    if "sshd" in s:
        return "sshd"
    if "sudo" in s:
        return "sudo"
    return None
     
def utc_now_iso() -> str:
      return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")

def build_rules(ignore_case: bool) -> list[Rule]:
      flags = re.IGNORECASE if ignore_case else 0
      
      return [
            Rule(
                  name="failed_password",
                  pattern=re.compile(r"\bFailed password\b",flags),
                  severity="high",
            ),
            Rule(
                  name="accepted_password",
                  pattern=re.compile(r"\bAccepted password\b",flags),
                  severity="low",
            ),
            Rule(
                  name="sudo",
                  pattern=re.compile(r"^\w+\s+sudo:|\bsudo:",flags),
                  severity="med",
            ),
      ]

def iter_hits_from_line(line:str, rules: list[Rule],  path: Path) -> Iterator[dict]:
      for rule in rules:
            if rule.pattern.search(line):
                  src_ip = extract_ip(line)
                  user = extract_user(line)
                  service = infer_service(line)

                  yield {
                  "ts": utc_now_iso(),
                  "rule": rule.name,
                  "severity": rule.severity,
                  "path": str(path),
                  "line": line.rstrip("\n"),
                  "src_ip": src_ip,
                  "user": user,
                  "service": service,
                  }

def scan_file(path: Path, rules: list[Rule]) -> Iterator[dict]:
      with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                  yield from iter_hits_from_line(line, rules,path)
                  
def follow_file(path: Path, rules: list[Rule], sleep_s: float = 0.25):
    # Open in a way that allows other processes to write (Windows share-friendly)
    fd = os.open(str(path), os.O_RDONLY)
    try:
        # Put the file descriptor into binary mode (avoid CRLF translation issues)
        msvcrt.setmode(fd, os.O_BINARY)

        with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)  # SEEK_END
            while True:
                line = f.readline()
                if not line:
                    time.sleep(sleep_s)
                    continue
                yield from iter_hits_from_line(line, rules, path)
    finally:
        # os.fdopen closes fd, so only close if something failed before wrapping
        pass
                        
def print_hit(hit: dict) -> None:
      # human friendly
      print(f'[{hit["severity"]}] {hit["rule"]} :: {hit["line"]}')
      
def write_jsonl(hit: dict, fp: TextIO) -> None:
      fp.write(json.dumps(hit, ensure_ascii=False) + "\n")
      fp.flush()
      
def normalize_ip(ip: str) -> Optional[str]:
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        nums = [int(p) for p in parts]  # removes leading zeros naturally
    except ValueError:
        return None
    if any(n < 0 or n > 255 for n in nums):
        return None
    return ".".join(str(n) for n in nums)

def extract_ip(line: str) -> Optional[str]:
    m = IP_RE.search(line)
    if not m:
        return None
    return normalize_ip(m.group("ip"))


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
      p = argparse.ArgumentParser(description="Watch authlogs for suspicious security events")
      p.add_argument(
            "--input",
            required=True,
            help="Path to log file to scan/watch."
      )
      
      p.add_argument(
            "--follow",
            action="store_true",
            help="keep running and watch for new lines."
      )
            
      p.add_argument(
            "--jsonl",
            help="write hits as JSONL files to this file."
      )
      
      p.add_argument("--ignore-case", 
                     action="store_true", 
                     help="Case-insensitive matching."
      )
      
      p.add_argument("--stats",
            action="store_true",
            help="Print summary counts after run (scan mode only)."
      )

      
      p.add_argument("--min-severity", 
                     default="low", 
                     choices=["low", "med", "high"],
                     help="Only emit hits at or above this severity."
      )
      
      p.add_argument("--dedupe-seconds", 
                     type=int, 
                     default=0,
                     help="If >0, suppress duplicate alerts for the same (rule, ip, user) within this many seconds."
      )
      
      p.add_argument("--fail-on", 
                     choices=["low", "med", "high"],
                     help="Scan mode only: exit 1 if any hit at/above this severity is found."
      )
      
      p.add_argument("--count-only", 
                     action="store_true", 
                     help="Don’t print hits, only print stats summary."
      )

      return p.parse_args(argv)

def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    path = Path(args.input)

    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 2
    if not path.is_file():
        print(f"ERROR: not a file: {path}", file=sys.stderr)
        return 2

    rules = build_rules(ignore_case=args.ignore_case)

    json_fp: Optional[TextIO] = None
    try:
        if args.jsonl:
            json_fp = Path(args.jsonl).open("a", encoding="utf-8")


        source = follow_file(path, rules) if args.follow else scan_file(path, rules)
        emit_output = not args.count_only
        collect_stats = (args.stats or args.count_only) and (not args.follow)
        rule_counts = Counter()
        ip_counts = Counter()

        min_sev = args.min_severity
        dedupe_s = args.dedupe_seconds
        last_seen = {}  # key -> monotonic timestamp

        fail_rank = SEV_RANK.get(args.fail_on, 999) if args.fail_on else None
        worst_rank_seen = 0

        for hit in source:
            # 1) severity filter first
            if not severity_ok(hit["severity"], min_sev):
                continue

            # 2) dedupe (only if enabled)
            if dedupe_s and dedupe_s > 0:
                key = (hit.get("rule"), hit.get("user"))
                now = monotonic()
                prev = last_seen.get(key)
                if prev is not None and (now - prev) < dedupe_s:
                    continue
                last_seen[key] = now

            # 3) now it’s a “real” emitted hit: print + count + jsonl
            if emit_output:
                  print_hit(hit)

            if collect_stats:
                rule_counts[hit["rule"]] += 1
                if hit.get("src_ip"):
                    ip_counts[hit["src_ip"]] += 1

            rank = SEV_RANK.get(hit["severity"], 0)
            if rank > worst_rank_seen:
                worst_rank_seen = rank

            if json_fp:
                write_jsonl(hit, json_fp)

        if collect_stats:
            print("\n--- stats ---")
            for rule, c in rule_counts.most_common():
                print(f"{rule}: {c}")

            print("\nTop IPs:")
            for ip, c in ip_counts.most_common(5):
                print(f"{ip}: {c}")

        if args.fail_on and (not args.follow):
            if worst_rank_seen >= fail_rank:
                return 1

    except KeyboardInterrupt:
        return 0
    finally:
        if json_fp:
            json_fp.close()

    return 0


if __name__ == "__main__":
      raise SystemExit(main())
