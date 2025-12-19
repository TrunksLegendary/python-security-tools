#!/usr/bin/env python3
"""
ci_run_authwatch.py

CI wrapper for authwatch.py:
- Runs authwatch.py against one or more log files
- Parses output lines like: [high] failed_password :: ...
- Produces a JSON report
- Exits non-zero (fails CI) if thresholds are exceeded

Typical usage (fail CI if any high findings):
  python ci_run_authwatch.py --authwatch src/authwatch/authwatch.py --input sample_logs/auth.log --max-high 0

Allow a small number of highs:
  python ci_run_authwatch.py --input sample_logs/auth.log --max-high 2

Multiple inputs:
  python ci_run_authwatch.py --input logs/auth.log --input logs/auth2.log --max-high 0
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Finding:
    severity: str
    raw: str
    event_type: Optional[str] = None


def parse_finding_line(line: str) -> Optional[Finding]:
    """
    Expected formats (examples):
      [high] failed_password :: Dec 10 ...
      [low] accepted_password :: Dec 10 ...
    """
    line_stripped = line.strip()
    m = re.match(r"^\[(?P<sev>[A-Za-z]+)\]\s+(?P<rest>.+)$", line_stripped)
    if not m:
        return None

    sev = m.group("sev").lower()
    rest = m.group("rest")

    # Try to extract event type before " :: "
    event_type = None
    parts = rest.split("::", 1)
    if parts:
        # first token chunk e.g. "failed_password "
        event_type = parts[0].strip().split()[0] if parts[0].strip() else None

    return Finding(severity=sev, raw=line_stripped, event_type=event_type)


def should_ignore(f: Finding, ignore_types: List[str], ignore_sev: List[str]) -> bool:
    if f.severity in ignore_sev:
        return True
    if f.event_type and f.event_type in ignore_types:
        return True
    return False


def run_authwatch(
    python_exe: str,
    authwatch_path: Path,
    input_path: Path,
    extra_args: List[str],
    timeout_sec: int,
) -> Tuple[int, str, str, List[str]]:
    """
    Returns: (returncode, stdout, stderr, cmd_list)
    """
    cmd = [python_exe, str(authwatch_path), "--input", str(input_path)]
    cmd.extend(extra_args)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or "", cmd
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout or ""
        stderr = (e.stderr or "") + f"\nERROR: authwatch timed out after {timeout_sec}s"
        return 124, stdout, stderr, cmd


def safe_int(x: str) -> int:
    try:
        return int(x)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Expected integer, got: {x}")


def main() -> int:
    ap = argparse.ArgumentParser(description="CI runner for authwatch.py")

    ap.add_argument(
        "--authwatch",
        default="src/authwatch/authwatch.py",
        help="Path to authwatch.py (default: src/authwatch/authwatch.py)",
    )
    ap.add_argument(
        "--python",
        default=sys.executable,
        help="Python executable to run (default: current interpreter)",
    )
    ap.add_argument(
        "--input",
        action="append",
        required=True,
        help="Log file path. Can be provided multiple times.",
    )

    # Thresholds (defaults: fail on any high)
    ap.add_argument("--max-high", type=safe_int, default=0, help="Max allowed HIGH findings (default: 0)")
    ap.add_argument("--max-medium", type=safe_int, default=10, help="Max allowed MEDIUM findings (default: 10)")
    ap.add_argument("--max-low", type=safe_int, default=10_000, help="Max allowed LOW findings (default: 10000)")

    ap.add_argument(
        "--fail-on-severity",
        choices=["low", "medium", "high", "critical"],
        default="high",
        help="Fail if any finding >= this severity exists, regardless of max-* (default: high)",
    )

    # Filtering
    ap.add_argument(
        "--ignore-type",
        action="append",
        default=[],
        help="Ignore findings with this event type (e.g., failed_password). Can be used multiple times.",
    )
    ap.add_argument(
        "--ignore-severity",
        action="append",
        default=[],
        help="Ignore findings with this severity (e.g., low). Can be used multiple times.",
    )

    # Authwatch args passthrough
    ap.add_argument(
        "--authwatch-args",
        default="--stats",
        help='Extra args passed to authwatch, as a single string (default: "--stats")',
    )

    # Reporting
    ap.add_argument(
        "--json-out",
        default="authwatch_report.json",
        help="Path for JSON report (default: authwatch_report.json)",
    )
    ap.add_argument(
        "--stdout-out",
        default="authwatch_stdout.txt",
        help="Path to save combined stdout (default: authwatch_stdout.txt)",
    )
    ap.add_argument(
        "--timeout",
        type=safe_int,
        default=60,
        help="Timeout seconds per authwatch run (default: 60)",
    )
    ap.add_argument(
        "--max-sample",
        type=safe_int,
        default=50,
        help="Max number of findings to include in JSON sample (default: 50)",
    )

    args = ap.parse_args()

    authwatch_path = Path(args.authwatch).resolve()
    if not authwatch_path.exists():
        print(f"ERROR: authwatch not found: {authwatch_path}", file=sys.stderr)
        return 2

    input_paths = [Path(p).resolve() for p in args.input]
    for p in input_paths:
        if not p.exists():
            print(f"ERROR: input log not found: {p}", file=sys.stderr)
            return 2

    extra_args = shlex.split(args.authwatch_args.strip()) if args.authwatch_args.strip() else []

    all_findings: List[Finding] = []
    combined_stdout_chunks: List[str] = []
    combined_stderr_chunks: List[str] = []
    run_meta: List[Dict[str, str]] = []

    for p in input_paths:
        rc, out, err, cmd_list = run_authwatch(
            python_exe=args.python,
            authwatch_path=authwatch_path,
            input_path=p,
            extra_args=extra_args,
            timeout_sec=args.timeout,
        )

        run_meta.append(
            {
                "input": str(p),
                "returncode": str(rc),
                "cmd": " ".join(shlex.quote(x) for x in cmd_list),
            }
        )

        if out:
            combined_stdout_chunks.append(f"===== STDOUT ({p.name}) =====\n{out}".rstrip() + "\n")
        if err:
            combined_stderr_chunks.append(f"===== STDERR ({p.name}) =====\n{err}".rstrip() + "\n")

        if rc != 0:
            # Still try to parse stdout if any, but note failure
            print(f"ERROR: authwatch returned non-zero for {p}: rc={rc}", file=sys.stderr)

        for line in out.splitlines():
            f = parse_finding_line(line)
            if not f:
                continue
            if should_ignore(f, ignore_types=args.ignore_type, ignore_sev=[s.lower() for s in args.ignore_severity]):
                continue
            all_findings.append(f)

    # Save stdout/stderr artifacts for CI debugging
    stdout_out = Path(args.stdout_out)
    stdout_out.write_text("".join(combined_stdout_chunks + combined_stderr_chunks), encoding="utf-8")

    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for f in all_findings:
        sev = f.severity.lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["unknown"] += 1

    # Determine pass/fail
    fail_threshold_sev = args.fail_on_severity.lower()
    fail_threshold_rank = SEV_ORDER.get(fail_threshold_sev, SEV_ORDER["high"])

    any_at_or_above = False
    for f in all_findings:
        if SEV_ORDER.get(f.severity.lower(), -1) >= fail_threshold_rank:
            any_at_or_above = True
            break

    too_many = (
        counts.get("high", 0) > args.max_high
        or counts.get("medium", 0) > args.max_medium
        or counts.get("low", 0) > args.max_low
    )

    status = "pass"
    exit_code = 0
    if any_at_or_above or too_many:
        status = "fail"
        exit_code = 1

    # Emit summary for CI logs
    print("=== authwatch CI summary ===")
    print(f"status: {status}")
    print(f"inputs: {', '.join(str(p) for p in input_paths)}")
    print(f"authwatch: {authwatch_path}")
    print(f"authwatch_args: {args.authwatch_args}")
    print(f"counts: critical={counts['critical']} high={counts['high']} medium={counts['medium']} low={counts['low']} unknown={counts['unknown']}")
    print(f"thresholds: fail_on>={args.fail_on_severity} max_high={args.max_high} max_medium={args.max_medium} max_low={args.max_low}")
    print(f"artifacts: json={Path(args.json_out).resolve()} stdout={stdout_out.resolve()}")

    # JSON report
    report = {
        "tool": "authwatch",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "status": status,
        "counts": counts,
        "thresholds": {
            "fail_on_severity": args.fail_on_severity,
            "max_high": args.max_high,
            "max_medium": args.max_medium,
            "max_low": args.max_low,
        },
        "filters": {
            "ignore_type": args.ignore_type,
            "ignore_severity": args.ignore_severity,
        },
        "runs": run_meta,
        "findings_sample": [asdict(f) for f in all_findings[: args.max_sample]],
        "total_findings": len(all_findings),
        "stdout_artifact": str(stdout_out),
    }

    Path(args.json_out).write_text(json.dumps(report, indent=2), encoding="utf-8")

    # If failing, print a small sample to console for quick debugging
    if exit_code != 0 and all_findings:
        print("\n=== sample findings (first 10) ===")
        for f in all_findings[:10]:
            print(f.raw)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

