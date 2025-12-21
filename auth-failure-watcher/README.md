# Auth Failure Watcher (authwatch)

A focused log-analysis tool that detects authentication-related events (e.g., failed SSH logins) and prints severity-tagged findings.

This folder also includes a CI-friendly wrapper (`ci_run_authwatch.py`) that can fail a build when findings exceed thresholds.

---

## Useful flags (CI wrapper)

--max-high N : maximum allowed HIGH findings (default 0)
--max-medium N
--max-low N
--fail-on-severity {low,medium,high,critical} : fail if any finding at/above this severity appears
--`ignore-type <event_type>` : ignore specific event types (repeatable)
--`ignore-severity <severity>` : ignore specific severities (repeatable)
--timeout `<seconds>` : per-run timeout
--authwatch-args `"<args>`" : pass-through args for authwatch.py (default is --stats)

## Quickstart

From the **repo root**:

### Run authwatch directly (human-readable output)

`python auth-failure-watcher/src/authwatch/authwatch.py  --input auth-failure-watcher/sample_logs/auth.log --stats`
