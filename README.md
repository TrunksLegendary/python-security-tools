# Python Security Tools

A small collection of Python-based security tooling projects (log analysis, detection helpers, CI-friendly wrappers).

## Tools

## 1) auth-failure-watcher

Detects authentication failures and suspicious login activity patterns from log files.

- Folder: `auth-failure-watcher/`

Run (from repo root):

```bash
python auth-failure-watcher/src/authwatch/authwatch.py --input auth-failure-watcher/sample_logs/auth.log --stats```

## 2) log-grepper-v1

A fast “grep-like” log scanner that searches for keywords/regex patterns in log files and can output results as JSONL.```

- Folder: `log-grepper-v1/`

Run (from repo root):
```bash
python log-grepper-v1/loggrep.py log-grepper-v1/sample.log -r "failed password" --ignore-case --jsonl hits.jsonl```
