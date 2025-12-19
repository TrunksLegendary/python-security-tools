# Python Security Tools

A small collection of Python-based security tooling projects (log analysis, detection helpers, CI-friendly wrappers).

## Tools

### 1 ) auth-failure-watcher

Detects authentication failures and suspicious login activity patterns from log files.

- Folder: `auth-failure-watcher/`
- Run (example):
  
      ```python src/authwatch/authwatch.py --input sample_logs/auth.log --stats```

- CI Wrapper Example
      ```python ci_run_authwatch.py --authwatch src/authwatch/authwatch.py --input sample_logs/auth.log --max-high 0 --authwatch-args "--stats"```

### 2 ) log-grepper-v1

A fast “grep-like” log scanner that finds matches in log files and can optionally write results to JSONL.

- Folder: `log-grepper-v1/`
- Run (example):
  
      ```python loggrep.py sample.log -r "failed password" --ignore-case --jsonl hits.jsonl```
      ```python .\main.py --help```
      