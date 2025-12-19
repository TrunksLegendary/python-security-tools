# Python Security Tools

A small collection of Python-based security tooling projects (log analysis, detection helpers, CI-friendly wrappers).

## Tools

### 1 ) auth-failure-watcher

Detects authentication failures and suspicious login activity patterns from log files.

- Folder: `auth-failure-watcher/`
- Run (example):
  
      ```bash python src/authwatch/authwatch.py --input sample_logs/auth.log --stats```

### 2 ) auth-failure-watcher

Detects authentication failures and suspicious login activity patterns from log files.

- Folder: `log-grepper-v1/`
- Run (example):
  
      ```bash python .\main.py --input sample_logs/app.log --keyword ERROR```

      ```bash python .\main.py --help```
  