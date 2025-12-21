# Python Security Tools

A small collection of Python-based security tooling projects (log analysis, detection helpers, CI-friendly wrappers).

## Tools

Detects authentication failures and suspicious login activity patterns from log files.

- Folder: `auth-failure-watcher/`

Run (from repo root):
```python auth-failure-watcher/src/authwatch/authwatch.py --input auth-failure-watcher/sample_logs/auth.log --stats```

### Detector Output

```python auth-failure-watcher\src\authwatch\authwatch.py --input auth-failure-watcher\sample_logs\auth.log --stats```

![CI ready demo](https://raw.githubusercontent.com/TrunksLegendary/python-security-tools/main/img/tooldemo.png)

### CI wrapper Pass

```python auth-failure-watcher\ci_run_authwatch.py authwatch auth-failure-watcher\src\authwatch\authwatch.py input auth-failure-watcher\sample_logs\auth_clean.log --max-high 0```

![CI ready demo](https://raw.githubusercontent.com/TrunksLegendary/python-security-tools/main/img/greendemo.png)

### CI wrapper FAIL

```python auth-failure-watcher\ci_run_authwatch.py --authwatch auth-failure-watcher\src\authwatch\authwatch.py --input auth-failure-watcher\sample_logs\auth.log --max-high 0```

![CI ready demo](https://raw.githubusercontent.com/TrunksLegendary/python-security-tools/main/img/reddemo.png)

### CI JSON report + artifacts created

```python auth-failure-watcher\ci_run_authwatch.py --authwatch auth-failure-watcher\src\authwatch\authwatch.py --input auth-failure-watcher\sample_logs\auth_clean.log --max-high 0 --json-out authwatch_report.json --stdout-out authwatch_stdout.txt```

![CI ready demo](https://raw.githubusercontent.com/TrunksLegendary/python-security-tools/main/img/ci_readydemo.png)

```Get-Content .\authwatch_report.json -TotalCount 40```

## 2) log-grepper-v1

A fast “grep-like” log scanner that searches for keywords/regex patterns in log files and can output results as JSONL.```

- Folder: `log-grepper-v1/`

```python log-grepper-v1/loggrep.py log-grepper-v1/sample.log -r "failed password" --ignore-case --jsonl hits.jsonl```

### Classic “grep” search with JSONL output

```python log-grepper-v1\loggrep.py log-grepper-v1\sample.log -r "failed password" --ignore-case --jsonl hits.jsonl``

```Get-Content .\hits.jsonl -TotalCount 5```

![CI ready demo](https://raw.githubusercontent.com/TrunksLegendary/python-security-tools/main/img/lg_grtepwithjsonl.png)

### “Help” screenshot (quick proof of CLI completeness)

```python log-grepper-v1\loggrep.py log-grepper-v1\sample.log -r "failed password" --ignore-case --jsonl hits.jsonl```

```Get-Content .\hits.jsonl -TotalCount 5```

![CI ready demo](https://raw.githubusercontent.com/TrunksLegendary/python-security-tools/main/img/lg_grephelp.png)
