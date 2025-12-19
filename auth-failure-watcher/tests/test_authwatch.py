import sys
from pathlib import Path
import tempfile

# Ensure we can import from src/ without installing a package
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_DIR))

from authwatch.authwatch import (  # noqa: E402
    severity_ok,
    extract_ip,
    extract_user,
    infer_service,
    build_rules,
    iter_hits_from_line,
    scan_file,
)


def test_severity_ok_ordering():
    assert severity_ok("high", "low") is True
    assert severity_ok("med", "low") is True
    assert severity_ok("low", "med") is False
    assert severity_ok("low", "high") is False


def test_extract_ip_from_sshd_line():
    line = "Dec 10 10:15:03 server sshd[1234]: Failed password for root from 192.168.1.10 port 54322 ssh2"
    assert extract_ip(line) == "192.168.1.10"


def test_extract_user_valid_and_invalid_user():
    line1 = "Failed password for alice from 10.0.0.5 port 60000 ssh2"
    line2 = "Failed password for invalid user guest from 192.168.1.10 port 54321 ssh2"
    assert extract_user(line1) == "alice"
    assert extract_user(line2) == "guest"


def test_infer_service():
    assert infer_service("... sshd[111]: Failed password ...") == "sshd"
    assert infer_service("sudo: user : COMMAND=/bin/cat /etc/shadow") == "sudo"
    assert infer_service("some other log line") is None


def test_iter_hits_from_line_includes_fields():
    rules = build_rules(ignore_case=False)
    path = Path("fake.log")
    line = "Dec 10 10:15:03 server sshd[1234]: Failed password for invalid user guest from 192.168.1.10 port 54321 ssh2"

    hits = list(iter_hits_from_line(line, rules, path))
    assert len(hits) >= 1

    hit = hits[0]
    # Core keys
    assert "ts" in hit
    assert hit["rule"] in {"failed_password", "accepted_password", "sudo"}
    assert hit["severity"] in {"low", "med", "high"}
    assert hit["path"] == str(path)
    assert "line" in hit

    # Extracted fields
    assert hit["src_ip"] == "192.168.1.10"
    assert hit["user"] == "guest"
    assert hit["service"] == "sshd"


def test_scan_file_finds_expected_hits():
    rules = build_rules(ignore_case=False)

    sample = "\n".join(
        [
            "Dec 10 10:15:03 server sshd[1234]: Failed password for invalid user guest from 192.168.1.10 port 54321 ssh2",
            "Dec 10 10:16:01 server sshd[1300]: Accepted password for alice from 10.0.0.5 port 60000 ssh2",
            "Dec 10 10:17:00 server something else not matching",
        ]
    ) + "\n"

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "auth.log"
        p.write_text(sample, encoding="utf-8")

        hits = list(scan_file(p, rules))
        # should match at least failed + accepted
        rules_seen = {h["rule"] for h in hits}
        assert "failed_password" in rules_seen
        assert "accepted_password" in rules_seen
