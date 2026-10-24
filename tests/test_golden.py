"""Golden test: the hand-authored CloudTrail fixture must produce exactly the committed alerts.

Regenerate after an intentional behaviour change with::

    UPDATE_GOLDEN=1 uv run pytest tests/test_golden.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from trailwatch.cli import main

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "fixtures" / "cloudtrail"
GOLDEN = ROOT / "fixtures" / "expected-alerts.jsonl"


def test_fixture_alerts_match_golden(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "alerts.jsonl"
    assert main(["detect", str(FIXTURE_DIR), "--out", str(out), "--stats"]) == 0
    stats = json.loads(capsys.readouterr().err)
    assert stats["ingest"]["malformed"] == 1
    assert stats["ingest"]["duplicates"] == 1
    assert stats["engine"]["skipped_service_events"] == 1
    produced = out.read_text(encoding="utf-8")
    if os.environ.get("UPDATE_GOLDEN"):
        GOLDEN.write_text(produced, encoding="utf-8")
    assert produced == GOLDEN.read_text(encoding="utf-8")


def test_golden_covers_the_intended_story() -> None:
    alerts = [json.loads(line) for line in GOLDEN.read_text(encoding="utf-8").splitlines()]
    by_rule = {(a["rule_id"], a["principal"].rsplit("/", 1)[-1]): a for a in alerts}
    assert ("console_no_mfa_iam_change", "ops-legacy") in by_rule
    assert ("unusual_access_key_creation", "ops-legacy") in by_rule
    assert ("logging_disabled", "svc-backup-42") in by_rule
    assert by_rule[("logging_disabled", "svc-backup-42")]["severity"] == "critical"
    # The SSO console sign-in (MFAUsed=No by design of federation) must not alert.
    assert not any("AWSReservedSSO" in a["principal"] for a in alerts)
    # Streamed alerts are written when first emitted, so `count` reflects folding up to that
    # moment (here: the risk crossing folded into the rule alert for the same event).
    assert by_rule[("console_no_mfa_iam_change", "ops-legacy")]["count"] == 2
