"""Unit tests for the Security Hub -> Jira findings-router helpers."""

from __future__ import annotations

import base64


class TestSeverityLabels:
    def test_default_when_unset(self, findings_router, monkeypatch):
        monkeypatch.delenv("SEVERITY_LABELS", raising=False)
        assert findings_router._severity_labels() == frozenset({"HIGH", "CRITICAL"})

    def test_parsed_and_uppercased(self, findings_router, monkeypatch):
        monkeypatch.setenv("SEVERITY_LABELS", "high, low")
        assert findings_router._severity_labels() == frozenset({"HIGH", "LOW"})


class TestDryRun:
    def test_dry_run_when_config_absent(self, findings_router, monkeypatch):
        monkeypatch.delenv("JIRA_BASE_URL", raising=False)
        monkeypatch.delenv("JIRA_SECRET_ARN", raising=False)
        assert findings_router._dry_run() is True

    def test_not_dry_run_when_fully_configured(self, findings_router, monkeypatch):
        monkeypatch.setenv("JIRA_BASE_URL", "https://example.atlassian.net")
        monkeypatch.setenv("JIRA_SECRET_ARN", "arn:aws:secretsmanager:...:secret:jira")
        assert findings_router._dry_run() is False


class TestFindingLabel:
    def test_label_is_deterministic_and_prefixed(self, findings_router):
        label_a = findings_router._finding_label("arn:finding:1")
        label_b = findings_router._finding_label("arn:finding:1")
        assert label_a == label_b
        assert label_a.startswith("shfinding-")
        assert len(label_a) == len("shfinding-") + 16

    def test_distinct_findings_get_distinct_labels(self, findings_router):
        assert findings_router._finding_label("a") != findings_router._finding_label("b")


class TestAuthHeader:
    def test_basic_auth_round_trips(self, findings_router):
        header = findings_router._auth_header("user@example.com", "token123")
        assert header.startswith("Basic ")
        decoded = base64.b64decode(header.split(" ", 1)[1]).decode()
        assert decoded == "user@example.com:token123"


class TestBuildIssue:
    def _finding(self, **overrides):
        finding = {
            "Severity": {"Label": "HIGH"},
            "Title": "S3 bucket is public",
            "Id": "arn:aws:securityhub:...:finding/abc",
            "AwsAccountId": "123456789012",
            "Region": "us-east-1",
            "Types": ["Software and Configuration Checks"],
            "Resources": [{"Id": "arn:aws:s3:::demo-bucket"}],
            "Description": "The bucket allows public reads.",
        }
        finding.update(overrides)
        return finding

    def test_issue_fields(self, findings_router):
        issue = findings_router._build_issue(
            self._finding(), "SEC", "Bug", "shfinding-deadbeefdeadbeef"
        )
        fields = issue["fields"]
        assert fields["project"]["key"] == "SEC"
        assert fields["issuetype"]["name"] == "Bug"
        assert fields["summary"].startswith("[HIGH] S3 bucket is public")
        assert "security-hub" in fields["labels"]
        assert "high" in fields["labels"]
        assert "shfinding-deadbeefdeadbeef" in fields["labels"]

    def test_summary_is_truncated(self, findings_router):
        issue = findings_router._build_issue(
            self._finding(Title="X" * 400), "SEC", "Bug", "shfinding-0000000000000000"
        )
        assert len(issue["fields"]["summary"]) <= 255
