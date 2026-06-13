"""Forward HIGH/CRITICAL Security Hub findings to Jira as tracked issues.

Invoked by EventBridge on the ``Security Hub Findings - Imported`` event. The
rule (see terraform/findings-router.tf) pre-filters to NEW, active findings
whose normalised severity label is in ``SEVERITY_LABELS``; this function
re-applies the severity filter defensively, then creates one Jira issue per
finding.

Because GuardDuty, Inspector, and AWS Config findings are all normalised into
Security Hub, this single handler covers every finding source with one schema.

Idempotency:
    Each finding carries a stable ``Id``. The handler tags the issue with a
    ``shfinding-<hash>`` label and, before creating, runs a JQL search for that
    label so retries / duplicate deliveries do not open a second ticket.

Configuration (environment variables):
    JIRA_BASE_URL    Base URL, e.g. ``https://example.atlassian.net``. When
                     empty the handler runs in dry-run mode: it logs the issue
                     it would create and makes no network calls.
    JIRA_PROJECT_KEY Project key new issues are filed under. Default ``SEC``.
    JIRA_ISSUE_TYPE  Issue type name. Default ``Bug``.
    JIRA_SECRET_ARN  Secrets Manager ARN of a JSON secret
                     ``{"email": "...", "api_token": "..."}``. Empty -> dry-run.
    SEVERITY_LABELS  Comma-separated labels to act on. Default ``HIGH,CRITICAL``.
    LOG_LEVEL        Python logging level name. Default ``INFO``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from functools import lru_cache
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

SECRETS = boto3.client("secretsmanager")

DEFAULT_SEVERITIES = frozenset({"HIGH", "CRITICAL"})
HTTP_TIMEOUT_SECONDS = 10


class JiraConfigError(RuntimeError):
    """Raised when Jira is enabled but its configuration is incomplete."""


def _severity_labels() -> frozenset[str]:
    """Return the set of severity labels the handler should act on."""
    raw = os.environ.get("SEVERITY_LABELS", "")
    labels = {item.strip().upper() for item in raw.split(",") if item.strip()}
    return frozenset(labels) if labels else DEFAULT_SEVERITIES


def _dry_run() -> bool:
    """Dry-run when either the base URL or the credential secret is unset."""
    return not os.environ.get("JIRA_BASE_URL") or not os.environ.get("JIRA_SECRET_ARN")


@lru_cache(maxsize=1)
def _credentials() -> tuple[str, str]:
    """Fetch and cache the Jira ``(email, api_token)`` from Secrets Manager."""
    secret_arn = os.environ["JIRA_SECRET_ARN"]
    try:
        response = SECRETS.get_secret_value(SecretId=secret_arn)
    except ClientError as exc:  # pragma: no cover - exercised via mocks
        raise JiraConfigError(f"unable to read Jira secret: {exc}") from exc

    try:
        payload = json.loads(response["SecretString"])
        return payload["email"], payload["api_token"]
    except (KeyError, ValueError) as exc:
        raise JiraConfigError(
            "Jira secret must be JSON with 'email' and 'api_token' keys"
        ) from exc


def _auth_header(email: str, api_token: str) -> str:
    """Build a Basic auth header value from Jira email + API token."""
    token = base64.b64encode(f"{email}:{api_token}".encode()).decode()
    return f"Basic {token}"


def _finding_label(finding_id: str) -> str:
    """Derive a deterministic, Jira-safe dedupe label from a finding id."""
    digest = hashlib.sha256(finding_id.encode()).hexdigest()[:16]
    return f"shfinding-{digest}"


def _request(url: str, *, method: str, auth: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Issue a JSON HTTP request to Jira and return the decoded response."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", auth)
    request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/json")

    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        raw = response.read().decode()
    return json.loads(raw) if raw else {}


def _issue_exists(base_url: str, auth: str, label: str) -> bool:
    """Return True if an issue already carries the dedupe label."""
    jql = urllib.parse.quote(f'labels = "{label}"')
    url = f"{base_url}/rest/api/2/search?jql={jql}&maxResults=1&fields=key"
    try:
        result = _request(url, method="GET", auth=auth)
    except urllib.error.HTTPError as exc:
        # A failed search must not suppress alerting — log and fall through to
        # attempt creation rather than silently dropping the finding.
        logger.warning("dedupe search failed (%s); proceeding to create", exc.code)
        return False
    return bool(result.get("issues"))


def _build_issue(finding: dict[str, Any], project_key: str, issue_type: str, label: str) -> dict[str, Any]:
    """Render a Jira issue payload from a Security Hub finding."""
    severity = finding.get("Severity", {}).get("Label", "UNKNOWN")
    title = finding.get("Title", "Untitled finding")
    account = finding.get("AwsAccountId", "unknown")
    region = finding.get("Region", "unknown")
    finding_id = finding.get("Id", "unknown")
    types = ", ".join(finding.get("Types", []) or ["n/a"])
    resources = ", ".join(r.get("Id", "n/a") for r in finding.get("Resources", []) or [])
    description = finding.get("Description", "")
    remediation = (
        finding.get("Remediation", {}).get("Recommendation", {}).get("Text", "")
    )

    body = (
        f"*Severity:* {severity}\n"
        f"*Account:* {account} ({region})\n"
        f"*Types:* {types}\n"
        f"*Resources:* {resources or 'n/a'}\n\n"
        f"{description}\n\n"
        f"*Remediation:* {remediation or 'See AWS Security Hub.'}\n\n"
        f"_Security Hub finding id: {finding_id}_"
    )

    return {
        "fields": {
            "project": {"key": project_key},
            "issuetype": {"name": issue_type},
            "summary": f"[{severity}] {title}"[:255],
            "description": body,
            "labels": ["security-hub", severity.lower(), label],
        }
    }


def _process_finding(finding: dict[str, Any], base_url: str, auth: str) -> str:
    """Create (or skip, if duplicate) a Jira issue for one finding.

    Returns a short status string used for the handler summary.
    """
    finding_id = finding.get("Id", "unknown")
    label = _finding_label(finding_id)

    if _issue_exists(base_url, auth, label):
        logger.info("finding %s already tracked (label %s); skipping", finding_id, label)
        return "duplicate"

    payload = _build_issue(
        finding,
        os.environ.get("JIRA_PROJECT_KEY", "SEC"),
        os.environ.get("JIRA_ISSUE_TYPE", "Bug"),
        label,
    )
    created = _request(f"{base_url}/rest/api/2/issue", method="POST", auth=auth, body=payload)
    logger.info("created Jira issue %s for finding %s", created.get("key"), finding_id)
    return "created"


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """EventBridge entry point. Returns a per-status count summary."""
    findings: list[dict[str, Any]] = event.get("detail", {}).get("findings", [])
    severities = _severity_labels()
    summary = {"created": 0, "duplicate": 0, "skipped": 0, "dry_run": 0}

    if not findings:
        logger.info("event carried no findings; nothing to do")
        return summary

    dry_run = _dry_run()
    base_url = os.environ.get("JIRA_BASE_URL", "").rstrip("/")
    auth = ""
    if not dry_run:
        email, api_token = _credentials()
        auth = _auth_header(email, api_token)

    for finding in findings:
        label = finding.get("Severity", {}).get("Label", "").upper()
        if label not in severities:
            summary["skipped"] += 1
            continue

        if dry_run:
            logger.info(
                "[dry-run] would create Jira issue for finding %s (%s)",
                finding.get("Id"),
                label,
            )
            summary["dry_run"] += 1
            continue

        try:
            summary[_process_finding(finding, base_url, auth)] += 1
        except (urllib.error.URLError, JiraConfigError) as exc:
            logger.error("failed to forward finding %s: %s", finding.get("Id"), exc)
            summary["skipped"] += 1

    logger.info("findings router summary: %s", json.dumps(summary))
    return summary
