"""Export a daily compliance snapshot to S3 for Athena and QuickSight.

This function is the data-production half of the compliance dashboard. It runs
on a daily EventBridge schedule (see terraform/athena-views.tf), reads the
current compliance posture from AWS Config and AWS Security Hub, and writes two
newline-delimited JSON (NDJSON) objects into the compliance-exports bucket,
partitioned by capture date:

    config-rule-compliance/dt=YYYY-MM-DD/<account-id>.json
    securityhub-finding-summary/dt=YYYY-MM-DD/<account-id>.json

Glue external tables with partition projection sit over those two prefixes, so
the moment an object lands it is queryable in Athena and refreshable into the
QuickSight SPICE datasets — no crawler run required.

Why a pre-aggregated snapshot instead of querying the services live?
    * Security Hub / Config APIs are paginated and rate-limited; a daily roll-up
      keeps QuickSight fast and cheap.
    * A dated partition gives the dashboard a real time series (trend of
      findings by severity, compliance percentage over time) that the live APIs
      cannot provide.

Config source selection:
    When ``CONFIG_AGGREGATOR_NAME`` is set the function reads organization-wide
    compliance from that aggregator (one row per account+rule). Otherwise it
    falls back to this account's local Config compliance.

Configuration (environment variables):
    EXPORT_BUCKET               Destination bucket (required).
    CONFIG_COMPLIANCE_PREFIX    Prefix for Config rows. Default
                                ``config-rule-compliance``.
    SECURITYHUB_SUMMARY_PREFIX  Prefix for Security Hub rows. Default
                                ``securityhub-finding-summary``.
    CONFIG_AGGREGATOR_NAME      Config aggregator name. Empty -> local account.
    SECURITYHUB_FINDINGS_MAX    Safety cap on findings paginated per run.
                                Default ``10000``.
    LOG_LEVEL                   Python logging level. Default ``INFO``.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from collections import defaultdict
from datetime import date, datetime, timezone
from typing import Any, Callable, Iterator

import boto3

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

DEFAULT_CONFIG_PREFIX = "config-rule-compliance"
DEFAULT_SUMMARY_PREFIX = "securityhub-finding-summary"
DEFAULT_FINDINGS_MAX = 10_000
FINDINGS_PAGE_SIZE = 100


def _client(service: str) -> Any:
    """Return a boto3 client. Indirected so tests can monkeypatch it."""
    return boto3.client(service)


def _utcnow_iso() -> str:
    """Current UTC time as a second-precision ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _snapshot_date() -> str:
    """Partition date (UTC) for this run, formatted ``YYYY-MM-DD``."""
    return datetime.now(timezone.utc).date().isoformat()


def _paginate(operation: Callable[..., dict[str, Any]], result_key: str, **kwargs: Any) -> Iterator[dict[str, Any]]:
    """Yield items across a ``NextToken``-paginated boto3 operation.

    Manual pagination (rather than a registered paginator) keeps the function
    resilient to botocore versions that have not registered a paginator for the
    less common Config aggregate operations, and makes the control flow trivial
    to exercise with stubbed clients in tests.
    """
    next_token: str | None = None
    while True:
        params = dict(kwargs)
        if next_token:
            params["NextToken"] = next_token
        response = operation(**params)
        for item in response.get(result_key, []):
            yield item
        next_token = response.get("NextToken")
        if not next_token:
            break


def _compliance_counts(compliance: dict[str, Any]) -> tuple[str, int]:
    """Extract ``(compliance_type, non_compliant_resource_count)``.

    Config reports the number of non-compliant resources as a (capped)
    contributor count; compliant rules carry no contributor count.
    """
    compliance_type = compliance.get("ComplianceType", "INSUFFICIENT_DATA")
    capped = compliance.get("ComplianceContributorCount", {}).get("CappedCount", 0)
    non_compliant = capped if compliance_type == "NON_COMPLIANT" else 0
    return compliance_type, int(non_compliant)


def collect_config_compliance(
    config_client: Any,
    aggregator_name: str,
    account_id: str,
    region: str,
    captured_at: str,
) -> list[dict[str, Any]]:
    """Return one record per (account, rule) describing its compliance state."""
    records: list[dict[str, Any]] = []

    if aggregator_name:
        logger.info("collecting Config compliance from aggregator %s", aggregator_name)
        items = _paginate(
            config_client.describe_aggregate_compliance_by_config_rules,
            "AggregateComplianceByConfigRules",
            ConfigurationAggregatorName=aggregator_name,
        )
        for item in items:
            compliance_type, non_compliant = _compliance_counts(item.get("Compliance", {}))
            records.append(
                {
                    "account_id": item.get("AccountId", account_id),
                    "aws_region": item.get("AwsRegion", region),
                    "rule_name": item.get("ConfigRuleName", "unknown"),
                    "compliance_type": compliance_type,
                    "compliant_resource_count": 0,
                    "non_compliant_resource_count": non_compliant,
                    "source": "aggregator",
                    "captured_at": captured_at,
                }
            )
    else:
        logger.info("collecting Config compliance from local account %s", account_id)
        items = _paginate(
            config_client.describe_compliance_by_config_rule,
            "ComplianceByConfigRules",
        )
        for item in items:
            compliance_type, non_compliant = _compliance_counts(item.get("Compliance", {}))
            records.append(
                {
                    "account_id": account_id,
                    "aws_region": region,
                    "rule_name": item.get("ConfigRuleName", "unknown"),
                    "compliance_type": compliance_type,
                    "compliant_resource_count": 0,
                    "non_compliant_resource_count": non_compliant,
                    "source": "account",
                    "captured_at": captured_at,
                }
            )

    logger.info("collected %d Config rule compliance records", len(records))
    return records


def collect_securityhub_summary(
    securityhub_client: Any,
    captured_at: str,
    max_findings: int,
    default_account_id: str,
) -> list[dict[str, Any]]:
    """Return aggregated counts of active Security Hub findings.

    Findings are tallied by (account, severity, product, workflow status,
    compliance status, record state). Pagination stops once ``max_findings``
    findings have been read, bounding both run time and cost.
    """
    tally: dict[tuple[str, ...], int] = defaultdict(int)
    seen = 0
    next_token: str | None = None
    active_filter = {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}

    while seen < max_findings:
        params: dict[str, Any] = {"Filters": active_filter, "MaxResults": FINDINGS_PAGE_SIZE}
        if next_token:
            params["NextToken"] = next_token
        response = securityhub_client.get_findings(**params)

        for finding in response.get("Findings", []):
            key = (
                finding.get("AwsAccountId", default_account_id),
                (finding.get("Severity") or {}).get("Label", "UNKNOWN"),
                finding.get("ProductName", "unknown"),
                (finding.get("Workflow") or {}).get("Status", "UNKNOWN"),
                (finding.get("Compliance") or {}).get("Status", "NOT_AVAILABLE"),
                finding.get("RecordState", "UNKNOWN"),
            )
            tally[key] += 1
            seen += 1
            if seen >= max_findings:
                logger.warning("hit findings cap of %d; summary is partial", max_findings)
                break

        next_token = response.get("NextToken")
        if not next_token:
            break

    records = [
        {
            "account_id": account_id,
            "severity_label": severity,
            "product_name": product,
            "workflow_status": workflow,
            "compliance_status": compliance,
            "record_state": record_state,
            "finding_count": count,
            "captured_at": captured_at,
        }
        for (account_id, severity, product, workflow, compliance, record_state), count in tally.items()
    ]

    logger.info("collected %d Security Hub summary rows from %d findings", len(records), seen)
    return records


def render_ndjson(records: list[dict[str, Any]]) -> bytes:
    """Serialise records as UTF-8 newline-delimited JSON."""
    if not records:
        return b""
    lines = "\n".join(json.dumps(record, default=str, sort_keys=True) for record in records)
    return (lines + "\n").encode("utf-8")


def write_export(
    s3_client: Any,
    bucket: str,
    prefix: str,
    snapshot_date: str,
    account_id: str,
    records: list[dict[str, Any]],
) -> str:
    """Write one NDJSON export object and return its S3 key."""
    key = f"{prefix}/dt={snapshot_date}/{account_id}.json"
    s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=render_ndjson(records),
        ContentType="application/x-ndjson",
    )
    logger.info("wrote s3://%s/%s (%d records)", bucket, key, len(records))
    return key


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """EventBridge entry point. Collect, export, and return a run summary."""
    bucket = os.environ["EXPORT_BUCKET"]
    config_prefix = os.environ.get("CONFIG_COMPLIANCE_PREFIX", DEFAULT_CONFIG_PREFIX)
    summary_prefix = os.environ.get("SECURITYHUB_SUMMARY_PREFIX", DEFAULT_SUMMARY_PREFIX)
    aggregator_name = os.environ.get("CONFIG_AGGREGATOR_NAME", "").strip()
    max_findings = int(os.environ.get("SECURITYHUB_FINDINGS_MAX", DEFAULT_FINDINGS_MAX))

    account_id = _client("sts").get_caller_identity()["Account"]
    region = os.environ.get("AWS_REGION") or boto3.session.Session().region_name or "us-east-1"
    captured_at = _utcnow_iso()
    snapshot_date = _snapshot_date()

    config_records = collect_config_compliance(
        _client("config"), aggregator_name, account_id, region, captured_at
    )
    securityhub_records = collect_securityhub_summary(
        _client("securityhub"), captured_at, max_findings, account_id
    )

    s3_client = _client("s3")
    config_key = write_export(
        s3_client, bucket, config_prefix, snapshot_date, account_id, config_records
    )
    summary_key = write_export(
        s3_client, bucket, summary_prefix, snapshot_date, account_id, securityhub_records
    )

    summary = {
        "snapshot_date": snapshot_date,
        "account_id": account_id,
        "config_rule_records": len(config_records),
        "securityhub_summary_rows": len(securityhub_records),
        "config_object": config_key,
        "securityhub_object": summary_key,
    }
    logger.info("compliance export complete: %s", json.dumps(summary))
    return summary


def main() -> None:
    """Local entry point: collect and print record counts without writing S3.

    Useful for eyeballing the export shape against a real account
    (``python app.py --aggregator my-org-aggregator``) before scheduling.
    """
    parser = argparse.ArgumentParser(description="Collect a compliance snapshot locally.")
    parser.add_argument("--aggregator", default="", help="Config aggregator name (blank = local account).")
    parser.add_argument("--max-findings", type=int, default=DEFAULT_FINDINGS_MAX)
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    args = parser.parse_args()

    account_id = _client("sts").get_caller_identity()["Account"]
    captured_at = _utcnow_iso()

    config_records = collect_config_compliance(
        _client("config"), args.aggregator, account_id, args.region, captured_at
    )
    securityhub_records = collect_securityhub_summary(
        _client("securityhub"), captured_at, args.max_findings, account_id
    )
    print(json.dumps({
        "config_rule_records": len(config_records),
        "securityhub_summary_rows": len(securityhub_records),
        "sample_config": config_records[:2],
        "sample_securityhub": securityhub_records[:2],
    }, indent=2, default=str))


if __name__ == "__main__":
    main()
