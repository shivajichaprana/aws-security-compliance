"""AWS Config custom rule: flag IAM access keys older than a maximum age.

Runs on a schedule (periodic rule). Every IAM user in the account is
evaluated: a user is NON_COMPLIANT when any of their *Active* access keys is
older than the configured maximum age. Inactive keys are ignored — they
cannot be used and deleting them is housekeeping, not a security gate.

Users without active access keys are COMPLIANT: console-only and role-based
identities are the desired end state, not a violation.

Rule parameters (optional, passed as JSON by AWS Config):
    maxAccessKeyAgeDays  Maximum allowed age of an active key in days.
                         Default: ``90``.

Environment variables:
    LOG_LEVEL  Python logging level name. Default: ``INFO``.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

import boto3

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

CONFIG = boto3.client("config")
IAM = boto3.client("iam")

DEFAULT_MAX_KEY_AGE_DAYS = 90
#: PutEvaluations accepts at most 100 evaluations per call.
PUT_EVALUATIONS_BATCH_SIZE = 100
MAX_ANNOTATION_LENGTH = 256


def _truncate(annotation: str) -> str:
    """Clamp an annotation to the 256-character PutEvaluations limit."""
    if len(annotation) <= MAX_ANNOTATION_LENGTH:
        return annotation
    return annotation[: MAX_ANNOTATION_LENGTH - 3] + "..."


def _max_key_age_days(raw_parameters: str | None) -> int:
    """Resolve the maximum key age from rule parameters, with validation."""
    if not raw_parameters:
        return DEFAULT_MAX_KEY_AGE_DAYS
    try:
        parameters = json.loads(raw_parameters)
        max_age = int(parameters.get("maxAccessKeyAgeDays", DEFAULT_MAX_KEY_AGE_DAYS))
    except (json.JSONDecodeError, TypeError, ValueError):
        logger.warning(
            "Malformed ruleParameters %r — using default of %d days",
            raw_parameters,
            DEFAULT_MAX_KEY_AGE_DAYS,
        )
        return DEFAULT_MAX_KEY_AGE_DAYS
    if max_age < 1:
        logger.warning(
            "maxAccessKeyAgeDays must be >= 1, got %d — using default", max_age
        )
        return DEFAULT_MAX_KEY_AGE_DAYS
    return max_age


def _iter_users() -> Iterator[dict[str, Any]]:
    """Yield every IAM user in the account, following pagination."""
    paginator = IAM.get_paginator("list_users")
    for page in paginator.paginate():
        yield from page["Users"]


def _evaluate_user(
    user: dict[str, Any], max_age_days: int, now: datetime
) -> tuple[str, str]:
    """Evaluate a single IAM user's active access keys.

    Returns:
        Tuple of (compliance_type, annotation).
    """
    user_name = user["UserName"]
    response = IAM.list_access_keys(UserName=user_name)
    active_key_ages = [
        (now - key["CreateDate"]).days
        for key in response["AccessKeyMetadata"]
        if key["Status"] == "Active"
    ]

    if not active_key_ages:
        return "COMPLIANT", "No active access keys."

    oldest = max(active_key_ages)
    if oldest > max_age_days:
        return (
            "NON_COMPLIANT",
            f"Oldest active access key is {oldest} days old "
            f"(maximum allowed: {max_age_days}).",
        )
    return (
        "COMPLIANT",
        f"All active access keys are within {max_age_days} days "
        f"(oldest: {oldest}).",
    )


def _put_evaluations_batched(
    evaluations: Iterable[dict[str, Any]], result_token: str
) -> int:
    """Submit evaluations to AWS Config in API-sized batches."""
    batch: list[dict[str, Any]] = []
    submitted = 0
    for evaluation in evaluations:
        batch.append(evaluation)
        if len(batch) == PUT_EVALUATIONS_BATCH_SIZE:
            CONFIG.put_evaluations(Evaluations=batch, ResultToken=result_token)
            submitted += len(batch)
            batch = []
    if batch:
        CONFIG.put_evaluations(Evaluations=batch, ResultToken=result_token)
        submitted += len(batch)
    return submitted


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, int]:
    """Entry point invoked by AWS Config on the configured schedule."""
    logger.debug("Received event: %s", json.dumps(event))

    invoking_event = json.loads(event["invokingEvent"])
    message_type = invoking_event["messageType"]
    if message_type != "ScheduledNotification":
        raise ValueError(f"Expected ScheduledNotification, got: {message_type}")

    max_age_days = _max_key_age_days(event.get("ruleParameters"))
    ordering_timestamp = invoking_event["notificationCreationTime"]
    now = datetime.now(timezone.utc)

    evaluations: list[dict[str, Any]] = []
    non_compliant = 0
    for user in _iter_users():
        compliance, annotation = _evaluate_user(user, max_age_days, now)
        if compliance == "NON_COMPLIANT":
            non_compliant += 1
            logger.info("%s => NON_COMPLIANT (%s)", user["UserName"], annotation)
        evaluations.append(
            {
                # Config tracks IAM users by their stable unique id, not name.
                "ComplianceResourceType": "AWS::IAM::User",
                "ComplianceResourceId": user["UserId"],
                "ComplianceType": compliance,
                "Annotation": _truncate(annotation),
                "OrderingTimestamp": ordering_timestamp,
            }
        )

    submitted = _put_evaluations_batched(evaluations, event["resultToken"])
    logger.info(
        "Evaluated %d IAM users (%d non-compliant, max key age %d days)",
        submitted,
        non_compliant,
        max_age_days,
    )
    return {"evaluated": submitted, "nonCompliant": non_compliant}
