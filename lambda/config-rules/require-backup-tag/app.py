"""AWS Config custom rule: require a backup tag on storage resources.

Evaluates EBS volumes, RDS instances, and EFS file systems delivered via
configuration-change notifications. A resource is COMPLIANT when it carries
the configured tag key (default ``Backup``) with a non-empty value. When the
``allowedTagValues`` rule parameter is supplied, the tag value must also be
one of the allowed values (case-sensitive, comma-separated).

Rule parameters (all optional, passed as JSON by AWS Config):
    tagKey            Tag key that must be present. Default: ``Backup``.
    allowedTagValues  Comma-separated acceptable values, e.g. ``daily,weekly``.
                      Empty/omitted means any non-empty value is accepted.

Environment variables:
    LOG_LEVEL  Python logging level name. Default: ``INFO``.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

CONFIG = boto3.client("config")

#: Resource types this rule knows how to evaluate. The Terraform scope block
#: restricts delivery to these types already; this guard keeps the rule safe
#: if the scope is ever widened without a code change.
EVALUATED_RESOURCE_TYPES = frozenset(
    {
        "AWS::EC2::Volume",
        "AWS::RDS::DBInstance",
        "AWS::EFS::FileSystem",
    }
)

#: Configuration item states that mean the resource no longer exists, so an
#: evaluation result would be meaningless.
DELETED_STATUSES = frozenset(
    {"ResourceDeleted", "ResourceDeletedNotRecorded", "ResourceNotRecorded"}
)

MAX_ANNOTATION_LENGTH = 256


def _truncate(annotation: str) -> str:
    """Clamp an annotation to the 256-character PutEvaluations limit."""
    if len(annotation) <= MAX_ANNOTATION_LENGTH:
        return annotation
    return annotation[: MAX_ANNOTATION_LENGTH - 3] + "..."


def _parse_rule_parameters(raw: str | None) -> dict[str, Any]:
    """Decode the ruleParameters JSON string, tolerating absence."""
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Ignoring malformed ruleParameters: %r", raw)
        return {}


def _get_configuration_item(invoking_event: dict[str, Any]) -> dict[str, Any]:
    """Return the full configuration item for the invoking event.

    Oversized change notifications only carry a summary; the full item must
    be fetched back out of the Config service. Values returned by the API
    arrive as JSON strings, so they are normalised to match the inline shape.
    """
    message_type = invoking_event["messageType"]
    if message_type == "ConfigurationItemChangeNotification":
        return invoking_event["configurationItem"]

    if message_type == "OversizedConfigurationItemChangeNotification":
        summary = invoking_event["configurationItemSummary"]
        logger.info(
            "Fetching oversized configuration item for %s %s",
            summary["resourceType"],
            summary["resourceId"],
        )
        history = CONFIG.get_resource_config_history(
            resourceType=summary["resourceType"],
            resourceId=summary["resourceId"],
            limit=1,
        )
        item = history["configurationItems"][0]
        # The API uses a slightly different envelope than the notification.
        normalised: dict[str, Any] = dict(item)
        if isinstance(item.get("configuration"), str):
            normalised["configuration"] = json.loads(item["configuration"])
        normalised.setdefault("tags", item.get("tags") or {})
        normalised["configurationItemCaptureTime"] = item[
            "configurationItemCaptureTime"
        ]
        return normalised

    raise ValueError(f"Unexpected message type: {message_type}")


def _evaluate(
    configuration_item: dict[str, Any], parameters: dict[str, Any]
) -> tuple[str, str]:
    """Evaluate one configuration item.

    Returns:
        Tuple of (compliance_type, annotation).
    """
    resource_type = configuration_item["resourceType"]
    if resource_type not in EVALUATED_RESOURCE_TYPES:
        return "NOT_APPLICABLE", f"{resource_type} is not evaluated by this rule."

    tag_key = str(parameters.get("tagKey", "Backup")).strip() or "Backup"
    allowed_raw = str(parameters.get("allowedTagValues", "")).strip()
    allowed_values = [v.strip() for v in allowed_raw.split(",") if v.strip()]

    tags: dict[str, str] = configuration_item.get("tags") or {}
    value = tags.get(tag_key)

    if value is None:
        return "NON_COMPLIANT", f"Required tag '{tag_key}' is missing."
    if not value.strip():
        return "NON_COMPLIANT", f"Tag '{tag_key}' is present but empty."
    if allowed_values and value not in allowed_values:
        return (
            "NON_COMPLIANT",
            f"Tag '{tag_key}' value '{value}' is not one of: "
            f"{', '.join(allowed_values)}.",
        )
    return "COMPLIANT", f"Tag '{tag_key}' is set to '{value}'."


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, str]:
    """Entry point invoked by AWS Config for configuration changes."""
    logger.debug("Received event: %s", json.dumps(event))

    invoking_event = json.loads(event["invokingEvent"])
    parameters = _parse_rule_parameters(event.get("ruleParameters"))
    configuration_item = _get_configuration_item(invoking_event)

    resource_type = configuration_item["resourceType"]
    resource_id = configuration_item["resourceId"]

    if event.get("eventLeftScope"):
        compliance, annotation = (
            "NOT_APPLICABLE",
            "Resource moved out of rule scope.",
        )
    elif configuration_item.get("configurationItemStatus") in DELETED_STATUSES:
        compliance, annotation = "NOT_APPLICABLE", "Resource has been deleted."
    else:
        compliance, annotation = _evaluate(configuration_item, parameters)

    logger.info("%s %s => %s (%s)", resource_type, resource_id, compliance, annotation)

    CONFIG.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType": resource_type,
                "ComplianceResourceId": resource_id,
                "ComplianceType": compliance,
                "Annotation": _truncate(annotation),
                "OrderingTimestamp": configuration_item[
                    "configurationItemCaptureTime"
                ],
            }
        ],
        ResultToken=event["resultToken"],
    )
    return {"compliance": compliance}
