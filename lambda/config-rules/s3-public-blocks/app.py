"""AWS Config custom rule: every S3 bucket must block public access.

Evaluates S3 buckets delivered via configuration-change notifications. A
bucket is COMPLIANT when all four public-access-block settings are enabled,
either directly on the bucket or — optionally — inherited from the
account-level public access block.

The four settings checked are BlockPublicAcls, IgnorePublicAcls,
BlockPublicPolicy, and RestrictPublicBuckets. All four must be true; a
partial block is reported NON_COMPLIANT with the missing flags named in the
annotation.

Rule parameters (optional, passed as JSON by AWS Config):
    allowAccountLevelBlock  When ``"true"`` (default), a bucket with no
                            bucket-level configuration is still COMPLIANT if
                            the account-level public access block enables all
                            four settings. Set to ``"false"`` to require an
                            explicit bucket-level block on every bucket.

Environment variables:
    LOG_LEVEL  Python logging level name. Default: ``INFO``.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

CONFIG = boto3.client("config")
S3CONTROL = boto3.client("s3control")

#: Flag names as they appear in the Config supplementary configuration
#: (camelCase), mapped to the canonical names used in annotations.
PUBLIC_ACCESS_FLAGS = {
    "blockPublicAcls": "BlockPublicAcls",
    "ignorePublicAcls": "IgnorePublicAcls",
    "blockPublicPolicy": "BlockPublicPolicy",
    "restrictPublicBuckets": "RestrictPublicBuckets",
}

DELETED_STATUSES = frozenset(
    {"ResourceDeleted", "ResourceDeletedNotRecorded", "ResourceNotRecorded"}
)

MAX_ANNOTATION_LENGTH = 256


def _truncate(annotation: str) -> str:
    """Clamp an annotation to the 256-character PutEvaluations limit."""
    if len(annotation) <= MAX_ANNOTATION_LENGTH:
        return annotation
    return annotation[: MAX_ANNOTATION_LENGTH - 3] + "..."


def _allow_account_level_block(raw_parameters: str | None) -> bool:
    """Resolve the allowAccountLevelBlock parameter (default: true)."""
    if not raw_parameters:
        return True
    try:
        parameters = json.loads(raw_parameters)
    except json.JSONDecodeError:
        logger.warning("Ignoring malformed ruleParameters: %r", raw_parameters)
        return True
    return str(parameters.get("allowAccountLevelBlock", "true")).lower() != "false"


def _get_configuration_item(invoking_event: dict[str, Any]) -> dict[str, Any]:
    """Return the full configuration item, fetching oversized items."""
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
        item = dict(history["configurationItems"][0])
        # API responses carry nested JSON as strings; normalise to dicts so
        # the evaluation logic sees one shape regardless of delivery path.
        supplementary = item.get("supplementaryConfiguration") or {}
        item["supplementaryConfiguration"] = {
            key: json.loads(value) if isinstance(value, str) else value
            for key, value in supplementary.items()
        }
        return item

    raise ValueError(f"Unexpected message type: {message_type}")


def _bucket_level_flags(configuration_item: dict[str, Any]) -> dict[str, bool] | None:
    """Extract bucket-level public-access-block flags, if configured."""
    supplementary = configuration_item.get("supplementaryConfiguration") or {}
    block = supplementary.get("PublicAccessBlockConfiguration")
    if block is None:
        return None
    if isinstance(block, str):
        block = json.loads(block)
    return {name: bool(block.get(name, False)) for name in PUBLIC_ACCESS_FLAGS}


def _account_level_flags(account_id: str) -> dict[str, bool] | None:
    """Fetch account-level public-access-block flags, if configured."""
    try:
        response = S3CONTROL.get_public_access_block(AccountId=account_id)
    except ClientError as error:
        if (
            error.response["Error"]["Code"]
            == "NoSuchPublicAccessBlockConfiguration"
        ):
            return None
        raise
    block = response["PublicAccessBlockConfiguration"]
    # s3control returns PascalCase keys; normalise to the camelCase flag map.
    return {
        camel: bool(block.get(pascal, False))
        for camel, pascal in PUBLIC_ACCESS_FLAGS.items()
    }


def _evaluate(
    configuration_item: dict[str, Any],
    account_id: str,
    allow_account_level: bool,
) -> tuple[str, str]:
    """Evaluate one S3 bucket configuration item.

    Returns:
        Tuple of (compliance_type, annotation).
    """
    flags = _bucket_level_flags(configuration_item)
    source = "bucket-level"

    if flags is None and allow_account_level:
        flags = _account_level_flags(account_id)
        source = "account-level"

    if flags is None:
        return (
            "NON_COMPLIANT",
            "No public access block configuration found on the bucket"
            + (" or the account." if allow_account_level else "."),
        )

    missing = sorted(
        PUBLIC_ACCESS_FLAGS[name] for name, enabled in flags.items() if not enabled
    )
    if missing:
        return (
            "NON_COMPLIANT",
            f"The {source} public access block leaves disabled: "
            f"{', '.join(missing)}.",
        )
    return "COMPLIANT", f"All four public access block settings enabled ({source})."


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, str]:
    """Entry point invoked by AWS Config for configuration changes."""
    logger.debug("Received event: %s", json.dumps(event))

    invoking_event = json.loads(event["invokingEvent"])
    allow_account_level = _allow_account_level_block(event.get("ruleParameters"))
    configuration_item = _get_configuration_item(invoking_event)

    resource_type = configuration_item["resourceType"]
    resource_id = configuration_item["resourceId"]

    if event.get("eventLeftScope"):
        compliance, annotation = (
            "NOT_APPLICABLE",
            "Resource moved out of rule scope.",
        )
    elif configuration_item.get("configurationItemStatus") in DELETED_STATUSES:
        compliance, annotation = "NOT_APPLICABLE", "Bucket has been deleted."
    elif resource_type != "AWS::S3::Bucket":
        compliance, annotation = (
            "NOT_APPLICABLE",
            f"{resource_type} is not evaluated by this rule.",
        )
    else:
        compliance, annotation = _evaluate(
            configuration_item, event["accountId"], allow_account_level
        )

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
