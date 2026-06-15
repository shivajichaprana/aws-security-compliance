"""Unit tests for the three custom AWS Config rule evaluators.

The decision functions are pure: they take plain dicts and return
``(compliance_type, annotation)`` tuples, so every branch is exercised without
touching AWS. The one function that calls IAM (``_evaluate_user``) has its
module-level client monkeypatched with a fake.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


# --------------------------------------------------------------------------- #
# require-backup-tag
# --------------------------------------------------------------------------- #
class TestRequireBackupTag:
    def test_compliant_with_backup_tag(self, require_backup_tag):
        item = {"resourceType": "AWS::EC2::Volume", "tags": {"Backup": "daily"}}
        compliance, annotation = require_backup_tag._evaluate(item, {})
        assert compliance == "COMPLIANT"
        assert "daily" in annotation

    def test_missing_tag_is_non_compliant(self, require_backup_tag):
        item = {"resourceType": "AWS::RDS::DBInstance", "tags": {}}
        compliance, annotation = require_backup_tag._evaluate(item, {})
        assert compliance == "NON_COMPLIANT"
        assert "missing" in annotation.lower()

    def test_empty_tag_value_is_non_compliant(self, require_backup_tag):
        item = {"resourceType": "AWS::EFS::FileSystem", "tags": {"Backup": "   "}}
        compliance, annotation = require_backup_tag._evaluate(item, {})
        assert compliance == "NON_COMPLIANT"
        assert "empty" in annotation.lower()

    def test_unevaluated_type_is_not_applicable(self, require_backup_tag):
        item = {"resourceType": "AWS::S3::Bucket", "tags": {}}
        compliance, _ = require_backup_tag._evaluate(item, {})
        assert compliance == "NOT_APPLICABLE"

    def test_value_outside_allowed_set_is_non_compliant(self, require_backup_tag):
        item = {"resourceType": "AWS::EC2::Volume", "tags": {"Backup": "monthly"}}
        compliance, _ = require_backup_tag._evaluate(
            item, {"allowedTagValues": "daily,weekly"}
        )
        assert compliance == "NON_COMPLIANT"

    def test_value_inside_allowed_set_is_compliant(self, require_backup_tag):
        item = {"resourceType": "AWS::EC2::Volume", "tags": {"Backup": "weekly"}}
        compliance, _ = require_backup_tag._evaluate(
            item, {"allowedTagValues": "daily,weekly"}
        )
        assert compliance == "COMPLIANT"

    def test_parse_rule_parameters(self, require_backup_tag):
        assert require_backup_tag._parse_rule_parameters(None) == {}
        assert require_backup_tag._parse_rule_parameters('{"tagKey": "Backup"}') == {
            "tagKey": "Backup"
        }
        assert require_backup_tag._parse_rule_parameters("not json") == {}

    def test_truncate_clamps_to_limit(self, require_backup_tag):
        short = "ok"
        assert require_backup_tag._truncate(short) == short
        long = "x" * 300
        clamped = require_backup_tag._truncate(long)
        assert len(clamped) == 256
        assert clamped.endswith("...")


# --------------------------------------------------------------------------- #
# iam-key-rotation
# --------------------------------------------------------------------------- #
class _FakeIam:
    """Minimal IAM stand-in returning a fixed list_access_keys response."""

    def __init__(self, keys):
        self._keys = keys

    def list_access_keys(self, UserName):  # noqa: N803 - boto3 kwarg name
        return {"AccessKeyMetadata": self._keys}


class TestIamKeyRotation:
    def test_max_key_age_defaults_and_overrides(self, iam_key_rotation):
        assert iam_key_rotation._max_key_age_days(None) == 90
        assert iam_key_rotation._max_key_age_days('{"maxAccessKeyAgeDays": 30}') == 30
        assert iam_key_rotation._max_key_age_days('{"maxAccessKeyAgeDays": "45"}') == 45
        # Malformed JSON and sub-1 values fall back to the default.
        assert iam_key_rotation._max_key_age_days("garbage") == 90
        assert iam_key_rotation._max_key_age_days('{"maxAccessKeyAgeDays": 0}') == 90

    def test_old_active_key_is_non_compliant(self, iam_key_rotation, monkeypatch):
        now = datetime.now(timezone.utc)
        keys = [{"Status": "Active", "CreateDate": now - timedelta(days=120)}]
        monkeypatch.setattr(iam_key_rotation, "IAM", _FakeIam(keys))
        compliance, annotation = iam_key_rotation._evaluate_user(
            {"UserName": "alice", "UserId": "AIDAALICE"}, 90, now
        )
        assert compliance == "NON_COMPLIANT"
        assert "120" in annotation

    def test_no_active_keys_is_compliant(self, iam_key_rotation, monkeypatch):
        now = datetime.now(timezone.utc)
        keys = [{"Status": "Inactive", "CreateDate": now - timedelta(days=400)}]
        monkeypatch.setattr(iam_key_rotation, "IAM", _FakeIam(keys))
        compliance, annotation = iam_key_rotation._evaluate_user(
            {"UserName": "bob", "UserId": "AIDABOB"}, 90, now
        )
        assert compliance == "COMPLIANT"
        assert "No active access keys" in annotation

    def test_recent_active_key_is_compliant(self, iam_key_rotation, monkeypatch):
        now = datetime.now(timezone.utc)
        keys = [{"Status": "Active", "CreateDate": now - timedelta(days=10)}]
        monkeypatch.setattr(iam_key_rotation, "IAM", _FakeIam(keys))
        compliance, _ = iam_key_rotation._evaluate_user(
            {"UserName": "carol", "UserId": "AIDACAROL"}, 90, now
        )
        assert compliance == "COMPLIANT"


# --------------------------------------------------------------------------- #
# s3-public-blocks
# --------------------------------------------------------------------------- #
def _block(all_enabled=True, **overrides):
    flags = {
        "blockPublicAcls": all_enabled,
        "ignorePublicAcls": all_enabled,
        "blockPublicPolicy": all_enabled,
        "restrictPublicBuckets": all_enabled,
    }
    flags.update(overrides)
    return flags


class TestS3PublicBlocks:
    def test_allow_account_level_default_and_override(self, s3_public_blocks):
        assert s3_public_blocks._allow_account_level_block(None) is True
        assert (
            s3_public_blocks._allow_account_level_block(
                '{"allowAccountLevelBlock": "false"}'
            )
            is False
        )
        assert (
            s3_public_blocks._allow_account_level_block(
                '{"allowAccountLevelBlock": "true"}'
            )
            is True
        )
        assert s3_public_blocks._allow_account_level_block("garbage") is True

    def test_bucket_level_flags_parsed_from_dict_and_string(self, s3_public_blocks):
        item_dict = {
            "supplementaryConfiguration": {"PublicAccessBlockConfiguration": _block()}
        }
        flags = s3_public_blocks._bucket_level_flags(item_dict)
        assert flags == {
            "blockPublicAcls": True,
            "ignorePublicAcls": True,
            "blockPublicPolicy": True,
            "restrictPublicBuckets": True,
        }
        # No block configured -> None.
        assert s3_public_blocks._bucket_level_flags({"supplementaryConfiguration": {}}) is None

    def test_fully_blocked_bucket_is_compliant(self, s3_public_blocks):
        item = {
            "supplementaryConfiguration": {"PublicAccessBlockConfiguration": _block()}
        }
        compliance, annotation = s3_public_blocks._evaluate(item, "123456789012", True)
        assert compliance == "COMPLIANT"
        assert "bucket-level" in annotation

    def test_partial_block_lists_missing_flags(self, s3_public_blocks):
        item = {
            "supplementaryConfiguration": {
                "PublicAccessBlockConfiguration": _block(
                    ignorePublicAcls=False, restrictPublicBuckets=False
                )
            }
        }
        compliance, annotation = s3_public_blocks._evaluate(item, "123456789012", True)
        assert compliance == "NON_COMPLIANT"
        assert "IgnorePublicAcls" in annotation
        assert "RestrictPublicBuckets" in annotation

    def test_no_config_without_account_fallback_is_non_compliant(self, s3_public_blocks):
        item = {"supplementaryConfiguration": {}}
        compliance, annotation = s3_public_blocks._evaluate(item, "123456789012", False)
        assert compliance == "NON_COMPLIANT"
        assert "No public access block" in annotation
