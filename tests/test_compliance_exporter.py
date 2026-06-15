"""Unit tests for the compliance-exporter helper functions."""

from __future__ import annotations

import json


class _FakeS3:
    """Capture the last put_object call for assertions."""

    def __init__(self):
        self.calls = []

    def put_object(self, **kwargs):
        self.calls.append(kwargs)
        return {"ETag": "fake"}


class TestRenderNdjson:
    def test_empty_records_render_to_empty_bytes(self, compliance_exporter):
        assert compliance_exporter.render_ndjson([]) == b""

    def test_records_are_sorted_newline_delimited_json(self, compliance_exporter):
        out = compliance_exporter.render_ndjson([{"b": 1, "a": 2}, {"a": 3}])
        assert out.endswith(b"\n")
        lines = out.decode().splitlines()
        assert len(lines) == 2
        # sort_keys=True -> "a" precedes "b".
        assert lines[0] == '{"a": 2, "b": 1}'
        assert json.loads(lines[1]) == {"a": 3}

    def test_non_serialisable_values_fall_back_to_str(self, compliance_exporter):
        from datetime import datetime

        out = compliance_exporter.render_ndjson([{"ts": datetime(2026, 6, 15)}])
        # default=str keeps the export from blowing up on datetimes.
        assert b"2026-06-15" in out


class TestComplianceCounts:
    def test_non_compliant_returns_capped_count(self, compliance_exporter):
        compliance = {
            "ComplianceType": "NON_COMPLIANT",
            "ComplianceContributorCount": {"CappedCount": 7},
        }
        assert compliance_exporter._compliance_counts(compliance) == ("NON_COMPLIANT", 7)

    def test_compliant_returns_zero(self, compliance_exporter):
        assert compliance_exporter._compliance_counts(
            {"ComplianceType": "COMPLIANT"}
        ) == ("COMPLIANT", 0)

    def test_missing_type_defaults_to_insufficient_data(self, compliance_exporter):
        assert compliance_exporter._compliance_counts({}) == ("INSUFFICIENT_DATA", 0)


class TestWriteExport:
    def test_key_layout_and_body(self, compliance_exporter):
        s3 = _FakeS3()
        records = [{"rule": "cloudtrail-enabled", "compliance": "COMPLIANT"}]
        key = compliance_exporter.write_export(
            s3, "bucket", "config-compliance", "2026-06-15", "123456789012", records
        )
        assert key == "config-compliance/dt=2026-06-15/123456789012.json"
        assert len(s3.calls) == 1
        call = s3.calls[0]
        assert call["Bucket"] == "bucket"
        assert call["Key"] == key
        assert call["ContentType"] == "application/x-ndjson"
        assert call["Body"] == compliance_exporter.render_ndjson(records)
