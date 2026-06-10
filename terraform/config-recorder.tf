# AWS Config baseline: recorder, delivery channel, and organization-wide
# aggregation.
#
# Layout:
#   1. Delivery bucket  — hardened S3 bucket Config snapshots/history land in
#   2. Recorder         — records all supported + global resource types
#   3. Delivery channel — ships configuration items to the bucket
#   4. Aggregator       — single pane across every account/region in the org

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  # Account id + region in the name guarantees global uniqueness without
  # hardcoding anything environment-specific in code.
  config_bucket_name = "${var.project}-config-${local.account_id}-${var.aws_region}"
}

variable "config_snapshot_frequency" {
  description = "How often Config delivers a full configuration snapshot to S3."
  type        = string
  default     = "TwentyFour_Hours"

  validation {
    condition = contains(
      ["One_Hour", "Three_Hours", "Six_Hours", "Twelve_Hours", "TwentyFour_Hours"],
      var.config_snapshot_frequency,
    )
    error_message = "config_snapshot_frequency must be a valid Config delivery frequency."
  }
}

variable "config_history_retention_days" {
  description = "Days to retain configuration history objects in the delivery bucket before expiry."
  type        = number
  default     = 365

  validation {
    condition     = var.config_history_retention_days >= 90
    error_message = "Retain Config history for at least 90 days to support audits."
  }
}

variable "enable_organization_aggregator" {
  description = "Create an organization-wide Config aggregator. Requires this account to be the Organizations management account or a delegated administrator for Config."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------------------
# 1. Delivery bucket
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "config" {
  bucket = local.config_bucket_name

  # Compliance evidence — never allow `terraform destroy` to take this out.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket = aws_s3_bucket.config.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    id     = "expire-config-history"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = var.config_history_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# Bucket policy per the AWS Config delivery-permissions documentation:
# ACL check + existence check + object delivery, all pinned to this account
# so another account's recorder can never write here. TLS is mandatory.
data "aws_iam_policy_document" "config_bucket" {
  statement {
    sid       = "AWSConfigBucketPermissionsCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config.arn]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "AWSConfigBucketExistenceCheck"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.config.arn]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "AWSConfigBucketDelivery"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config.arn}/AWSLogs/${local.account_id}/Config/*"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.config.arn, "${aws_s3_bucket.config.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id
  policy = data.aws_iam_policy_document.config_bucket.json

  # Public-access-block first, so a policy evaluation never races it.
  depends_on = [aws_s3_bucket_public_access_block.config]
}

# ---------------------------------------------------------------------------
# 2. Recorder (service-linked role)
# ---------------------------------------------------------------------------

resource "aws_iam_service_linked_role" "config" {
  aws_service_name = "config.amazonaws.com"
  description      = "Service-linked role used by the AWS Config recorder."
}

resource "aws_config_configuration_recorder" "main" {
  name     = "${var.project}-recorder"
  role_arn = aws_iam_service_linked_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
}

# ---------------------------------------------------------------------------
# 3. Delivery channel
# ---------------------------------------------------------------------------

resource "aws_config_delivery_channel" "main" {
  name           = "${var.project}-delivery"
  s3_bucket_name = aws_s3_bucket.config.bucket

  snapshot_delivery_properties {
    delivery_frequency = var.config_snapshot_frequency
  }

  # The channel validates bucket write access on create — policy must exist,
  # and a channel cannot exist without a recorder.
  depends_on = [
    aws_config_configuration_recorder.main,
    aws_s3_bucket_policy.config,
  ]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  # Turning the recorder on before its delivery channel exists fails.
  depends_on = [aws_config_delivery_channel.main]
}

# ---------------------------------------------------------------------------
# 4. Organization-wide aggregation
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "aggregator_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "aggregator" {
  count = var.enable_organization_aggregator ? 1 : 0

  name               = "${var.project}-config-aggregator"
  assume_role_policy = data.aws_iam_policy_document.aggregator_assume.json
}

resource "aws_iam_role_policy_attachment" "aggregator" {
  count = var.enable_organization_aggregator ? 1 : 0

  role       = aws_iam_role.aggregator[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSConfigRoleForOrganizations"
}

resource "aws_config_configuration_aggregator" "organization" {
  count = var.enable_organization_aggregator ? 1 : 0

  name = "${var.project}-org-aggregator"

  organization_aggregation_source {
    all_regions = true
    role_arn    = aws_iam_role.aggregator[0].arn
  }

  depends_on = [aws_iam_role_policy_attachment.aggregator]
}
