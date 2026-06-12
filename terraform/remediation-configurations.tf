# AWS Config auto-remediation: maps each NON_COMPLIANT custom rule to an SSM
# Automation runbook so drifted resources are fixed within minutes.
#
#   s3-public-blocks    → <project>-enable-s3-public-block
#   iam-key-rotation    → <project>-rotate-iam-key
#   require-backup-tag  → <project>-attach-missing-tags
#
# Flow: Config marks a resource NON_COMPLIANT → Config starts the mapped SSM
# Automation execution → the runbook assumes aws_iam_role.remediation and
# fixes the resource → the next rule evaluation flips it back to COMPLIANT.
#
# Layout mirrors custom-rules.tf:
#   1. Variables  — remediation tuning knobs
#   2. Locals     — runbook registry + default tag map
#   3. SSM        — register the YAML runbooks under ssm-documents/
#   4. IAM        — least-privilege execution role assumed by the runbooks
#   5. Config     — remediation configurations wiring rules to runbooks

# ----------------------------- 1. Variables ---------------------------------

variable "enable_auto_remediation" {
  description = "Start remediations automatically on NON_COMPLIANT evaluations. When false the runbooks stay registered but must be triggered by an operator from the Config console."
  type        = bool
  default     = true
}

variable "remediation_max_attempts" {
  description = "How many times Config retries an automatic remediation before giving up."
  type        = number
  default     = 3

  validation {
    condition     = var.remediation_max_attempts >= 1 && var.remediation_max_attempts <= 25
    error_message = "remediation_max_attempts must be between 1 and 25 (AWS Config limit)."
  }
}

variable "remediation_retry_seconds" {
  description = "Seconds Config waits for an attempt to succeed before retrying."
  type        = number
  default     = 300

  validation {
    condition     = var.remediation_retry_seconds >= 30 && var.remediation_retry_seconds <= 2678000
    error_message = "remediation_retry_seconds must be between 30 and 2678000 (AWS Config limit)."
  }
}

variable "remediation_concurrency_percent" {
  description = "Maximum percentage of non-compliant resources remediated concurrently."
  type        = number
  default     = 25

  validation {
    condition     = var.remediation_concurrency_percent >= 1 && var.remediation_concurrency_percent <= 100
    error_message = "remediation_concurrency_percent must be between 1 and 100."
  }
}

variable "remediation_error_percent" {
  description = "Percentage of failed remediations at which Config stops launching new ones (circuit breaker)."
  type        = number
  default     = 20

  validation {
    condition     = var.remediation_error_percent >= 1 && var.remediation_error_percent <= 100
    error_message = "remediation_error_percent must be between 1 and 100."
  }
}

variable "iam_key_remediation_mode" {
  description = "What rotate-iam-key does with aged access keys: Deactivate (reversible, default) or Delete (permanent)."
  type        = string
  default     = "Deactivate"

  validation {
    condition     = contains(["Deactivate", "Delete"], var.iam_key_remediation_mode)
    error_message = "iam_key_remediation_mode must be Deactivate or Delete."
  }
}

variable "remediation_default_tags" {
  description = "Tags the attach-missing-tags runbook applies to untagged resources. Empty map = derive a single backup tag from backup_tag_key / backup_allowed_tag_values so remediation restores compliance with the require-backup-tag rule."
  type        = map(string)
  default     = {}
}

# ------------------------------ 2. Locals ------------------------------------

locals {
  # Runbook name → YAML source under ssm-documents/.
  remediation_documents = {
    enable-s3-public-block = "enable-s3-public-block.yaml"
    rotate-iam-key         = "rotate-iam-key.yaml"
    attach-missing-tags    = "attach-missing-tags.yaml"
  }

  # Tags attach-missing-tags applies. Defaults to the exact tag the
  # require-backup-tag rule checks, so a remediated resource actually comes
  # back COMPLIANT instead of gaining unrelated tags.
  remediation_default_tags = (
    length(var.remediation_default_tags) > 0
    ? var.remediation_default_tags
    : {
      (var.backup_tag_key) = (
        length(var.backup_allowed_tag_values) > 0
        ? var.backup_allowed_tag_values[0]
        : "true"
      )
    }
  )
}

# ------------------------------- 3. SSM --------------------------------------

resource "aws_ssm_document" "remediation" {
  for_each = local.remediation_documents

  name            = "${var.project}-${each.key}"
  document_type   = "Automation"
  document_format = "YAML"
  content         = file("${path.module}/../ssm-documents/${each.value}")

  tags = {
    Purpose = "config-auto-remediation"
  }
}

# ------------------------------- 4. IAM --------------------------------------

# One execution role for all three runbooks: they form a single trust
# boundary (Config-triggered fixers) and none holds write access beyond the
# specific remediation APIs below. The evaluator role in custom-rules.tf
# stays read-only — evaluation and remediation never share credentials.
data "aws_iam_policy_document" "remediation_trust" {
  statement {
    sid     = "SsmAutomationAssume"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ssm.amazonaws.com"]
    }

    # Confused-deputy protection: only automations from this account may
    # assume the role.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "remediation" {
  name               = "${var.project}-remediation"
  description        = "Assumed by the SSM Automation runbooks that auto-fix non-compliant resources."
  assume_role_policy = data.aws_iam_policy_document.remediation_trust.json
}

data "aws_iam_policy_document" "remediation" {
  statement {
    sid    = "FixS3PublicAccessBlock"
    effect = "Allow"
    actions = [
      "s3:GetBucketPublicAccessBlock",
      "s3:PutBucketPublicAccessBlock",
    ]
    resources = ["arn:${data.aws_partition.current.partition}:s3:::*"]
  }

  # ListUsers/GetUser resolve the UserId reported by Config to a user name;
  # both are account-wide read calls that do not support narrower resources.
  statement {
    sid       = "ResolveIamUsers"
    effect    = "Allow"
    actions   = ["iam:ListUsers", "iam:GetUser"]
    resources = ["*"]
  }

  statement {
    sid    = "RotateIamAccessKeys"
    effect = "Allow"
    actions = [
      "iam:ListAccessKeys",
      "iam:UpdateAccessKey",
      "iam:DeleteAccessKey",
    ]
    resources = ["arn:${data.aws_partition.current.partition}:iam::${local.account_id}:user/*"]
  }

  statement {
    sid    = "ReadExistingTags"
    effect = "Allow"
    actions = [
      "ec2:DescribeTags",
      "elasticfilesystem:ListTagsForResource",
      "rds:DescribeDBInstances",
      "rds:ListTagsForResource",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "TagEbsVolumes"
    effect    = "Allow"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${local.account_id}:volume/*"]
  }

  statement {
    sid    = "TagRdsAndEfs"
    effect = "Allow"
    actions = [
      "rds:AddTagsToResource",
      "elasticfilesystem:TagResource",
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${local.account_id}:db:*",
      "arn:${data.aws_partition.current.partition}:elasticfilesystem:${var.aws_region}:${local.account_id}:file-system/*",
    ]
  }
}

resource "aws_iam_role_policy" "remediation" {
  name   = "remediation-write-access"
  role   = aws_iam_role.remediation.id
  policy = data.aws_iam_policy_document.remediation.json
}

# ------------------------------- 5. Config -----------------------------------

# maximum_automatic_attempts / retry_attempt_seconds are only valid alongside
# automatic = true, hence the conditionals.

resource "aws_config_remediation_configuration" "s3_public_blocks" {
  config_rule_name = aws_config_config_rule.custom["s3-public-blocks"].name
  resource_type    = "AWS::S3::Bucket"
  target_type      = "SSM_DOCUMENT"
  target_id        = aws_ssm_document.remediation["enable-s3-public-block"].name
  target_version   = "$DEFAULT"

  automatic                  = var.enable_auto_remediation
  maximum_automatic_attempts = var.enable_auto_remediation ? var.remediation_max_attempts : null
  retry_attempt_seconds      = var.enable_auto_remediation ? var.remediation_retry_seconds : null

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.remediation.arn
  }

  parameter {
    name           = "BucketName"
    resource_value = "RESOURCE_ID"
  }

  execution_controls {
    ssm_controls {
      concurrent_execution_rate_percentage = var.remediation_concurrency_percent
      error_percentage                     = var.remediation_error_percent
    }
  }
}

resource "aws_config_remediation_configuration" "iam_key_rotation" {
  config_rule_name = aws_config_config_rule.custom["iam-key-rotation"].name
  resource_type    = "AWS::IAM::User"
  target_type      = "SSM_DOCUMENT"
  target_id        = aws_ssm_document.remediation["rotate-iam-key"].name
  target_version   = "$DEFAULT"

  automatic                  = var.enable_auto_remediation
  maximum_automatic_attempts = var.enable_auto_remediation ? var.remediation_max_attempts : null
  retry_attempt_seconds      = var.enable_auto_remediation ? var.remediation_retry_seconds : null

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.remediation.arn
  }

  # Config reports IAM users by UserId (AIDA...); the runbook resolves it.
  parameter {
    name           = "IamUserIdentifier"
    resource_value = "RESOURCE_ID"
  }

  parameter {
    name         = "MaxKeyAgeDays"
    static_value = tostring(var.max_access_key_age_days)
  }

  parameter {
    name         = "Mode"
    static_value = var.iam_key_remediation_mode
  }

  execution_controls {
    ssm_controls {
      concurrent_execution_rate_percentage = var.remediation_concurrency_percent
      error_percentage                     = var.remediation_error_percent
    }
  }
}

# No resource_type here: the rule spans EBS volumes, RDS instances, and EFS
# file systems; the runbook detects the service from the resource id prefix.
resource "aws_config_remediation_configuration" "require_backup_tag" {
  config_rule_name = aws_config_config_rule.custom["require-backup-tag"].name
  target_type      = "SSM_DOCUMENT"
  target_id        = aws_ssm_document.remediation["attach-missing-tags"].name
  target_version   = "$DEFAULT"

  automatic                  = var.enable_auto_remediation
  maximum_automatic_attempts = var.enable_auto_remediation ? var.remediation_max_attempts : null
  retry_attempt_seconds      = var.enable_auto_remediation ? var.remediation_retry_seconds : null

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.remediation.arn
  }

  parameter {
    name           = "ResourceId"
    resource_value = "RESOURCE_ID"
  }

  parameter {
    name         = "DefaultTagsJson"
    static_value = jsonencode(local.remediation_default_tags)
  }

  execution_controls {
    ssm_controls {
      concurrent_execution_rate_percentage = var.remediation_concurrency_percent
      error_percentage                     = var.remediation_error_percent
    }
  }
}
