# Custom Lambda-backed Config rules complementing the CIS managed baseline.
#
# Three rules, each packaged from its own directory under
# lambda/config-rules/<rule-name>/:
#
#   require-backup-tag   (change-triggered)  EBS volumes, RDS instances, and
#                                            EFS file systems must carry a
#                                            backup tag
#   iam-key-rotation     (periodic)          no *active* IAM access key may be
#                                            older than the configured maximum
#   s3-public-blocks     (change-triggered)  every bucket must block public
#                                            access (bucket- or account-level)
#
# Layout:
#   1. Variables   — rule tuning knobs
#   2. Locals      — one map driving packaging, Lambda, and rule resources
#   3. IAM         — shared execution role with least-privilege read access
#   4. Lambda      — packaged functions + log groups + Config invoke grants
#   5. Config      — the custom rules themselves

# ----------------------------- 1. Variables ---------------------------------

variable "backup_tag_key" {
  description = "Tag key the require-backup-tag rule looks for on EBS/RDS/EFS resources."
  type        = string
  default     = "Backup"

  validation {
    condition     = length(var.backup_tag_key) > 0 && length(var.backup_tag_key) <= 128
    error_message = "backup_tag_key must be 1-128 characters (AWS tag key limit)."
  }
}

variable "backup_allowed_tag_values" {
  description = "Acceptable values for the backup tag (empty list = any non-empty value)."
  type        = list(string)
  default     = []
}

variable "max_access_key_age_days" {
  description = "Maximum age in days for an active IAM access key before the iam-key-rotation rule flags its owner."
  type        = number
  default     = 90

  validation {
    condition     = var.max_access_key_age_days >= 1 && var.max_access_key_age_days <= 3650
    error_message = "max_access_key_age_days must be between 1 and 3650."
  }
}

variable "iam_key_rotation_frequency" {
  description = "How often the periodic iam-key-rotation rule re-evaluates the account."
  type        = string
  default     = "TwentyFour_Hours"

  validation {
    condition = contains(
      ["One_Hour", "Three_Hours", "Six_Hours", "Twelve_Hours", "TwentyFour_Hours"],
      var.iam_key_rotation_frequency,
    )
    error_message = "iam_key_rotation_frequency must be a valid Config execution frequency."
  }
}

variable "s3_allow_account_level_block" {
  description = "Whether the s3-public-blocks rule accepts the account-level public access block in place of a bucket-level one."
  type        = bool
  default     = true
}

variable "lambda_log_retention_days" {
  description = "CloudWatch Logs retention for the custom-rule Lambda functions."
  type        = number
  default     = 30

  validation {
    condition = contains(
      [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653],
      var.lambda_log_retention_days,
    )
    error_message = "lambda_log_retention_days must be a CloudWatch Logs retention value."
  }
}

# ------------------------------ 2. Locals ------------------------------------

locals {
  lambda_source_root = "${path.module}/../lambda/config-rules"

  # One entry per rule. `trigger` selects the source_detail shape:
  #   change   — ConfigurationItemChange + Oversized notifications, scoped
  #   periodic — ScheduledNotification at `frequency`, account-wide
  custom_rules = {
    require-backup-tag = {
      description = "Custom - EBS volumes, RDS instances, and EFS file systems must carry the '${var.backup_tag_key}' tag so the backup plan picks them up."
      trigger     = "change"
      scope_types = ["AWS::EC2::Volume", "AWS::RDS::DBInstance", "AWS::EFS::FileSystem"]
      frequency   = null
      timeout     = 30
      input_parameters = {
        tagKey           = var.backup_tag_key
        allowedTagValues = join(",", var.backup_allowed_tag_values)
      }
    }

    iam-key-rotation = {
      description = "Custom - no active IAM access key may be older than ${var.max_access_key_age_days} days."
      trigger     = "periodic"
      scope_types = null
      frequency   = var.iam_key_rotation_frequency
      timeout     = 300 # paginates every IAM user in the account
      input_parameters = {
        maxAccessKeyAgeDays = tostring(var.max_access_key_age_days)
      }
    }

    s3-public-blocks = {
      description = "Custom - every S3 bucket must have all four public access block settings enabled."
      trigger     = "change"
      scope_types = ["AWS::S3::Bucket"]
      frequency   = null
      timeout     = 30
      input_parameters = {
        allowAccountLevelBlock = var.s3_allow_account_level_block ? "true" : "false"
      }
    }
  }
}

# Package each rule directory into a deterministic zip. Output lands in
# terraform/build/, which is gitignored — artifacts are rebuilt on plan.
data "archive_file" "config_rule" {
  for_each = local.custom_rules

  type        = "zip"
  source_dir  = "${local.lambda_source_root}/${each.key}"
  output_path = "${path.module}/build/${each.key}.zip"
}

# ------------------------------- 3. IAM --------------------------------------

# All three evaluators share one execution role: they are the same trust
# boundary (Config-invoked, read-only evaluators reporting back to Config),
# and a single role keeps the rule pack easy to extend. Write access to the
# evaluated services is deliberately absent — remediation runs through SSM
# Automation with its own role, never through the evaluators.
data "aws_iam_policy_document" "config_rule_trust" {
  statement {
    sid     = "LambdaAssume"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "config_rules" {
  name               = "${var.project}-config-rules"
  description        = "Execution role for the custom Config rule evaluators."
  assume_role_policy = data.aws_iam_policy_document.config_rule_trust.json
}

resource "aws_iam_role_policy_attachment" "config_rules_logs" {
  role       = aws_iam_role.config_rules.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "config_rules" {
  statement {
    sid    = "ReportEvaluations"
    effect = "Allow"
    actions = [
      "config:PutEvaluations",
      "config:GetResourceConfigHistory", # oversized configuration items
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ReadIamAccessKeys"
    effect = "Allow"
    actions = [
      "iam:ListUsers",
      "iam:ListAccessKeys",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "ReadAccountPublicAccessBlock"
    effect    = "Allow"
    actions   = ["s3:GetAccountPublicAccessBlock"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "config_rules" {
  name   = "evaluator-read-access"
  role   = aws_iam_role.config_rules.id
  policy = data.aws_iam_policy_document.config_rules.json
}

# ------------------------------ 4. Lambda ------------------------------------

# Pre-created so retention is enforced instead of the Lambda-created default
# of "never expire".
resource "aws_cloudwatch_log_group" "config_rule" {
  for_each = local.custom_rules

  name              = "/aws/lambda/${var.project}-${each.key}"
  retention_in_days = var.lambda_log_retention_days
}

resource "aws_lambda_function" "config_rule" {
  for_each = local.custom_rules

  function_name = "${var.project}-${each.key}"
  description   = each.value.description
  role          = aws_iam_role.config_rules.arn

  filename         = data.archive_file.config_rule[each.key].output_path
  source_code_hash = data.archive_file.config_rule[each.key].output_base64sha256

  runtime       = "python3.12"
  architectures = ["arm64"]
  handler       = "app.lambda_handler"
  timeout       = each.value.timeout
  memory_size   = 128

  environment {
    variables = {
      LOG_LEVEL = "INFO"
    }
  }

  # The execution role must be able to write logs before first invocation,
  # and the log group must exist so the retention policy applies from day one.
  depends_on = [
    aws_iam_role_policy_attachment.config_rules_logs,
    aws_iam_role_policy.config_rules,
    aws_cloudwatch_log_group.config_rule,
  ]
}

# Allow the Config service to invoke each evaluator. source_account pins the
# grant to this account so another account's Config cannot invoke them.
resource "aws_lambda_permission" "config_rule" {
  for_each = local.custom_rules

  statement_id   = "AllowConfigInvocation"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.config_rule[each.key].function_name
  principal      = "config.amazonaws.com"
  source_account = local.account_id
}

# ------------------------------- 5. Config -----------------------------------

resource "aws_config_config_rule" "custom" {
  for_each = local.custom_rules

  name        = each.key
  description = each.value.description

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.config_rule[each.key].arn

    # Change-triggered rules subscribe to both the inline and the oversized
    # change notification — large resources (e.g. buckets with many policies)
    # arrive as the oversized variant and would otherwise never be evaluated.
    dynamic "source_detail" {
      for_each = (
        each.value.trigger == "change"
        ? ["ConfigurationItemChangeNotification", "OversizedConfigurationItemChangeNotification"]
        : []
      )
      content {
        event_source = "aws.config"
        message_type = source_detail.value
      }
    }

    dynamic "source_detail" {
      for_each = each.value.trigger == "periodic" ? [1] : []
      content {
        event_source                = "aws.config"
        message_type                = "ScheduledNotification"
        maximum_execution_frequency = each.value.frequency
      }
    }
  }

  input_parameters = jsonencode(each.value.input_parameters)

  dynamic "scope" {
    for_each = each.value.scope_types == null ? [] : [each.value.scope_types]
    content {
      compliance_resource_types = scope.value
    }
  }

  # Rules need a running recorder and an invocable Lambda.
  depends_on = [
    aws_config_configuration_recorder_status.main,
    aws_lambda_permission.config_rule,
  ]
}
