# Findings router: fan HIGH/CRITICAL Security Hub findings out to operators
# (SNS) and to issue tracking (a Jira-forwarding Lambda).
#
# GuardDuty, Inspector, and Config findings are all normalised into Security
# Hub (see security-hub.tf), so a single EventBridge rule on the
# "Security Hub Findings - Imported" event captures every source with one
# consistent severity label (HIGH/CRITICAL) and workflow filter.
#
# Flow:
#   Security Hub finding (NEW, ACTIVE, HIGH|CRITICAL)
#     -> EventBridge rule
#         -> SNS topic (KMS-encrypted)  -> email / chat subscribers
#         -> Jira forwarder Lambda      -> creates/dedupes a Jira issue
#
# Layout:
#   1. Variables   — severity filter + Jira forwarder configuration
#   2. KMS         — customer-managed key encrypting the SNS topic
#   3. SNS         — notification topic + EventBridge publish policy
#   4. Lambda      — Jira forwarder (packaged from lambda/findings-router/)
#   5. EventBridge — rule + SNS and Lambda targets

# ----------------------------- 1. Variables ---------------------------------

variable "findings_severity_labels" {
  description = "Normalised Security Hub severity labels that trigger routing."
  type        = list(string)
  default     = ["HIGH", "CRITICAL"]

  validation {
    condition = length(var.findings_severity_labels) > 0 && alltrue([
      for label in var.findings_severity_labels :
      contains(["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"], label)
    ])
    error_message = "findings_severity_labels must be a non-empty subset of INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL."
  }
}

variable "enable_jira_forwarder" {
  description = "Deploy the Jira-forwarding Lambda and wire it as a second target on the findings rule."
  type        = bool
  default     = true
}

variable "jira_base_url" {
  description = "Base URL of the Jira instance, e.g. https://example.atlassian.net. Leave empty to run the forwarder in dry-run (log-only) mode."
  type        = string
  default     = ""

  validation {
    condition     = var.jira_base_url == "" || can(regex("^https://", var.jira_base_url))
    error_message = "jira_base_url must be empty or an https:// URL."
  }
}

variable "jira_project_key" {
  description = "Jira project key new issues are created under (e.g. SEC)."
  type        = string
  default     = "SEC"
}

variable "jira_issue_type" {
  description = "Jira issue type created for each routed finding."
  type        = string
  default     = "Bug"
}

variable "jira_secret_arn" {
  description = "ARN of a Secrets Manager secret holding Jira credentials as JSON {\"email\":\"...\",\"api_token\":\"...\"}. Empty disables Jira calls (dry-run)."
  type        = string
  default     = ""

  validation {
    condition     = var.jira_secret_arn == "" || can(regex("^arn:aws[a-z-]*:secretsmanager:", var.jira_secret_arn))
    error_message = "jira_secret_arn must be empty or a Secrets Manager secret ARN."
  }
}

variable "findings_router_log_retention_days" {
  description = "CloudWatch Logs retention for the Jira forwarder Lambda."
  type        = number
  default     = 30

  validation {
    condition = contains(
      [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653],
      var.findings_router_log_retention_days,
    )
    error_message = "findings_router_log_retention_days must be a CloudWatch Logs retention value."
  }
}

# -------------------------------- 2. KMS -------------------------------------

# Customer-managed key so the SNS topic is encrypted with a key whose policy
# we control — EventBridge must be granted data-key access to publish to an
# encrypted topic.
data "aws_iam_policy_document" "findings_key" {
  statement {
    sid       = "AccountKeyAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowEventBridgeToUseKey"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey*",
    ]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "findings" {
  description             = "${var.project} - encrypts the security findings notification topic."
  deletion_window_in_days = 14
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.findings_key.json
}

resource "aws_kms_alias" "findings" {
  name          = "alias/${var.project}-findings"
  target_key_id = aws_kms_key.findings.key_id
}

# -------------------------------- 3. SNS -------------------------------------

resource "aws_sns_topic" "findings" {
  name              = "${var.project}-findings"
  kms_master_key_id = aws_kms_key.findings.id
}

data "aws_iam_policy_document" "findings_topic" {
  # Let EventBridge publish, but only from this account's rule.
  statement {
    sid       = "AllowEventBridgePublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.findings.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.findings.arn]
    }
  }

  # Defence in depth: deny any non-TLS publish/subscribe.
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["sns:Publish", "sns:Subscribe"]
    resources = [aws_sns_topic.findings.arn]

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

resource "aws_sns_topic_policy" "findings" {
  arn    = aws_sns_topic.findings.arn
  policy = data.aws_iam_policy_document.findings_topic.json
}

# ------------------------------- 4. Lambda -----------------------------------

locals {
  jira_forwarder_name = "${var.project}-findings-jira-forwarder"
}

data "archive_file" "findings_router" {
  count = var.enable_jira_forwarder ? 1 : 0

  type        = "zip"
  source_dir  = "${path.module}/../lambda/findings-router"
  output_path = "${path.module}/build/findings-router.zip"
}

data "aws_iam_policy_document" "findings_router_trust" {
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

resource "aws_iam_role" "findings_router" {
  count = var.enable_jira_forwarder ? 1 : 0

  name               = local.jira_forwarder_name
  description        = "Execution role for the Security Hub findings Jira forwarder."
  assume_role_policy = data.aws_iam_policy_document.findings_router_trust.json
}

resource "aws_iam_role_policy_attachment" "findings_router_logs" {
  count = var.enable_jira_forwarder ? 1 : 0

  role       = aws_iam_role.findings_router[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Read access to the Jira credential secret, only when one is configured.
data "aws_iam_policy_document" "findings_router" {
  count = var.enable_jira_forwarder && var.jira_secret_arn != "" ? 1 : 0

  statement {
    sid       = "ReadJiraSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.jira_secret_arn]
  }
}

resource "aws_iam_role_policy" "findings_router" {
  count = var.enable_jira_forwarder && var.jira_secret_arn != "" ? 1 : 0

  name   = "read-jira-secret"
  role   = aws_iam_role.findings_router[0].id
  policy = data.aws_iam_policy_document.findings_router[0].json
}

resource "aws_cloudwatch_log_group" "findings_router" {
  count = var.enable_jira_forwarder ? 1 : 0

  name              = "/aws/lambda/${local.jira_forwarder_name}"
  retention_in_days = var.findings_router_log_retention_days
}

resource "aws_lambda_function" "findings_router" {
  count = var.enable_jira_forwarder ? 1 : 0

  function_name = local.jira_forwarder_name
  description   = "Creates a Jira issue for each HIGH/CRITICAL Security Hub finding."
  role          = aws_iam_role.findings_router[0].arn

  filename         = data.archive_file.findings_router[0].output_path
  source_code_hash = data.archive_file.findings_router[0].output_base64sha256

  runtime       = "python3.12"
  architectures = ["arm64"]
  handler       = "app.lambda_handler"
  timeout       = 30
  memory_size   = 128

  environment {
    variables = {
      JIRA_BASE_URL    = var.jira_base_url
      JIRA_PROJECT_KEY = var.jira_project_key
      JIRA_ISSUE_TYPE  = var.jira_issue_type
      JIRA_SECRET_ARN  = var.jira_secret_arn
      SEVERITY_LABELS  = join(",", var.findings_severity_labels)
      LOG_LEVEL        = "INFO"
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.findings_router_logs,
    aws_cloudwatch_log_group.findings_router,
  ]
}

resource "aws_lambda_permission" "findings_router" {
  count = var.enable_jira_forwarder ? 1 : 0

  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.findings_router[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.findings.arn
}

# ----------------------------- 5. EventBridge --------------------------------

resource "aws_cloudwatch_event_rule" "findings" {
  name        = "${var.project}-high-critical-findings"
  description = "Route NEW, active HIGH/CRITICAL Security Hub findings to SNS and Jira."

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = var.findings_severity_labels
        }
        Workflow = {
          Status = ["NEW"]
        }
        RecordState = ["ACTIVE"]
      }
    }
  })
}

# Target 1 — SNS. An input transformer turns the raw finding into a concise,
# human-readable alert instead of paging out the full JSON envelope.
resource "aws_cloudwatch_event_target" "findings_sns" {
  rule      = aws_cloudwatch_event_rule.findings.name
  target_id = "sns"
  arn       = aws_sns_topic.findings.arn

  input_transformer {
    input_paths = {
      account  = "$.detail.findings[0].AwsAccountId"
      region   = "$.detail.findings[0].Region"
      severity = "$.detail.findings[0].Severity.Label"
      title    = "$.detail.findings[0].Title"
      type     = "$.detail.findings[0].Types[0]"
      resource = "$.detail.findings[0].Resources[0].Id"
    }

    input_template = <<TEMPLATE
"[<severity>] <title>"
"Account : <account> (<region>)"
"Type    : <type>"
"Resource: <resource>"
TEMPLATE
  }

  depends_on = [aws_sns_topic_policy.findings]
}

# Target 2 — Jira forwarder Lambda (optional).
resource "aws_cloudwatch_event_target" "findings_jira" {
  count = var.enable_jira_forwarder ? 1 : 0

  rule      = aws_cloudwatch_event_rule.findings.name
  target_id = "jira-forwarder"
  arn       = aws_lambda_function.findings_router[0].arn
}

# ------------------------------- Outputs -------------------------------------

output "findings_topic_arn" {
  description = "ARN of the SNS topic HIGH/CRITICAL findings are published to."
  value       = aws_sns_topic.findings.arn
}

output "findings_rule_name" {
  description = "Name of the EventBridge rule matching routed findings."
  value       = aws_cloudwatch_event_rule.findings.name
}

output "findings_jira_forwarder_name" {
  description = "Name of the Jira forwarder Lambda (null when disabled)."
  value       = try(aws_lambda_function.findings_router[0].function_name, null)
}
