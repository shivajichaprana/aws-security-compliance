# Compliance analytics pipeline: export -> catalog -> query.
#
# The QuickSight dashboard (quicksight.tf) needs a fast, dated, pre-aggregated
# view of compliance posture. Querying AWS Config and Security Hub live on every
# dashboard load would be slow, rate-limited, and history-less. Instead, a
# scheduled Lambda rolls the current posture up once a day and drops two NDJSON
# objects into a partitioned S3 layout; Glue external tables with partition
# projection make those objects queryable in Athena the instant they land, and
# a set of named-query views shape them for analysts and for QuickSight.
#
# Flow:
#   EventBridge (daily)
#     -> compliance-exporter Lambda
#         -> reads AWS Config (org aggregator or local) + Security Hub findings
#         -> writes s3://<exports>/config-rule-compliance/dt=.../<account>.json
#                   s3://<exports>/securityhub-finding-summary/dt=.../<account>.json
#   Athena (Glue catalog, partition projection) -> views -> QuickSight
#
# Layout:
#   1. Variables  — retention, schedule, projection range, findings cap
#   2. Locals     — derived names
#   3. KMS        — customer-managed key for the analytics buckets + results
#   4. S3         — exports bucket + Athena query-results bucket (hardened)
#   5. Glue       — catalog database + two projected external tables
#   6. Athena     — workgroup + view/analytic named queries
#   7. Lambda     — compliance-exporter (package, role, function, schedule)
#   8. Outputs
#
# Shared data sources (aws_caller_identity.current, aws_partition.current in
# config-recorder.tf; aws_region.current in security-hub.tf) and local.account_id
# are reused here, not redeclared.

# ----------------------------- 1. Variables ---------------------------------

variable "compliance_exports_retention_days" {
  description = "Days to retain dated compliance export objects before expiry."
  type        = number
  default     = 365

  validation {
    condition     = var.compliance_exports_retention_days >= 90
    error_message = "Retain compliance exports for at least 90 days to support trend reporting and audits."
  }
}

variable "athena_results_retention_days" {
  description = "Days to retain Athena query-result objects before expiry."
  type        = number
  default     = 30

  validation {
    condition     = var.athena_results_retention_days >= 1
    error_message = "athena_results_retention_days must be at least 1."
  }
}

variable "compliance_export_schedule" {
  description = "EventBridge schedule expression controlling how often the exporter runs."
  type        = string
  default     = "cron(0 4 * * ? *)" # 04:00 UTC daily, after the nightly Config snapshot.

  validation {
    condition     = can(regex("^(cron|rate)\\(.+\\)$", var.compliance_export_schedule))
    error_message = "compliance_export_schedule must be a cron(...) or rate(...) expression."
  }
}

variable "analytics_projection_start_date" {
  description = "Earliest date (yyyy-MM-dd) the partition projection enumerates for the export tables."
  type        = string
  default     = "2026-01-01"

  validation {
    condition     = can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", var.analytics_projection_start_date))
    error_message = "analytics_projection_start_date must be formatted yyyy-MM-dd."
  }
}

variable "securityhub_findings_max" {
  description = "Safety cap on the number of Security Hub findings the exporter paginates per run."
  type        = number
  default     = 10000

  validation {
    condition     = var.securityhub_findings_max >= 1000 && var.securityhub_findings_max <= 200000
    error_message = "securityhub_findings_max must be between 1000 and 200000."
  }
}

variable "compliance_exporter_log_retention_days" {
  description = "CloudWatch Logs retention for the compliance-exporter Lambda."
  type        = number
  default     = 30

  validation {
    condition = contains(
      [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653],
      var.compliance_exporter_log_retention_days,
    )
    error_message = "compliance_exporter_log_retention_days must be a CloudWatch Logs retention value."
  }
}

# ------------------------------ 2. Locals ------------------------------------

locals {
  exports_bucket_name        = "${var.project}-compliance-exports-${local.account_id}-${var.aws_region}"
  athena_results_bucket_name = "${var.project}-athena-results-${local.account_id}-${var.aws_region}"

  # Glue/Athena identifiers must be lowercase with underscores, not hyphens.
  glue_database_name = replace("${var.project}_compliance", "-", "_")

  config_compliance_prefix   = "config-rule-compliance"
  securityhub_summary_prefix = "securityhub-finding-summary"

  compliance_exporter_name = "${var.project}-compliance-exporter"
}

# -------------------------------- 3. KMS -------------------------------------

# One customer-managed key encrypts both analytics buckets and the Athena
# workgroup result set. Root retains administration; QuickSight is granted use
# of the key so SPICE ingestion can read KMS-encrypted Athena results. The
# exporter Lambda is granted key use through its IAM role (section 7) rather
# than the key policy, to avoid a resource dependency cycle.
data "aws_iam_policy_document" "analytics_key" {
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
    sid    = "AllowQuickSightUseOfKey"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:GenerateDataKey*",
    ]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["quicksight.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "analytics" {
  description             = "${var.project} - encrypts compliance exports, Athena results, and SPICE reads."
  deletion_window_in_days = 14
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.analytics_key.json
}

resource "aws_kms_alias" "analytics" {
  name          = "alias/${var.project}-analytics"
  target_key_id = aws_kms_key.analytics.key_id
}

# -------------------------------- 4. S3 --------------------------------------

# 4a. Compliance exports bucket — the dated NDJSON the tables sit over.
resource "aws_s3_bucket" "exports" {
  bucket = local.exports_bucket_name
}

resource "aws_s3_bucket_versioning" "exports" {
  bucket = aws_s3_bucket.exports.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "exports" {
  bucket = aws_s3_bucket.exports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.analytics.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "exports" {
  bucket = aws_s3_bucket.exports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "exports" {
  bucket = aws_s3_bucket.exports.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "exports" {
  bucket = aws_s3_bucket.exports.id

  rule {
    id     = "expire-exports"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = var.compliance_exports_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# 4b. Athena query-results bucket.
resource "aws_s3_bucket" "athena_results" {
  bucket = local.athena_results_bucket_name
}

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.analytics.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    id     = "expire-query-results"
    status = "Enabled"

    filter {}

    expiration {
      days = var.athena_results_retention_days
    }
  }
}

# TLS-only is mandatory on both analytics buckets.
data "aws_iam_policy_document" "exports" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.exports.arn, "${aws_s3_bucket.exports.arn}/*"]

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

resource "aws_s3_bucket_policy" "exports" {
  bucket     = aws_s3_bucket.exports.id
  policy     = data.aws_iam_policy_document.exports.json
  depends_on = [aws_s3_bucket_public_access_block.exports]
}

data "aws_iam_policy_document" "athena_results" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.athena_results.arn, "${aws_s3_bucket.athena_results.arn}/*"]

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

resource "aws_s3_bucket_policy" "athena_results" {
  bucket     = aws_s3_bucket.athena_results.id
  policy     = data.aws_iam_policy_document.athena_results.json
  depends_on = [aws_s3_bucket_public_access_block.athena_results]
}

# ------------------------------- 5. Glue -------------------------------------

resource "aws_glue_catalog_database" "compliance" {
  name        = local.glue_database_name
  description = "Catalog for ${var.project} compliance exports queried by Athena and QuickSight."
}

# 5a. config_rule_compliance — one row per (account, rule) per day.
#
# Partition projection enumerates the dt partition from a config map, so no
# crawler or ALTER TABLE ADD PARTITION is ever required. The $${dt} token below
# is escaped ($$) so Terraform writes the literal ${dt} that Athena expands.
resource "aws_glue_catalog_table" "config_rule_compliance" {
  name          = "config_rule_compliance"
  database_name = aws_glue_catalog_database.compliance.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    EXTERNAL                      = "TRUE"
    classification                = "json"
    "projection.enabled"          = "true"
    "projection.dt.type"          = "date"
    "projection.dt.format"        = "yyyy-MM-dd"
    "projection.dt.range"         = "${var.analytics_projection_start_date},NOW"
    "projection.dt.interval"      = "1"
    "projection.dt.interval.unit" = "DAYS"
    "storage.location.template"   = "s3://${aws_s3_bucket.exports.bucket}/${local.config_compliance_prefix}/dt=$${dt}/"
  }

  partition_keys {
    name = "dt"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.exports.bucket}/${local.config_compliance_prefix}/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "json"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "serialization.format"  = "1"
        "case.insensitive"      = "true"
        "ignore.malformed.json" = "true"
      }
    }

    columns {
      name = "account_id"
      type = "string"
    }
    columns {
      name = "aws_region"
      type = "string"
    }
    columns {
      name = "rule_name"
      type = "string"
    }
    columns {
      name = "compliance_type"
      type = "string"
    }
    columns {
      name = "compliant_resource_count"
      type = "bigint"
    }
    columns {
      name = "non_compliant_resource_count"
      type = "bigint"
    }
    columns {
      name = "source"
      type = "string"
    }
    columns {
      name = "captured_at"
      type = "string"
    }
  }
}

# 5b. securityhub_finding_summary — pre-aggregated active-finding counts per day.
resource "aws_glue_catalog_table" "securityhub_finding_summary" {
  name          = "securityhub_finding_summary"
  database_name = aws_glue_catalog_database.compliance.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    EXTERNAL                      = "TRUE"
    classification                = "json"
    "projection.enabled"          = "true"
    "projection.dt.type"          = "date"
    "projection.dt.format"        = "yyyy-MM-dd"
    "projection.dt.range"         = "${var.analytics_projection_start_date},NOW"
    "projection.dt.interval"      = "1"
    "projection.dt.interval.unit" = "DAYS"
    "storage.location.template"   = "s3://${aws_s3_bucket.exports.bucket}/${local.securityhub_summary_prefix}/dt=$${dt}/"
  }

  partition_keys {
    name = "dt"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.exports.bucket}/${local.securityhub_summary_prefix}/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "json"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "serialization.format"  = "1"
        "case.insensitive"      = "true"
        "ignore.malformed.json" = "true"
      }
    }

    columns {
      name = "account_id"
      type = "string"
    }
    columns {
      name = "severity_label"
      type = "string"
    }
    columns {
      name = "product_name"
      type = "string"
    }
    columns {
      name = "workflow_status"
      type = "string"
    }
    columns {
      name = "compliance_status"
      type = "string"
    }
    columns {
      name = "record_state"
      type = "string"
    }
    columns {
      name = "finding_count"
      type = "bigint"
    }
    columns {
      name = "captured_at"
      type = "string"
    }
  }
}

# ------------------------------ 6. Athena ------------------------------------

resource "aws_athena_workgroup" "compliance" {
  name        = "${var.project}-compliance"
  description = "Workgroup for compliance posture queries over the exported snapshots."
  state       = "ENABLED"

  # Allow `terraform destroy` to remove the workgroup even with query history.
  force_destroy = true

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    # Guardrail: fail any single query that would scan more than 1 GiB. The
    # daily snapshots are tiny, so a runaway scan signals a mistake.
    bytes_scanned_cutoff_per_query = 1073741824

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/query-results/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.analytics.arn
      }
    }
  }
}

# 6a. View DDL — saved so an operator (or a bootstrap step) can materialise the
# views once. QuickSight does not depend on them: its datasets embed equivalent
# SQL directly (quicksight.tf), so the dashboard works even before the views
# are created.
resource "aws_athena_named_query" "view_compliance_scorecard" {
  name        = "create_vw_compliance_scorecard"
  description = "Per-account compliance scorecard: rule counts and compliant percentage by day."
  database    = aws_glue_catalog_database.compliance.name
  workgroup   = aws_athena_workgroup.compliance.name

  query = <<-SQL
    CREATE OR REPLACE VIEW vw_compliance_scorecard AS
    SELECT
      account_id,
      dt AS snapshot_date,
      count(*)                                   AS total_rules,
      count_if(compliance_type = 'COMPLIANT')    AS compliant_rules,
      count_if(compliance_type = 'NON_COMPLIANT') AS non_compliant_rules,
      round(
        100.0 * count_if(compliance_type = 'COMPLIANT') / nullif(count(*), 0),
        2
      )                                          AS compliance_percentage
    FROM ${aws_glue_catalog_database.compliance.name}.config_rule_compliance
    GROUP BY account_id, dt;
  SQL
}

resource "aws_athena_named_query" "view_config_compliance_latest" {
  name        = "create_vw_config_compliance_latest"
  description = "Most recent snapshot of every Config rule's compliance state."
  database    = aws_glue_catalog_database.compliance.name
  workgroup   = aws_athena_workgroup.compliance.name

  query = <<-SQL
    CREATE OR REPLACE VIEW vw_config_compliance_latest AS
    SELECT *
    FROM ${aws_glue_catalog_database.compliance.name}.config_rule_compliance
    WHERE dt = (SELECT max(dt) FROM ${aws_glue_catalog_database.compliance.name}.config_rule_compliance);
  SQL
}

resource "aws_athena_named_query" "view_securityhub_severity_latest" {
  name        = "create_vw_securityhub_severity_latest"
  description = "Most recent active Security Hub finding counts by account and severity."
  database    = aws_glue_catalog_database.compliance.name
  workgroup   = aws_athena_workgroup.compliance.name

  query = <<-SQL
    CREATE OR REPLACE VIEW vw_securityhub_severity_latest AS
    SELECT
      account_id,
      severity_label,
      record_state,
      sum(finding_count) AS findings
    FROM ${aws_glue_catalog_database.compliance.name}.securityhub_finding_summary
    WHERE dt = (SELECT max(dt) FROM ${aws_glue_catalog_database.compliance.name}.securityhub_finding_summary)
    GROUP BY account_id, severity_label, record_state;
  SQL
}

# 6b. Analyst convenience queries.
resource "aws_athena_named_query" "top_noncompliant_rules" {
  name        = "report_top_noncompliant_rules"
  description = "Top 20 Config rules by non-compliant resource count in the latest snapshot."
  database    = aws_glue_catalog_database.compliance.name
  workgroup   = aws_athena_workgroup.compliance.name

  query = <<-SQL
    SELECT
      rule_name,
      sum(non_compliant_resource_count) AS non_compliant_resources,
      count(DISTINCT account_id)        AS affected_accounts
    FROM ${aws_glue_catalog_database.compliance.name}.config_rule_compliance
    WHERE dt = (SELECT max(dt) FROM ${aws_glue_catalog_database.compliance.name}.config_rule_compliance)
      AND compliance_type = 'NON_COMPLIANT'
    GROUP BY rule_name
    ORDER BY non_compliant_resources DESC
    LIMIT 20;
  SQL
}

resource "aws_athena_named_query" "severity_trend_30d" {
  name        = "report_severity_trend_30d"
  description = "Active Security Hub findings by severity over the last 30 snapshots."
  database    = aws_glue_catalog_database.compliance.name
  workgroup   = aws_athena_workgroup.compliance.name

  query = <<-SQL
    SELECT
      dt AS snapshot_date,
      severity_label,
      sum(finding_count) AS findings
    FROM ${aws_glue_catalog_database.compliance.name}.securityhub_finding_summary
    WHERE record_state = 'ACTIVE'
      AND dt >= date_format(current_date - interval '30' day, '%Y-%m-%d')
    GROUP BY dt, severity_label
    ORDER BY snapshot_date, severity_label;
  SQL
}

# ------------------------------ 7. Lambda ------------------------------------

data "archive_file" "compliance_exporter" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/compliance-exporter"
  output_path = "${path.module}/build/compliance-exporter.zip"
}

data "aws_iam_policy_document" "compliance_exporter_trust" {
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

resource "aws_iam_role" "compliance_exporter" {
  name               = local.compliance_exporter_name
  description        = "Execution role for the daily compliance snapshot exporter."
  assume_role_policy = data.aws_iam_policy_document.compliance_exporter_trust.json
}

resource "aws_iam_role_policy_attachment" "compliance_exporter_logs" {
  role       = aws_iam_role.compliance_exporter.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Least-privilege: read-only compliance APIs, write only to the exports bucket,
# and use only the analytics key. Config and Security Hub read actions do not
# support resource-level scoping, so they are pinned to "*" by the service.
data "aws_iam_policy_document" "compliance_exporter" {
  statement {
    sid    = "ReadConfigCompliance"
    effect = "Allow"
    actions = [
      "config:DescribeConfigRules",
      "config:DescribeComplianceByConfigRule",
      "config:GetComplianceSummaryByConfigRule",
      "config:DescribeConfigurationAggregators",
      "config:DescribeAggregateComplianceByConfigRules",
      "config:GetAggregateConfigRuleComplianceSummary",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "ReadSecurityHubFindings"
    effect    = "Allow"
    actions   = ["securityhub:GetFindings"]
    resources = ["*"]
  }

  statement {
    sid       = "WriteExports"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.exports.arn}/*"]
  }

  statement {
    sid    = "UseAnalyticsKey"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
    ]
    resources = [aws_kms_key.analytics.arn]
  }
}

resource "aws_iam_role_policy" "compliance_exporter" {
  name   = "compliance-exporter"
  role   = aws_iam_role.compliance_exporter.id
  policy = data.aws_iam_policy_document.compliance_exporter.json
}

resource "aws_cloudwatch_log_group" "compliance_exporter" {
  name              = "/aws/lambda/${local.compliance_exporter_name}"
  retention_in_days = var.compliance_exporter_log_retention_days
}

resource "aws_lambda_function" "compliance_exporter" {
  function_name = local.compliance_exporter_name
  description   = "Exports a daily AWS Config + Security Hub compliance snapshot to S3 for Athena/QuickSight."
  role          = aws_iam_role.compliance_exporter.arn

  filename         = data.archive_file.compliance_exporter.output_path
  source_code_hash = data.archive_file.compliance_exporter.output_base64sha256

  runtime       = "python3.12"
  architectures = ["arm64"]
  handler       = "app.lambda_handler"
  timeout       = 300
  memory_size   = 256

  environment {
    variables = {
      EXPORT_BUCKET              = aws_s3_bucket.exports.bucket
      CONFIG_COMPLIANCE_PREFIX   = local.config_compliance_prefix
      SECURITYHUB_SUMMARY_PREFIX = local.securityhub_summary_prefix
      CONFIG_AGGREGATOR_NAME     = try(aws_config_configuration_aggregator.organization[0].name, "")
      SECURITYHUB_FINDINGS_MAX   = tostring(var.securityhub_findings_max)
      LOG_LEVEL                  = "INFO"
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.compliance_exporter_logs,
    aws_cloudwatch_log_group.compliance_exporter,
  ]
}

resource "aws_cloudwatch_event_rule" "compliance_exporter" {
  name                = "${var.project}-compliance-export"
  description         = "Trigger the daily compliance snapshot exporter."
  schedule_expression = var.compliance_export_schedule
}

resource "aws_cloudwatch_event_target" "compliance_exporter" {
  rule      = aws_cloudwatch_event_rule.compliance_exporter.name
  target_id = "compliance-exporter"
  arn       = aws_lambda_function.compliance_exporter.arn
}

resource "aws_lambda_permission" "compliance_exporter" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance_exporter.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.compliance_exporter.arn
}

# ------------------------------ 8. Outputs -----------------------------------

output "compliance_exports_bucket" {
  description = "S3 bucket the daily compliance snapshots are written to."
  value       = aws_s3_bucket.exports.bucket
}

output "athena_results_bucket" {
  description = "S3 bucket holding Athena query results for the compliance workgroup."
  value       = aws_s3_bucket.athena_results.bucket
}

output "compliance_glue_database" {
  description = "Glue catalog database exposing the compliance export tables."
  value       = aws_glue_catalog_database.compliance.name
}

output "compliance_athena_workgroup" {
  description = "Athena workgroup used to query the compliance snapshots."
  value       = aws_athena_workgroup.compliance.name
}

output "compliance_exporter_function_name" {
  description = "Name of the daily compliance snapshot exporter Lambda."
  value       = aws_lambda_function.compliance_exporter.function_name
}

output "analytics_kms_key_arn" {
  description = "ARN of the CMK encrypting compliance exports and Athena results."
  value       = aws_kms_key.analytics.arn
}
