# AWS Security Hub: organisation-wide security signal aggregation.
#
# Security Hub is the single pane of glass for this stack — it ingests
# findings from AWS Config (this repo's recorder + rules), GuardDuty (see
# guardduty.tf), Inspector, IAM Access Analyzer, and Macie automatically, then
# scores them against compliance standards.
#
# Layout:
#   1. Variables  — standard toggles, CIS version, org enrolment switch
#   2. Data/Local — region + the standard ARNs derived from it
#   3. Account    — enable Security Hub with consolidated control findings
#   4. Standards  — FSBP, CIS AWS Foundations, and PCI DSS subscriptions
#   5. Aggregation— cross-Region finding aggregator
#   6. Org config — delegated administrator + member auto-enrolment
#
# Native AWS integrations (GuardDuty, Inspector, Config, Access Analyzer,
# Macie) are enabled automatically by Security Hub once both services are on
# in the account, so no aws_securityhub_product_subscription is declared for
# them — doing so would conflict with the auto-created integration.

# ----------------------------- 1. Variables ---------------------------------

variable "enable_fsbp_standard" {
  description = "Subscribe to the AWS Foundational Security Best Practices standard."
  type        = bool
  default     = true
}

variable "enable_cis_standard" {
  description = "Subscribe to the CIS AWS Foundations Benchmark standard."
  type        = bool
  default     = true
}

variable "enable_pci_dss_standard" {
  description = "Subscribe to the PCI DSS standard."
  type        = bool
  default     = true
}

variable "cis_standard_version" {
  description = "CIS AWS Foundations Benchmark version to subscribe to."
  type        = string
  default     = "3.0.0"

  validation {
    condition     = contains(["1.2.0", "1.4.0", "3.0.0"], var.cis_standard_version)
    error_message = "cis_standard_version must be one of: 1.2.0, 1.4.0, 3.0.0."
  }
}

variable "pci_dss_standard_version" {
  description = "PCI DSS standard version to subscribe to."
  type        = string
  default     = "3.2.1"

  validation {
    condition     = contains(["3.2.1", "4.0.1"], var.pci_dss_standard_version)
    error_message = "pci_dss_standard_version must be one of: 3.2.1, 4.0.1."
  }
}

variable "securityhub_control_finding_generator" {
  description = "How Security Hub generates control findings. SECURITY_CONTROL consolidates findings across standards (recommended)."
  type        = string
  default     = "SECURITY_CONTROL"

  validation {
    condition     = contains(["SECURITY_CONTROL", "STANDARD_CONTROL"], var.securityhub_control_finding_generator)
    error_message = "securityhub_control_finding_generator must be SECURITY_CONTROL or STANDARD_CONTROL."
  }
}

variable "enable_securityhub_org" {
  description = "Register this account as the Security Hub delegated administrator and auto-enrol organisation members. Requires running from (or as a delegated admin of) the Organizations management account."
  type        = bool
  default     = true
}

variable "securityhub_auto_enable_standards" {
  description = "Whether newly enrolled member accounts automatically receive the default standards (DEFAULT) or none (NONE)."
  type        = string
  default     = "DEFAULT"

  validation {
    condition     = contains(["DEFAULT", "NONE"], var.securityhub_auto_enable_standards)
    error_message = "securityhub_auto_enable_standards must be DEFAULT or NONE."
  }
}

# --------------------------- 2. Data / Locals --------------------------------

data "aws_region" "current" {}

locals {
  # Standard subscription ARNs are Region-scoped and account-agnostic (the
  # account field is intentionally empty: "...:securityhub:<region>::...").
  securityhub_standard_arns = {
    fsbp = {
      enabled = var.enable_fsbp_standard
      arn     = "arn:${data.aws_partition.current.partition}:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
    }
    cis = {
      enabled = var.enable_cis_standard
      arn     = "arn:${data.aws_partition.current.partition}:securityhub:${data.aws_region.current.name}::standards/cis-aws-foundations-benchmark/v/${var.cis_standard_version}"
    }
    pci_dss = {
      enabled = var.enable_pci_dss_standard
      arn     = "arn:${data.aws_partition.current.partition}:securityhub:${data.aws_region.current.name}::standards/pci-dss/v/${var.pci_dss_standard_version}"
    }
  }

  # Only the standards actually toggled on become subscription resources.
  securityhub_enabled_standards = {
    for key, std in local.securityhub_standard_arns : key => std.arn if std.enabled
  }
}

# ------------------------------ 3. Account -----------------------------------

resource "aws_securityhub_account" "this" {
  # Consolidated control findings keep one finding per control across every
  # subscribed standard instead of duplicating it per standard.
  control_finding_generator = var.securityhub_control_finding_generator

  # Controls added to subscribed standards are turned on automatically so new
  # AWS controls do not silently go unmonitored.
  auto_enable_controls = true

  # Standards are subscribed explicitly below, so do not let the account
  # bootstrap its own default set (which would fight the subscriptions).
  enable_default_standards = false
}

# ------------------------------ 4. Standards ---------------------------------

resource "aws_securityhub_standards_subscription" "this" {
  for_each = local.securityhub_enabled_standards

  standards_arn = each.value

  # Security Hub must be enabled on the account before a standard can be
  # subscribed.
  depends_on = [aws_securityhub_account.this]
}

# ----------------------------- 5. Aggregation --------------------------------

# Aggregate findings from every linked Region into this (home) Region so the
# dashboard and the findings router below see a complete, single-Region view.
resource "aws_securityhub_finding_aggregator" "this" {
  linking_mode = "ALL_REGIONS"

  depends_on = [aws_securityhub_account.this]
}

# ------------------------------ 6. Org config --------------------------------

# Delegate Security Hub administration to this account. This call is made from
# the Organizations management account; admin_account_id is normally the
# dedicated security/audit account (here, the account running the stack).
resource "aws_securityhub_organization_admin_account" "this" {
  count = var.enable_securityhub_org ? 1 : 0

  admin_account_id = local.account_id

  depends_on = [aws_securityhub_account.this]
}

# Auto-enrol existing and future member accounts. Runs as the delegated admin.
resource "aws_securityhub_organization_configuration" "this" {
  count = var.enable_securityhub_org ? 1 : 0

  auto_enable           = true
  auto_enable_standards = var.securityhub_auto_enable_standards

  organization_configuration {
    configuration_type = "LOCAL"
  }

  depends_on = [aws_securityhub_organization_admin_account.this]
}

# ------------------------------- Outputs -------------------------------------

output "securityhub_account_arn" {
  description = "ARN of the Security Hub account resource (the hub itself)."
  value       = aws_securityhub_account.this.arn
}

output "securityhub_subscribed_standards" {
  description = "Standard subscription ARNs that are active in this account."
  value       = sort([for sub in aws_securityhub_standards_subscription.this : sub.standards_arn])
}

output "securityhub_finding_aggregator_arn" {
  description = "ARN of the cross-Region Security Hub finding aggregator."
  value       = aws_securityhub_finding_aggregator.this.arn
}
