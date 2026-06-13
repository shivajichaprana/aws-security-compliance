# Amazon GuardDuty: continuous threat detection, enabled organisation-wide.
#
# GuardDuty findings are normalised into Security Hub automatically (both
# services run in this account), so the findings router in findings-router.tf
# picks up HIGH/CRITICAL GuardDuty findings with no extra wiring.
#
# Protection plans are modelled as detector "features" (the current API) so
# each can be toggled independently:
#   S3_DATA_EVENTS         S3 protection
#   EKS_AUDIT_LOGS         EKS control-plane audit-log monitoring
#   RDS_LOGIN_EVENTS       RDS login-activity monitoring
#   EBS_MALWARE_PROTECTION agentless malware scanning of EBS volumes
#   LAMBDA_NETWORK_LOGS    Lambda network-activity monitoring
#   RUNTIME_MONITORING     EKS/ECS/EC2 runtime agent monitoring
#
# Layout:
#   1. Variables  — publishing frequency + per-protection toggles + org switch
#   2. Locals     — single feature map driving account + org resources
#   3. Detector   — account detector + per-feature configuration
#   4. Org config — delegated administrator + member/feature auto-enrolment

# ----------------------------- 1. Variables ---------------------------------

variable "guardduty_finding_publishing_frequency" {
  description = "How often GuardDuty publishes updated findings to Security Hub / EventBridge."
  type        = string
  default     = "FIFTEEN_MINUTES"

  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.guardduty_finding_publishing_frequency)
    error_message = "guardduty_finding_publishing_frequency must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

variable "enable_guardduty_s3_protection" {
  description = "Enable S3 data-event protection (S3_DATA_EVENTS)."
  type        = bool
  default     = true
}

variable "enable_guardduty_eks_protection" {
  description = "Enable EKS control-plane audit-log monitoring (EKS_AUDIT_LOGS)."
  type        = bool
  default     = true
}

variable "enable_guardduty_rds_protection" {
  description = "Enable RDS login-activity monitoring (RDS_LOGIN_EVENTS)."
  type        = bool
  default     = true
}

variable "enable_guardduty_malware_protection" {
  description = "Enable agentless EBS malware protection (EBS_MALWARE_PROTECTION)."
  type        = bool
  default     = true
}

variable "enable_guardduty_lambda_protection" {
  description = "Enable Lambda network-activity monitoring (LAMBDA_NETWORK_LOGS)."
  type        = bool
  default     = true
}

variable "enable_guardduty_runtime_monitoring" {
  description = "Enable runtime monitoring with managed agents for EKS, ECS Fargate, and EC2 (RUNTIME_MONITORING)."
  type        = bool
  default     = true
}

variable "enable_guardduty_org" {
  description = "Register this account as the GuardDuty delegated administrator and auto-enrol organisation members. Requires running from (or as a delegated admin of) the Organizations management account."
  type        = bool
  default     = true
}

# ------------------------------ 2. Locals ------------------------------------

locals {
  # status/auto_enable derive from the toggle; ENABLED <-> ALL, DISABLED <-> NONE.
  # `additional` holds managed-agent sub-features (RUNTIME_MONITORING only).
  guardduty_features = {
    S3_DATA_EVENTS = {
      enabled    = var.enable_guardduty_s3_protection
      additional = {}
    }
    EKS_AUDIT_LOGS = {
      enabled    = var.enable_guardduty_eks_protection
      additional = {}
    }
    RDS_LOGIN_EVENTS = {
      enabled    = var.enable_guardduty_rds_protection
      additional = {}
    }
    EBS_MALWARE_PROTECTION = {
      enabled    = var.enable_guardduty_malware_protection
      additional = {}
    }
    LAMBDA_NETWORK_LOGS = {
      enabled    = var.enable_guardduty_lambda_protection
      additional = {}
    }
    RUNTIME_MONITORING = {
      enabled = var.enable_guardduty_runtime_monitoring
      additional = {
        EKS_ADDON_MANAGEMENT         = var.enable_guardduty_runtime_monitoring
        ECS_FARGATE_AGENT_MANAGEMENT = var.enable_guardduty_runtime_monitoring
        EC2_AGENT_MANAGEMENT         = var.enable_guardduty_runtime_monitoring
      }
    }
  }
}

# ------------------------------ 3. Detector ----------------------------------

resource "aws_guardduty_detector" "this" {
  enable                       = true
  finding_publishing_frequency = var.guardduty_finding_publishing_frequency
}

resource "aws_guardduty_detector_feature" "this" {
  for_each = local.guardduty_features

  detector_id = aws_guardduty_detector.this.id
  name        = each.key
  status      = each.value.enabled ? "ENABLED" : "DISABLED"

  dynamic "additional_configuration" {
    for_each = each.value.additional
    content {
      name   = additional_configuration.key
      status = additional_configuration.value ? "ENABLED" : "DISABLED"
    }
  }
}

# ------------------------------ 4. Org config --------------------------------

# Delegate GuardDuty administration to this account (run from the Organizations
# management account). The delegated admin then governs all member detectors.
resource "aws_guardduty_organization_admin_account" "this" {
  count = var.enable_guardduty_org ? 1 : 0

  admin_account_id = local.account_id

  depends_on = [aws_guardduty_detector.this]
}

# Auto-enable GuardDuty in every current and future member account.
resource "aws_guardduty_organization_configuration" "this" {
  count = var.enable_guardduty_org ? 1 : 0

  detector_id                      = aws_guardduty_detector.this.id
  auto_enable_organization_members = "ALL"

  depends_on = [aws_guardduty_organization_admin_account.this]
}

# Auto-enable each protection plan org-wide so members inherit the same
# coverage as the delegated admin.
resource "aws_guardduty_organization_configuration_feature" "this" {
  for_each = var.enable_guardduty_org ? local.guardduty_features : {}

  detector_id = aws_guardduty_detector.this.id
  name        = each.key
  auto_enable = each.value.enabled ? "ALL" : "NONE"

  dynamic "additional_configuration" {
    for_each = each.value.additional
    content {
      name        = additional_configuration.key
      auto_enable = additional_configuration.value ? "ALL" : "NONE"
    }
  }

  depends_on = [aws_guardduty_organization_configuration.this]
}

# ------------------------------- Outputs -------------------------------------

output "guardduty_detector_id" {
  description = "ID of the account GuardDuty detector."
  value       = aws_guardduty_detector.this.id
}

output "guardduty_enabled_features" {
  description = "GuardDuty protection features that are ENABLED in this account."
  value       = sort([for name, feature in local.guardduty_features : name if feature.enabled])
}

output "guardduty_org_admin_account_id" {
  description = "Account delegated as the GuardDuty organisation administrator (null when org enrolment is disabled)."
  value       = try(aws_guardduty_organization_admin_account.this[0].admin_account_id, null)
}
