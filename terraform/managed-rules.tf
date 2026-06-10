# 20 AWS managed Config rules aligned to the CIS AWS Foundations Benchmark.
#
# All rules are driven from one map: adding, tuning, or retiring a control is
# a single reviewable diff. Each entry records the CIS control it backs so
# the control matrix in docs/ can be generated straight from this file.
#
# `frequency` is set only for periodic rules; change-triggered rules must
# omit maximum_execution_frequency or the API rejects them.

variable "access_key_max_age_days" {
  description = "Maximum age in days before an IAM access key is flagged by access-keys-rotated (CIS 1.14)."
  type        = number
  default     = 90

  validation {
    condition     = var.access_key_max_age_days >= 1 && var.access_key_max_age_days <= 365
    error_message = "access_key_max_age_days must be between 1 and 365."
  }
}

variable "unused_credentials_max_age_days" {
  description = "Days of inactivity before credentials are flagged by iam-user-unused-credentials-check (CIS 1.12)."
  type        = number
  default     = 45

  validation {
    condition     = var.unused_credentials_max_age_days >= 1 && var.unused_credentials_max_age_days <= 365
    error_message = "unused_credentials_max_age_days must be between 1 and 365."
  }
}

locals {
  cis_managed_rules = {
    # ----------------------------- IAM (CIS section 1) -----------------------------
    iam-root-access-key-check = {
      source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
      description       = "CIS 1.4 - Ensure no root account access key exists."
      input_parameters  = null
      frequency         = "TwentyFour_Hours"
    }
    root-account-mfa-enabled = {
      source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
      description       = "CIS 1.5 - Ensure MFA is enabled for the root account."
      input_parameters  = null
      frequency         = "TwentyFour_Hours"
    }
    mfa-enabled-for-iam-console-access = {
      source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
      description       = "CIS 1.10 - Ensure MFA is enabled for all IAM users with a console password."
      input_parameters  = null
      frequency         = "TwentyFour_Hours"
    }
    access-keys-rotated = {
      source_identifier = "ACCESS_KEYS_ROTATED"
      description       = "CIS 1.14 - Ensure access keys are rotated within the configured window."
      input_parameters  = { maxAccessKeyAge = tostring(var.access_key_max_age_days) }
      frequency         = "TwentyFour_Hours"
    }
    iam-password-policy = {
      source_identifier = "IAM_PASSWORD_POLICY"
      description       = "CIS 1.8/1.9 - Ensure the account password policy meets length and reuse requirements."
      input_parameters = {
        RequireUppercaseCharacters = "true"
        RequireLowercaseCharacters = "true"
        RequireSymbols             = "true"
        RequireNumbers             = "true"
        MinimumPasswordLength      = "14"
        PasswordReusePrevention    = "24"
        MaxPasswordAge             = "90"
      }
      frequency = "TwentyFour_Hours"
    }
    iam-user-unused-credentials-check = {
      source_identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
      description       = "CIS 1.12 - Ensure credentials unused within the configured window are disabled."
      input_parameters  = { maxCredentialUsageAge = tostring(var.unused_credentials_max_age_days) }
      frequency         = "TwentyFour_Hours"
    }
    iam-policy-no-admin-statements = {
      source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
      description       = "CIS 1.16 - Ensure customer-managed IAM policies do not allow full *:* administrative privileges."
      input_parameters  = null
      frequency         = null
    }

    # --------------------------- Storage (CIS section 2) ---------------------------
    s3-bucket-public-read-prohibited = {
      source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
      description       = "CIS 2.1.5 - Ensure S3 buckets do not allow public read access."
      input_parameters  = null
      frequency         = null
    }
    s3-bucket-public-write-prohibited = {
      source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
      description       = "CIS 2.1.5 - Ensure S3 buckets do not allow public write access."
      input_parameters  = null
      frequency         = null
    }
    s3-bucket-sse-enabled = {
      source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
      description       = "CIS 2.1.1 - Ensure all S3 buckets enforce server-side encryption."
      input_parameters  = null
      frequency         = null
    }
    s3-bucket-ssl-requests-only = {
      source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
      description       = "CIS 2.1.2 - Ensure S3 bucket policies deny non-TLS requests."
      input_parameters  = null
      frequency         = null
    }
    s3-account-level-public-access-blocks = {
      source_identifier = "S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS_PERIODIC"
      description       = "CIS 2.1.5 - Ensure account-level S3 Block Public Access settings are fully enabled."
      input_parameters  = null
      frequency         = "TwentyFour_Hours"
    }
    encrypted-volumes = {
      source_identifier = "ENCRYPTED_VOLUMES"
      description       = "CIS 2.2.1 - Ensure attached EBS volumes are encrypted at rest."
      input_parameters  = null
      frequency         = null
    }
    rds-storage-encrypted = {
      source_identifier = "RDS_STORAGE_ENCRYPTED"
      description       = "CIS 2.3.1 - Ensure RDS instances have storage encryption enabled."
      input_parameters  = null
      frequency         = null
    }

    # --------------------------- Logging (CIS section 3) ---------------------------
    cloudtrail-enabled = {
      source_identifier = "CLOUD_TRAIL_ENABLED"
      description       = "CIS 3.1 - Ensure CloudTrail is enabled in the account."
      input_parameters  = null
      frequency         = "TwentyFour_Hours"
    }
    multi-region-cloudtrail-enabled = {
      source_identifier = "MULTI_REGION_CLOUD_TRAIL_ENABLED"
      description       = "CIS 3.1 - Ensure at least one multi-region CloudTrail exists."
      input_parameters  = null
      frequency         = "TwentyFour_Hours"
    }
    cloudtrail-log-file-validation = {
      source_identifier = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
      description       = "CIS 3.2 - Ensure CloudTrail log file integrity validation is enabled."
      input_parameters  = null
      frequency         = "TwentyFour_Hours"
    }
    cmk-backing-key-rotation-enabled = {
      source_identifier = "CMK_BACKING_KEY_ROTATION_ENABLED"
      description       = "CIS 3.8 - Ensure rotation for customer-managed KMS keys is enabled."
      input_parameters  = null
      frequency         = "TwentyFour_Hours"
    }
    vpc-flow-logs-enabled = {
      source_identifier = "VPC_FLOW_LOGS_ENABLED"
      description       = "CIS 3.7 - Ensure VPC flow logging is enabled in all VPCs."
      input_parameters  = null
      frequency         = "TwentyFour_Hours"
    }

    # -------------------------- Networking (CIS section 5) -------------------------
    restricted-ssh = {
      source_identifier = "INCOMING_SSH_DISABLED"
      description       = "CIS 5.2 - Ensure no security group allows ingress from 0.0.0.0/0 to port 22."
      input_parameters  = null
      frequency         = null
    }
  }
}

resource "aws_config_config_rule" "cis" {
  for_each = local.cis_managed_rules

  name        = each.key
  description = each.value.description

  source {
    owner             = "AWS"
    source_identifier = each.value.source_identifier
  }

  input_parameters = (
    each.value.input_parameters == null ? null : jsonencode(each.value.input_parameters)
  )

  maximum_execution_frequency = each.value.frequency

  # Rules can only be created once the recorder is running.
  depends_on = [aws_config_configuration_recorder_status.main]
}
