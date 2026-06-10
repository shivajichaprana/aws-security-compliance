# Core input variables. Rule- and recorder-specific variables live alongside
# the resources that consume them (config-recorder.tf, managed-rules.tf).

variable "project" {
  description = "Project identifier used as a prefix for resource names and tags."
  type        = string
  default     = "aws-security-compliance"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,40}$", var.project))
    error_message = "project must be lowercase alphanumeric/hyphen, 3-41 chars, starting with a letter."
  }
}

variable "environment" {
  description = "Deployment environment. Compliance tooling normally runs once, in the security/audit account, as prod."
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "aws_region" {
  description = "Region the Config recorder, delivery channel, and aggregator are deployed into."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", var.aws_region))
    error_message = "aws_region must be a valid AWS region name, e.g. us-east-1 or eu-west-2."
  }
}

variable "tags" {
  description = "Additional tags merged onto every resource via provider default_tags."
  type        = map(string)
  default     = {}
}
