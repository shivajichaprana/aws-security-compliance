# Terraform and provider version constraints.
#
# The AWS provider is pinned below 6.x: 5.40+ is required for the
# S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS_PERIODIC managed-rule identifier and
# current aws_config_* resource behaviour this module relies on.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40.0, < 6.0.0"
    }

    # Packages the custom Config rule Lambdas (data.archive_file).
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(
      {
        Project   = var.project
        ManagedBy = "terraform"
      },
      var.tags,
    )
  }
}
