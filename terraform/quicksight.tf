# QuickSight compliance dashboard over the Athena compliance snapshots.
#
# Sits on top of the analytics pipeline in athena-views.tf: a QuickSight Athena
# data source points at the compliance workgroup, two SPICE datasets embed the
# scorecard / severity SQL (so the dashboard does not depend on the named-query
# views being materialised first), daily refreshes pull the latest snapshot
# into SPICE, and a dashboard renders an executive compliance overview.
#
# Everything here is gated on `local.quicksight_enabled`
# (`enable_quicksight` AND a non-empty `quicksight_principal_arn`). QuickSight
# has no sensible default principal and an account may not be QuickSight-
# subscribed, so with the principal left blank this whole file plans to zero
# resources and the rest of the stack still applies cleanly.
#
# Prerequisite (one-time, outside Terraform): QuickSight Enterprise must be
# enabled and its service role granted access to Athena, the analytics buckets,
# and the analytics CMK (see athena-views.tf, which already permits the
# quicksight.amazonaws.com service principal on the key).
#
# Layout:
#   1. Variables — enable switch + principal + namespace
#   2. Locals    — gate + identifiers + dataset permission action sets
#   3. Data src  — Athena data source
#   4. Datasets  — scorecard + severity (SPICE, custom SQL)
#   5. Refresh   — daily SPICE refresh schedules
#   6. Dashboard — executive compliance overview
#   7. Outputs

# ----------------------------- 1. Variables ---------------------------------

variable "enable_quicksight" {
  description = "Provision the QuickSight data source, datasets, and dashboard. Requires a QuickSight Enterprise subscription in the account."
  type        = bool
  default     = true
}

variable "quicksight_principal_arn" {
  description = "ARN of the QuickSight user or group that owns the data source, datasets, and dashboard (e.g. arn:aws:quicksight:us-east-1:123456789012:user/default/alice). Blank disables every QuickSight resource."
  type        = string
  default     = ""

  validation {
    condition     = var.quicksight_principal_arn == "" || can(regex("^arn:aws[a-z-]*:quicksight:", var.quicksight_principal_arn))
    error_message = "quicksight_principal_arn must be empty or a QuickSight principal ARN."
  }
}

variable "quicksight_namespace" {
  description = "QuickSight namespace the assets live in."
  type        = string
  default     = "default"
}

# ------------------------------ 2. Locals ------------------------------------

locals {
  # Both conditions must hold for any QuickSight resource to be created.
  quicksight_enabled = var.enable_quicksight && var.quicksight_principal_arn != ""

  quicksight_data_source_id = "${var.project}-athena"
  scorecard_data_set_id     = "${var.project}-config-scorecard"
  severity_data_set_id      = "${var.project}-securityhub-severity"
  compliance_dashboard_id   = "${var.project}-compliance-overview"

  # Owner-level permission sets, applied uniformly to the QuickSight principal.
  quicksight_data_source_actions = [
    "quicksight:DescribeDataSource",
    "quicksight:DescribeDataSourcePermissions",
    "quicksight:PassDataSource",
    "quicksight:UpdateDataSource",
    "quicksight:UpdateDataSourcePermissions",
    "quicksight:DeleteDataSource",
  ]

  quicksight_data_set_actions = [
    "quicksight:DescribeDataSet",
    "quicksight:DescribeDataSetPermissions",
    "quicksight:PassDataSet",
    "quicksight:DescribeIngestion",
    "quicksight:ListIngestions",
    "quicksight:UpdateDataSet",
    "quicksight:UpdateDataSetPermissions",
    "quicksight:DeleteDataSet",
    "quicksight:CreateIngestion",
    "quicksight:CancelIngestion",
  ]

  quicksight_dashboard_actions = [
    "quicksight:DescribeDashboard",
    "quicksight:DescribeDashboardPermissions",
    "quicksight:ListDashboardVersions",
    "quicksight:QueryDashboard",
    "quicksight:UpdateDashboard",
    "quicksight:UpdateDashboardPermissions",
    "quicksight:UpdateDashboardPublishedVersion",
    "quicksight:DeleteDashboard",
  ]
}

# ------------------------------ 3. Data source -------------------------------

resource "aws_quicksight_data_source" "athena" {
  count = local.quicksight_enabled ? 1 : 0

  data_source_id = local.quicksight_data_source_id
  name           = "${var.project} compliance (Athena)"
  type           = "ATHENA"

  parameters {
    athena {
      work_group = aws_athena_workgroup.compliance.name
    }
  }

  ssl_properties {
    disable_ssl = false
  }

  permission {
    principal = var.quicksight_principal_arn
    actions   = local.quicksight_data_source_actions
  }
}

# ------------------------------ 4. Datasets ----------------------------------

# 4a. Config compliance scorecard — rule counts and compliant percentage for
# the latest snapshot, one row per account.
resource "aws_quicksight_data_set" "config_scorecard" {
  count = local.quicksight_enabled ? 1 : 0

  data_set_id = local.scorecard_data_set_id
  name        = "Config compliance scorecard"
  import_mode = "SPICE"

  physical_table_map {
    physical_table_map_id = "scorecard"

    custom_sql {
      data_source_arn = aws_quicksight_data_source.athena[0].arn
      name            = "config_scorecard"

      sql_query = <<-SQL
        SELECT
          account_id,
          count(*)                                    AS total_rules,
          count_if(compliance_type = 'COMPLIANT')     AS compliant_rules,
          count_if(compliance_type = 'NON_COMPLIANT') AS non_compliant_rules,
          round(
            100.0 * count_if(compliance_type = 'COMPLIANT') / nullif(count(*), 0),
            2
          )                                           AS compliance_percentage,
          dt                                          AS snapshot_date
        FROM "${local.glue_database_name}"."config_rule_compliance"
        WHERE dt = (SELECT max(dt) FROM "${local.glue_database_name}"."config_rule_compliance")
        GROUP BY account_id, dt
      SQL

      columns {
        name = "account_id"
        type = "STRING"
      }
      columns {
        name = "total_rules"
        type = "INTEGER"
      }
      columns {
        name = "compliant_rules"
        type = "INTEGER"
      }
      columns {
        name = "non_compliant_rules"
        type = "INTEGER"
      }
      columns {
        name = "compliance_percentage"
        type = "DECIMAL"
      }
      columns {
        name = "snapshot_date"
        type = "STRING"
      }
    }
  }

  permission {
    principal = var.quicksight_principal_arn
    actions   = local.quicksight_data_set_actions
  }
}

# 4b. Security Hub severity — active findings by account and severity for the
# latest snapshot.
resource "aws_quicksight_data_set" "securityhub_severity" {
  count = local.quicksight_enabled ? 1 : 0

  data_set_id = local.severity_data_set_id
  name        = "Security Hub findings by severity"
  import_mode = "SPICE"

  physical_table_map {
    physical_table_map_id = "severity"

    custom_sql {
      data_source_arn = aws_quicksight_data_source.athena[0].arn
      name            = "securityhub_severity"

      sql_query = <<-SQL
        SELECT
          account_id,
          severity_label,
          sum(finding_count) AS findings,
          dt                 AS snapshot_date
        FROM "${local.glue_database_name}"."securityhub_finding_summary"
        WHERE dt = (SELECT max(dt) FROM "${local.glue_database_name}"."securityhub_finding_summary")
          AND record_state = 'ACTIVE'
        GROUP BY account_id, severity_label, dt
      SQL

      columns {
        name = "account_id"
        type = "STRING"
      }
      columns {
        name = "severity_label"
        type = "STRING"
      }
      columns {
        name = "findings"
        type = "INTEGER"
      }
      columns {
        name = "snapshot_date"
        type = "STRING"
      }
    }
  }

  permission {
    principal = var.quicksight_principal_arn
    actions   = local.quicksight_data_set_actions
  }
}

# ------------------------------ 5. Refresh -----------------------------------

# Pull the latest snapshot into SPICE every morning, after the exporter's
# 04:00 UTC run (see compliance_export_schedule).
resource "aws_quicksight_refresh_schedule" "config_scorecard" {
  count = local.quicksight_enabled ? 1 : 0

  data_set_id = aws_quicksight_data_set.config_scorecard[0].data_set_id
  schedule_id = "${var.project}-scorecard-daily"

  schedule {
    refresh_type = "FULL_REFRESH"

    schedule_frequency {
      interval        = "DAILY"
      time_of_the_day = "05:30"
      timezone        = "UTC"
    }
  }
}

resource "aws_quicksight_refresh_schedule" "securityhub_severity" {
  count = local.quicksight_enabled ? 1 : 0

  data_set_id = aws_quicksight_data_set.securityhub_severity[0].data_set_id
  schedule_id = "${var.project}-severity-daily"

  schedule {
    refresh_type = "FULL_REFRESH"

    schedule_frequency {
      interval        = "DAILY"
      time_of_the_day = "05:30"
      timezone        = "UTC"
    }
  }
}

# ------------------------------ 6. Dashboard ---------------------------------

resource "aws_quicksight_dashboard" "compliance" {
  count = local.quicksight_enabled ? 1 : 0

  dashboard_id        = local.compliance_dashboard_id
  name                = "Security & Compliance Overview"
  version_description = "Compliance posture from AWS Config and Security Hub."

  definition {
    data_set_identifiers_declarations {
      data_set_arn = aws_quicksight_data_set.config_scorecard[0].arn
      identifier   = "scorecard"
    }

    data_set_identifiers_declarations {
      data_set_arn = aws_quicksight_data_set.securityhub_severity[0].arn
      identifier   = "severity"
    }

    sheets {
      sheet_id = "overview"
      name     = "Compliance Overview"

      # KPI: average Config compliance percentage across accounts.
      visuals {
        kpi_visual {
          visual_id = "compliance-pct"

          title {
            format_text {
              plain_text = "Average compliance %"
            }
          }

          chart_configuration {
            field_wells {
              values {
                numerical_measure_field {
                  field_id = "compliance_pct"

                  column {
                    data_set_identifier = "scorecard"
                    column_name         = "compliance_percentage"
                  }

                  aggregation_function {
                    simple_numerical_aggregation = "AVERAGE"
                  }
                }
              }
            }
          }
        }
      }

      # Bar: non-compliant rules by account.
      visuals {
        bar_chart_visual {
          visual_id = "noncompliant-by-account"

          title {
            format_text {
              plain_text = "Non-compliant rules by account"
            }
          }

          chart_configuration {
            field_wells {
              bar_chart_aggregated_field_wells {
                category {
                  categorical_dimension_field {
                    field_id = "account"

                    column {
                      data_set_identifier = "scorecard"
                      column_name         = "account_id"
                    }
                  }
                }

                values {
                  numerical_measure_field {
                    field_id = "noncompliant"

                    column {
                      data_set_identifier = "scorecard"
                      column_name         = "non_compliant_rules"
                    }

                    aggregation_function {
                      simple_numerical_aggregation = "SUM"
                    }
                  }
                }
              }
            }
          }
        }
      }

      # Bar: active Security Hub findings by severity.
      visuals {
        bar_chart_visual {
          visual_id = "findings-by-severity"

          title {
            format_text {
              plain_text = "Active findings by severity"
            }
          }

          chart_configuration {
            field_wells {
              bar_chart_aggregated_field_wells {
                category {
                  categorical_dimension_field {
                    field_id = "severity"

                    column {
                      data_set_identifier = "severity"
                      column_name         = "severity_label"
                    }
                  }
                }

                values {
                  numerical_measure_field {
                    field_id = "findings"

                    column {
                      data_set_identifier = "severity"
                      column_name         = "findings"
                    }

                    aggregation_function {
                      simple_numerical_aggregation = "SUM"
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  permission {
    principal = var.quicksight_principal_arn
    actions   = local.quicksight_dashboard_actions
  }
}

# ------------------------------ 7. Outputs -----------------------------------

output "quicksight_dashboard_id" {
  description = "ID of the QuickSight compliance dashboard (null when QuickSight is disabled)."
  value       = try(aws_quicksight_dashboard.compliance[0].dashboard_id, null)
}

output "quicksight_data_source_arn" {
  description = "ARN of the QuickSight Athena data source (null when QuickSight is disabled)."
  value       = try(aws_quicksight_data_source.athena[0].arn, null)
}

output "quicksight_data_set_ids" {
  description = "IDs of the QuickSight datasets backing the dashboard."
  value = compact([
    try(aws_quicksight_data_set.config_scorecard[0].data_set_id, ""),
    try(aws_quicksight_data_set.securityhub_severity[0].data_set_id, ""),
  ])
}
