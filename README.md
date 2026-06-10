# aws-security-compliance

Continuous compliance platform for AWS: AWS Config rules (managed + custom Lambda-backed),
SSM Automation auto-remediation, and organization-wide aggregation into Security Hub.

## What this provides

| Capability | Implementation |
|---|---|
| Configuration recording | AWS Config recorder + delivery channel, all supported resource types including global |
| CIS baseline evaluation | 20 AWS managed Config rules mapped to CIS AWS Foundations Benchmark controls |
| Custom guardrails | Lambda-backed Config rules (resource tagging, IAM key rotation, S3 public-access blocks) |
| Auto-remediation | SSM Automation documents wired to Config remediation configurations |
| Aggregation | Organization-wide Config aggregator; Security Hub + GuardDuty findings routing |
| Reporting | Compliance snapshots to S3, Athena views, QuickSight dashboard |

## Repository structure

```
.
├── terraform/            # All infrastructure: recorder, rules, remediation, aggregation
├── lambda/
│   ├── config-rules/     # Custom Config rule evaluation functions
│   └── remediation/      # Remediation helper functions
├── ssm-documents/        # SSM Automation documents (auto-fix runbooks)
└── docs/                 # Architecture and control-matrix documentation
```

## Getting started

```bash
cd terraform
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

### Requirements

| Name | Version |
|---|---|
| terraform | >= 1.6.0 |
| aws provider | >= 5.40.0, < 6.0.0 |

The deploying role needs permissions for AWS Config, IAM, S3, Lambda, SSM, Security Hub,
GuardDuty, and (for the organization aggregator) AWS Organizations read access.

## Design notes

- The Config delivery bucket is created with versioning, SSE, lifecycle expiry for old
  snapshots, and a deny-insecure-transport policy. It is never public.
- Managed rules are driven from a single `for_each` map so adding or retiring a control
  is a one-line change reviewed like any other code change.
- Custom rules and remediation documents are kept in separate directories so each can be
  unit-tested independently of Terraform.

## Contributing

Open a Discussion in the repo or comment on a PR.

## License

MIT — see [LICENSE](LICENSE).
