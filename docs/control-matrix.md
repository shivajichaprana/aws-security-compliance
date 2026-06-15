# Control matrix

This matrix maps every Config rule in the platform to the framework controls it
supports and, where applicable, the SSM runbook that auto-remediates it.

> **Note on mappings.** CIS references are authoritative and come straight from
> the `description` field of each rule in `terraform/managed-rules.tf`. The
> PCI-DSS and SOC 2 columns are **indicative cross-references** to help scope an
> audit — they are a starting point, not a certified attestation. Confirm the
> exact applicability with your QSA / SOC 2 auditor for your environment.

Frameworks referenced: **CIS** AWS Foundations Benchmark v3.0.0,
**PCI-DSS** v3.2.1, **SOC 2** Trust Services Criteria (2017).

## Managed rules (20)

| # | Config rule | Source identifier | CIS | PCI-DSS | SOC 2 |
|---|---|---|---|---|---|
| 1 | `iam-root-access-key-check` | IAM_ROOT_ACCESS_KEY_CHECK | 1.4 | 7.2 | CC6.1 |
| 2 | `root-account-mfa-enabled` | ROOT_ACCOUNT_MFA_ENABLED | 1.5 | 8.3 | CC6.1 |
| 3 | `mfa-enabled-for-iam-console-access` | MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS | 1.10 | 8.3 | CC6.1 |
| 4 | `access-keys-rotated` | ACCESS_KEYS_ROTATED | 1.14 | 8.2.4 | CC6.1 |
| 5 | `iam-password-policy` | IAM_PASSWORD_POLICY | 1.8 / 1.9 | 8.2.3–8.2.5 | CC6.1 |
| 6 | `iam-user-unused-credentials-check` | IAM_USER_UNUSED_CREDENTIALS_CHECK | 1.12 | 8.1.4 | CC6.2 |
| 7 | `iam-policy-no-admin-statements` | IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS | 1.16 | 7.1 | CC6.3 |
| 8 | `s3-bucket-public-read-prohibited` | S3_BUCKET_PUBLIC_READ_PROHIBITED | 2.1.5 | 1.3.1 | CC6.1 |
| 9 | `s3-bucket-public-write-prohibited` | S3_BUCKET_PUBLIC_WRITE_PROHIBITED | 2.1.5 | 1.3.2 | CC6.1 |
| 10 | `s3-bucket-sse-enabled` | S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED | 2.1.1 | 3.4 | CC6.1 |
| 11 | `s3-bucket-ssl-requests-only` | S3_BUCKET_SSL_REQUESTS_ONLY | 2.1.2 | 4.1 | CC6.7 |
| 12 | `s3-account-level-public-access-blocks` | S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS_PERIODIC | 2.1.5 | 1.3 | CC6.1 |
| 13 | `encrypted-volumes` | ENCRYPTED_VOLUMES | 2.2.1 | 3.4 | CC6.1 |
| 14 | `rds-storage-encrypted` | RDS_STORAGE_ENCRYPTED | 2.3.1 | 3.4 | CC6.1 |
| 15 | `cloudtrail-enabled` | CLOUD_TRAIL_ENABLED | 3.1 | 10.1 | CC7.2 |
| 16 | `multi-region-cloudtrail-enabled` | MULTI_REGION_CLOUD_TRAIL_ENABLED | 3.1 | 10.5.3 | CC7.2 |
| 17 | `cloudtrail-log-file-validation` | CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED | 3.2 | 10.5.5 | CC7.2 |
| 18 | `cmk-backing-key-rotation-enabled` | CMK_BACKING_KEY_ROTATION_ENABLED | 3.8 | 3.6.4 | CC6.1 |
| 19 | `vpc-flow-logs-enabled` | VPC_FLOW_LOGS_ENABLED | 3.7 | 10.3 | CC7.2 |
| 20 | `restricted-ssh` | INCOMING_SSH_DISABLED | 5.2 | 1.2.1 | CC6.6 |

## Custom rules (3)

| # | Config rule | Evaluator | CIS | PCI-DSS | SOC 2 | Auto-remediation |
|---|---|---|---|---|---|---|
| 21 | `require-backup-tag` | `lambda/config-rules/require-backup-tag` | — (org policy) | 12.5 | A1.2 | `attach-missing-tags.yaml` |
| 22 | `iam-key-rotation` | `lambda/config-rules/iam-key-rotation` | 1.14 (extends) | 8.2.4 / 8.3.9 | CC6.1 | `rotate-iam-key.yaml` |
| 23 | `s3-public-blocks` | `lambda/config-rules/s3-public-blocks` | 2.1.5 (extends) | 1.3 | CC6.1 | `enable-s3-public-block.yaml` |

## Remediation map

| Non-compliant rule | SSM runbook | Default action | Reversible? |
|---|---|---|---|
| `s3-public-blocks` | `enable-s3-public-block.yaml` | Enable all four public-access-block flags | n/a (hardening) |
| `iam-key-rotation` | `rotate-iam-key.yaml` | Deactivate aged active keys | Yes (deactivate, not delete) |
| `require-backup-tag` | `attach-missing-tags.yaml` | Attach default `Backup` tag | Yes |

## Coverage by framework domain

| Domain | Managed | Custom | Total |
|---|---|---|---|
| Identity & access (CIS 1) | 7 | 1 | 8 |
| Data protection / storage (CIS 2) | 7 | 1 | 8 |
| Logging & monitoring (CIS 3) | 5 | 0 | 5 |
| Networking (CIS 5) | 1 | 0 | 1 |
| Resilience / asset mgmt | 0 | 1 | 1 |
| **Total** | **20** | **3** | **23** |

## Aggregated standards (Security Hub)

Beyond the Config rules above, Security Hub continuously evaluates these managed
standards organization-wide (see `terraform/security-hub.tf`):

| Standard | Version | Toggle |
|---|---|---|
| AWS Foundational Security Best Practices | latest | `enable_fsbp_standard` |
| CIS AWS Foundations Benchmark | 3.0.0 | `enable_cis_standard` |
| PCI-DSS | 3.2.1 | `enable_pci_dss_standard` |
