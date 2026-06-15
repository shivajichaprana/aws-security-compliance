# Contributing

Thanks for helping improve `aws-security-compliance`. This repo favours small,
reviewable changes: most additions — a new managed rule, a tweaked threshold —
are a one-line diff in a `for_each` map.

## Getting set up

```bash
make install      # dev tooling: terraform fmt/validate + python test deps
make fmt          # terraform fmt + check
make lint         # tflint (if installed) + yamllint on ssm-documents/
make test         # pytest over the Lambda evaluators
make validate     # terraform validate (backend-less)
```

`make ci` runs `fmt`, `validate`, `lint`, and `test` together — the same gates
the GitHub Actions pipeline enforces.

## Adding a managed Config rule

1. Add an entry to `local.cis_managed_rules` in `terraform/managed-rules.tf`.
   Include the `source_identifier`, a `description` that names the CIS control,
   `input_parameters` (or `null`), and an evaluation `frequency`.
2. Add the rule to [`docs/control-matrix.md`](docs/control-matrix.md) with its
   CIS / PCI-DSS / SOC 2 references.
3. Run `make validate`.

## Adding a custom Config rule

1. Create `lambda/config-rules/<rule-name>/app.py`. Keep boto3 clients at module
   scope and the decision logic in pure functions that return
   `(compliance_type, annotation)` so it stays unit-testable.
2. Wire the Lambda and `aws_config_config_rule` in `terraform/custom-rules.tf`.
3. If it can self-heal, add an SSM runbook under `ssm-documents/` and a mapping
   in `terraform/remediation-configurations.tf`.
4. Add tests under `tests/` covering both COMPLIANT and NON_COMPLIANT paths.

## Coding standards

- **Terraform:** `terraform fmt`; variable `validation` blocks and meaningful
  `description`s; provider versions stay pinned in `versions.tf`.
- **Python:** type hints, docstrings, the `logging` module (never `print`),
  and no network calls in pure decision functions.
- **SSM YAML:** must pass `yamllint -c .yamllint.yml`.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):
`feat`, `fix`, `docs`, `test`, `ci`, `refactor`, `chore`. Example:

```
feat(custom-rules): add ECR image-scan-on-push Config rule
```

## Questions

Open a Discussion in the repo or comment on the relevant PR. Please do not
include real account ids, ARNs, or other environment-specific data in issues —
use the documented placeholder `123456789012`.
