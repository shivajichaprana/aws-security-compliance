# aws-security-compliance — developer convenience targets.
# Mirrors the checks enforced by .github/workflows/ci.yml.

TF_DIR        ?= terraform
LAMBDA_DIRS   := lambda/config-rules lambda/compliance-exporter lambda/findings-router
PYTHON        ?= python3
PIP           ?= $(PYTHON) -m pip

.DEFAULT_GOAL := help

.PHONY: help install fmt fmt-check validate lint lint-yaml test ci init plan apply clean

help: ## Show this help.
	grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Install Python dev/test dependencies.
	$(PIP) install -r requirements-dev.txt

fmt: ## Rewrite Terraform files to canonical format.
	terraform -chdir=$(TF_DIR) fmt -recursive

fmt-check: ## Fail if any Terraform file is not canonically formatted.
	terraform -chdir=$(TF_DIR) fmt -recursive -check -diff

validate: ## Validate Terraform without a backend or credentials.
	terraform -chdir=$(TF_DIR) init -backend=false -input=false
	terraform -chdir=$(TF_DIR) validate

lint: lint-yaml ## Run all linters (tflint when available, plus YAML).
	command -v tflint >/dev/null 2>&1 && tflint --chdir=$(TF_DIR) || echo "tflint not installed; skipping"

lint-yaml: ## Lint the SSM Automation documents.
	yamllint -c .yamllint.yml ssm-documents

test: ## Run the Lambda evaluator test suite.
	AWS_DEFAULT_REGION=us-east-1 $(PYTHON) -m pytest -q

ci: fmt-check validate lint test ## Run every gate the CI pipeline enforces.

init: ## terraform init (real backend).
	terraform -chdir=$(TF_DIR) init -input=false

plan: ## terraform plan.
	terraform -chdir=$(TF_DIR) plan -out=tfplan

apply: ## terraform apply the saved plan.
	terraform -chdir=$(TF_DIR) apply tfplan

clean: ## Remove local Terraform and Python build artifacts.
	rm -rf $(TF_DIR)/.terraform $(TF_DIR)/tfplan
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -prune -exec rm -rf {} + 2>/dev/null || true
