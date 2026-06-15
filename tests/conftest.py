"""Shared pytest fixtures for the Lambda evaluator suite.

The Lambda functions live in directories whose names contain hyphens
(``config-rules``, ``require-backup-tag``), which are not importable as normal
Python packages. Each module is therefore loaded directly from its file path
with :mod:`importlib`.

AWS region and dummy credentials are set *before* the modules import, because
each evaluator constructs its boto3 clients at module scope. Creating a client
needs a region but makes no network call, so this is safe and offline.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import sys
from types import ModuleType

# Must be set before any module that calls boto3.client(...) is imported.
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")

import pytest  # noqa: E402  (import after env setup, by design)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_module(module_name: str, relative_path: str) -> ModuleType:
    """Load a Lambda ``app.py`` from its path under a unique module name."""
    path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {relative_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def require_backup_tag() -> ModuleType:
    return load_module(
        "rule_require_backup_tag",
        "lambda/config-rules/require-backup-tag/app.py",
    )


@pytest.fixture(scope="session")
def iam_key_rotation() -> ModuleType:
    return load_module(
        "rule_iam_key_rotation",
        "lambda/config-rules/iam-key-rotation/app.py",
    )


@pytest.fixture(scope="session")
def s3_public_blocks() -> ModuleType:
    return load_module(
        "rule_s3_public_blocks",
        "lambda/config-rules/s3-public-blocks/app.py",
    )


@pytest.fixture(scope="session")
def compliance_exporter() -> ModuleType:
    return load_module("compliance_exporter", "lambda/compliance-exporter/app.py")


@pytest.fixture(scope="session")
def findings_router() -> ModuleType:
    return load_module("findings_router", "lambda/findings-router/app.py")
