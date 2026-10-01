"""Boundary tests for the fixture-only, untrusted provider adapter."""

import ast
import builtins
import os
from pathlib import Path
import socket
import subprocess
from unittest.mock import patch

import pytest

from autodev_control.workplane.semantic_review_provider import (
    ProviderResult,
    ProviderStatus,
    ScriptedSemanticReviewProvider,
)


def test_exact_request_and_response_bytes_are_unchanged() -> None:
    request = b'\x00\xff\n{"instruction":"opaque"}'
    response = b"\x00\xff\nraw response"
    metadata = {"claimed_reviewer": "unverified", "decision": "ALLOW"}
    scripted = ProviderResult(ProviderStatus.SUCCESS, response, metadata)
    provider = ScriptedSemanticReviewProvider(scripted)

    result = provider.invoke(request)

    assert provider.last_request_bytes is request
    assert request == b'\x00\xff\n{"instruction":"opaque"}'
    assert result is scripted
    assert result.raw_response_bytes is response
    assert result.untrusted_metadata is metadata
    assert provider.attempt_count == 1


@pytest.mark.parametrize(
    "response", [b"", b"not json", b'{"decision":"ALLOW"}']
)
def test_arbitrary_response_remains_raw(response: bytes) -> None:
    provider = ScriptedSemanticReviewProvider(
        ProviderResult(ProviderStatus.SUCCESS, response)
    )

    result = provider.invoke(b"request")

    assert result.status is ProviderStatus.SUCCESS
    assert result.raw_response_bytes is response
    assert result.untrusted_metadata is None


@pytest.mark.parametrize(
    "status", [ProviderStatus.PROVIDER_ERROR, ProviderStatus.TIMEOUT]
)
def test_failure_is_only_a_transport_outcome(status: ProviderStatus) -> None:
    provider = ScriptedSemanticReviewProvider(ProviderResult(status))

    result = provider.invoke(b"request")

    assert result.status is status
    assert result.raw_response_bytes is None
    assert result.untrusted_metadata is None
    assert provider.attempt_count == 1


def test_no_implicit_retry_or_fallback() -> None:
    scripted = ProviderResult(ProviderStatus.PROVIDER_ERROR)
    provider = ScriptedSemanticReviewProvider(scripted)

    assert provider.attempt_count == 0
    assert provider.invoke(b"one") is scripted
    assert provider.attempt_count == 1
    assert provider.last_request_bytes == b"one"
    assert provider.invoke(b"two") is scripted
    assert provider.attempt_count == 2
    assert provider.last_request_bytes == b"two"


def test_invocation_has_no_external_io_or_persistent_request_log() -> None:
    provider = ScriptedSemanticReviewProvider(
        ProviderResult(ProviderStatus.SUCCESS, b"raw")
    )
    forbidden = AssertionError("fixture provider attempted external I/O")
    with (
        patch.object(socket, "socket", side_effect=forbidden),
        patch.object(socket, "create_connection", side_effect=forbidden),
        patch.object(subprocess, "Popen", side_effect=forbidden),
        patch.object(subprocess, "run", side_effect=forbidden),
        patch.object(os, "system", side_effect=forbidden),
        patch.object(builtins, "open", side_effect=forbidden),
        patch.object(Path, "open", side_effect=forbidden),
    ):
        result = provider.invoke(b"secret request bytes")

    assert result.raw_response_bytes == b"raw"
    assert provider.last_request_bytes == b"secret request bytes"
    assert provider.attempt_count == 1


def test_result_shape_cannot_encode_a_synthetic_verdict() -> None:
    with pytest.raises(TypeError):
        ProviderResult("ALLOW", b"raw")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        ProviderResult(ProviderStatus.SUCCESS, None)
    with pytest.raises(ValueError):
        ProviderResult(ProviderStatus.PROVIDER_ERROR, b'{"decision":"ALLOW"}')


def test_adapter_imports_no_trusted_or_external_capabilities() -> None:
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "autodev_control"
        / "workplane"
        / "semantic_review_provider.py"
    )
    imports = set()
    for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            imports.add(node.module)
        elif isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
    assert imports == {"__future__", "dataclasses", "enum", "typing"}
