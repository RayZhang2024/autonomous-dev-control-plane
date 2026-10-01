"""Boundary tests for the fixture-only candidate producer."""

import ast
import builtins
import inspect
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
from unittest.mock import patch

import pytest

from autodev_control.workplane.candidate_producer import (
    CandidateProducer,
    CandidateProducerResult,
    CandidateProposal,
    ProducerStatus,
    ProposedChangeKind,
    ProposedFileChange,
    ScriptedCandidateProducer,
)


def test_protocol_uses_only_opaque_request_bytes() -> None:
    parameters = inspect.signature(CandidateProducer.invoke).parameters

    assert list(parameters) == ["self", "request_bytes"]
    assert parameters["request_bytes"].annotation in (bytes, "bytes")


def test_success_returns_exact_untrusted_proposal_and_metadata() -> None:
    request = b"\x00\xff opaque request"
    first = ProposedFileChange(
        ProposedChangeKind.ADD,
        "../../docs/CORE_POLICY.md",
        b"\x00untrusted\xff",
        "not-a-supported-mode",
    )
    deletion = ProposedFileChange(
        ProposedChangeKind.DELETE,
        "C:\\outside\\file",
        mode="also-unvalidated",
    )
    duplicate = ProposedFileChange(
        ProposedChangeKind.REPLACE,
        "../../docs/CORE_POLICY.md",
        b"replacement bytes",
        "0000;raw",
    )
    changes = (first, deletion, duplicate, first)
    proposal = CandidateProposal("not-a-git-sha", changes)
    metadata = {"worker": "unverified", "candidate": "untrusted"}
    scripted = CandidateProducerResult(
        ProducerStatus.SUCCESS, proposal, metadata
    )
    producer = ScriptedCandidateProducer(scripted)

    result = producer.invoke(request)

    assert producer.last_request_bytes is request
    assert producer.attempt_count == 1
    assert result is scripted
    assert result.candidate_proposal is proposal
    assert proposal.claimed_base_revision == "not-a-git-sha"
    assert proposal.changes is changes
    assert proposal.changes == (first, deletion, duplicate, first)
    assert proposal.changes[0].path == "../../docs/CORE_POLICY.md"
    assert proposal.changes[0].content_bytes == b"\x00untrusted\xff"
    assert proposal.changes[0].mode == "not-a-supported-mode"
    assert proposal.changes[1].path == "C:\\outside\\file"
    assert proposal.changes[1].mode == "also-unvalidated"
    assert proposal.changes[2].path == "../../docs/CORE_POLICY.md"
    assert proposal.changes[2].mode == "0000;raw"
    assert result.untrusted_metadata is metadata


@pytest.mark.parametrize(
    "status", [ProducerStatus.PRODUCER_ERROR, ProducerStatus.TIMEOUT]
)
def test_failure_outcomes_carry_no_proposal_or_metadata(
    status: ProducerStatus,
) -> None:
    scripted = CandidateProducerResult(status)
    producer = ScriptedCandidateProducer(scripted)

    result = producer.invoke(b"request")

    assert result is scripted
    assert result.status is status
    assert result.candidate_proposal is None
    assert result.untrusted_metadata is None
    assert producer.attempt_count == 1


def test_result_shape_rejects_missing_or_failure_proposals() -> None:
    with pytest.raises(TypeError):
        CandidateProducerResult(ProducerStatus.SUCCESS)
    with pytest.raises(ValueError):
        CandidateProducerResult(
            ProducerStatus.PRODUCER_ERROR,
            CandidateProposal("raw", ()),
        )
    with pytest.raises(ValueError):
        CandidateProducerResult(
            ProducerStatus.TIMEOUT,
            CandidateProposal("raw", ()),
        )
    with pytest.raises(ValueError):
        CandidateProducerResult(
            ProducerStatus.PRODUCER_ERROR,
            untrusted_metadata={"claimed": "success"},
        )


def test_proposal_checks_only_representation_and_variant_shape() -> None:
    with pytest.raises(ValueError):
        ProposedFileChange(ProposedChangeKind.ADD, "raw/path")
    with pytest.raises(ValueError):
        ProposedFileChange(
            ProposedChangeKind.DELETE, "raw/path", content_bytes=b"raw"
        )
    with pytest.raises(TypeError):
        CandidateProposal("raw", [ProposedFileChange(
            ProposedChangeKind.DELETE, "raw/path"
        )])  # type: ignore[arg-type]

    suspicious = CandidateProposal(
        "not-a-revision",
        (ProposedFileChange(ProposedChangeKind.DELETE, "../../outside"),),
    )
    assert suspicious.claimed_base_revision == "not-a-revision"
    assert suspicious.changes[0].path == "../../outside"


def test_one_invocation_has_no_retry_fallback_or_repair() -> None:
    scripted = CandidateProducerResult(ProducerStatus.PRODUCER_ERROR)
    producer = ScriptedCandidateProducer(scripted)

    assert producer.attempt_count == 0
    assert producer.invoke(b"first") is scripted
    assert producer.attempt_count == 1
    assert producer.invoke(b"second") is scripted
    assert producer.attempt_count == 2
    assert producer.last_request_bytes == b"second"
    assert scripted.candidate_proposal is None


def test_runtime_invocation_has_no_external_io_or_persistence() -> None:
    proposal = CandidateProposal("raw", ())
    producer = ScriptedCandidateProducer(
        CandidateProducerResult(ProducerStatus.SUCCESS, proposal)
    )
    forbidden = AssertionError("producer attempted external I/O")
    with (
        patch.object(socket, "socket", side_effect=forbidden),
        patch.object(socket, "create_connection", side_effect=forbidden),
        patch.object(subprocess, "Popen", side_effect=forbidden),
        patch.object(subprocess, "run", side_effect=forbidden),
        patch.object(os, "system", side_effect=forbidden),
        patch.object(os, "open", side_effect=forbidden),
        patch.object(builtins, "open", side_effect=forbidden),
        patch.object(Path, "open", side_effect=forbidden),
        patch.object(Path, "write_bytes", side_effect=forbidden),
        patch.object(Path, "write_text", side_effect=forbidden),
        patch.object(time, "sleep", side_effect=forbidden),
        patch.object(threading, "Thread", side_effect=forbidden),
    ):
        result = producer.invoke(b"candidate request")

    assert result.status is ProducerStatus.SUCCESS
    assert result.candidate_proposal is proposal
    assert producer.last_request_bytes == b"candidate request"
    assert producer.attempt_count == 1


def test_adapter_import_surface_has_no_protected_or_external_capabilities() -> None:
    source = Path(__file__).resolve().parents[2] / "src" / "autodev_control" / "workplane" / "candidate_producer.py"
    imports = set()
    for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            imports.add(node.module)
        elif isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)

    assert imports == {"__future__", "dataclasses", "enum", "typing"}
