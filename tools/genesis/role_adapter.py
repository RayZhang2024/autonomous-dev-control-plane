"""Explicit external-TCB per-role client for the fixture substrate service."""

from __future__ import annotations

import hashlib
import secrets
import threading
from typing import Mapping

from fixture_substrate import SubstrateTransportError, call_service


_ALLOWED = {
    "T": frozenset({"F_READ_VERIFY"}),
    "C": frozenset({"F_READ_VERIFY"}),
    "P": frozenset({"F_READ_VERIFY", "P_FENCE_READ", "PUBLICATION_PREPARE"}),
    "M": frozenset({"F_READ_VERIFY", "M_FENCE_READ", "MERGE_PREPARE"}),
}


class RoleSubstrateAdapter:
    """Hold one role's key and expose no cross-role/recovery/root operation."""

    __slots__ = ("_role", "_address", "_key", "_counter", "candidate_package_id",
                 "substrate_identity")

    def __init__(self, *, role: str, address: tuple[str, int], key: bytes,
                 candidate_package_id: str) -> None:
        if (role not in _ALLOWED or type(address) is not tuple or len(address) != 2
                or address[0] != "127.0.0.1" or type(address[1]) is not int
                or type(key) is not bytes or len(key) != 32
                or type(candidate_package_id) is not str or len(candidate_package_id) != 64
                or any(character not in "0123456789abcdef" for character in candidate_package_id)):
            raise ValueError("role adapter binding is not exact and closed")
        self._role, self._address, self._key = role, address, key
        self._counter = 0
        self.candidate_package_id = candidate_package_id
        self.substrate_identity = __import__(
            "autodev_control.trusted.identity", fromlist=["RawSha256"],
        ).RawSha256(hashlib.sha256(
            ("autodev.g9-substrate-binding/v1\0" + candidate_package_id
             + "\0" + address[0] + ":" + str(address[1])).encode("ascii")
        ).hexdigest())

    def _call(self, command: str, payload: dict[str, object]) -> dict[str, object]:
        if command not in _ALLOWED[self._role]:
            raise PermissionError("role adapter does not expose that endpoint")
        self._counter += 1
        request_id = f"{self._role}-{self._counter}"
        nonce = secrets.token_hex(16)
        return call_service(
            self._address, role=self._role, request_id=request_id, nonce=nonce,
            command=command, payload=payload, key=self._key,
        )

    def verify_resource(self, resource_id: str, expected_sha256: str) -> bool:
        result = self._call("F_READ_VERIFY", {
            "resource_id": resource_id, "expected_sha256": expected_sha256,
        })
        return result == {"verified": True, "resource_id": resource_id,
                          "candidate_package_id": self.candidate_package_id}

    def read_publication_fence(self) -> dict[str, object]:
        if self._role != "P":
            raise PermissionError("only P may read the publication target fence")
        return self._call("P_FENCE_READ", {})

    def read_merge_fence(self) -> dict[str, object]:
        if self._role != "M":
            raise PermissionError("only M may read the merge target fence")
        return self._call("M_FENCE_READ", {})

    def prepare_publication(self, effect_id: str, payload: bytes) -> dict[str, object]:
        if self._role != "P":
            raise PermissionError("only P may address PublicationAuthority")
        return self._call("PUBLICATION_PREPARE", {
            "effect_id": effect_id, "payload_sha256": hashlib.sha256(payload).hexdigest(),
        })

    def prepare_merge(self, effect_id: str, payload: bytes) -> dict[str, object]:
        if self._role != "M":
            raise PermissionError("only M may address MergeAuthority")
        return self._call("MERGE_PREPARE", {
            "effect_id": effect_id, "payload_sha256": hashlib.sha256(payload).hexdigest(),
        })

    # Candidate G1-G7 narrow F contract. The external service owns these
    # observations; this adapter deliberately has no mutation/recovery method.
    def verify_prepared_target_fence(self, binding: object) -> bool:
        return False

    def verify_start_held_target_fence(self, binding: object) -> bool:
        return False

    def resolve_historical_start_binding(self, binding: object) -> bool:
        return False

    def prepared_target_fence_binding(self, operation_id: object, action_class: str):
        return None

    def authoritative_snapshot(self, repository_id: object, profile_id: object,
                               transport_id: object):
        return None

    def authoritative_facts(self, repository_id: object, profile_id: object,
                            transport_id: object):
        return None

    def authoritative_binding(self, repository_id: object, profile_id: object,
                              transport_id: object):
        return None

    def read_prepared_effect_record(self, operation_id: object, action_class: str):
        return None

    def read_prepared_effect_state(self, operation_id: object, action_class: str):
        return None

    def read_ref(self, repository_id: object, ref: object):
        return None

    def read_marker(self, operation_id: object, action_class: str):
        return None

    def read_pull_request(self, number: object):
        return None

    def read_next_pull_request_number(self) -> int:
        return 0

    def verify_materialization(self, materialization: object) -> bool:
        return False

    def verify_marker_postcondition(self, marker: object) -> bool:
        return False


def role_capability_surface(role: str) -> tuple[str, ...]:
    if role not in _ALLOWED:
        raise ValueError("unknown candidate role")
    return tuple(sorted(_ALLOWED[role]))


class _AuditSink:
    """Non-persistent audit sink used only to construct the fenced rehearsal roles."""

    def append_event(self, event: object):
        from autodev_control.trusted.audit import AuditAppendStatus

        return AuditAppendStatus.REJECTED


class _Registry:
    """One-process-only role liveness registry; never shared across principals."""

    __slots__ = ("_lock", "_active")

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._active: set[tuple[object, int, str, int]] = set()

    @property
    def lock(self):
        return self._lock

    def activate_local(self, root: object, generation: int, role: str, owner: object) -> None:
        self._active.add((root, generation, role, id(owner)))

    def is_role_active(self, root: object, generation: int, role: str, owner: object) -> bool:
        return (root, generation, role, id(owner)) in self._active

    def acquire(self, owner: object, facts: frozenset[tuple]):
        return None

    def release(self, handle: object) -> None:
        return None


class _CallerVerifier:
    def verify(self, request_digest: object, caller_context: object = None) -> bool:
        return False


class _RoleFence:
    __slots__ = ("_adapter", "_role")

    def __init__(self, adapter: RoleSubstrateAdapter, role: str) -> None:
        self._adapter, self._role = adapter, role

    def is_active(self) -> bool:
        if self._role == "P":
            record = self._adapter.read_publication_fence()
        else:
            record = self._adapter.read_merge_fence()
        return record == {"fence": "RELEASED", "revision": 1,
                          "candidate_package_id": self._adapter.candidate_package_id}

    def acquire(self, facts: frozenset[tuple]):
        return None

    def release(self, token: object) -> None:
        return None


class _PublicationAuthority:
    """P-only authority shim. The external substrate rejects all effects FENCED."""

    __slots__ = ("_adapter",)

    def __init__(self, adapter: RoleSubstrateAdapter) -> None:
        self._adapter = adapter

    def binding_identity(self, service_identity, root_context_id, runtime_generation,
                         runtime_binding_id):
        from autodev_control.trusted.identity import RawSha256

        return RawSha256(hashlib.sha256(repr((service_identity, root_context_id,
                                             runtime_generation, runtime_binding_id)).encode()).hexdigest())

    def prepare_publication(self, prepared, fence_token) -> bool:
        result = self._adapter.prepare_publication("stage-b-probe", b"fenced")
        return result == {"accepted": True,
                          "candidate_package_id": self._adapter.candidate_package_id}

    def abort_prepared_publication(self, operation_id, action_class, fence_token=None) -> bool:
        return False

    def seal_publication_for_start(self, operation_id, action_class, prepared,
                                   authority_binding_identity):
        return None

    def execute_candidate_ref_publication(self, repository_id, ref, sha, marker,
                                         *, fence_token=None) -> bool:
        return False

    def execute_candidate_pr_creation(self, repository_id, head, base, head_sha, marker,
                                       *, fence_token=None):
        return None


class _MergeAuthority:
    """M-only authority shim. The external substrate rejects all effects FENCED."""

    __slots__ = ("_adapter",)

    def __init__(self, adapter: RoleSubstrateAdapter) -> None:
        self._adapter = adapter

    def binding_identity(self, service_identity, root_context_id, runtime_generation,
                         runtime_binding_id):
        from autodev_control.trusted.identity import RawSha256

        return RawSha256(hashlib.sha256(repr((service_identity, root_context_id,
                                             runtime_generation, runtime_binding_id)).encode()).hexdigest())

    def prepare_merge(self, prepared, fence_token) -> bool:
        result = self._adapter.prepare_merge("stage-b-probe", b"fenced")
        return result == {"accepted": True,
                          "candidate_package_id": self._adapter.candidate_package_id}

    def abort_prepared_merge(self, operation_id, action_class, fence_token=None) -> bool:
        return False

    def seal_merge_for_start(self, operation_id, action_class, prepared,
                             authority_binding_identity):
        return None

    def execute_fast_forward_merge(self, repository_id, target, expected, candidate,
                                   candidate_parent, pull_request_number, marker,
                                   *, fence_token=None) -> bool:
        return False


def construct_candidate_runtime(*, role: str, candidate_package_id: str,
                                substrate_adapter: RoleSubstrateAdapter,
                                runtime_run_id: str) -> dict[str, object]:
    """Construct one real G1-G7 role from its own process-local closed inputs.

    No object is shared across T/C/P/M processes. Every adapter is deliberately
    fail-closed; this rehearsal constructs and checks the frozen role surface
    while the external P/M fences remain FENCED.
    """
    from autodev_control.trusted.backend import InMemoryCanonicalStateBackend
    from autodev_control.trusted.identity import RawSha256, RootContextId
    from autodev_control.trusted.scope import ServicePrincipalId
    from autodev_control.trusted.runtime_roles import (
        ControlStateGateRuntime, FixtureRuntimeGeneration, GateRuntimeBinding,
        MergeGateRuntime, PublicationGateRuntime, TrustedControllerRuntime,
    )
    from autodev_control.trusted.runtime_authority import RuntimeSecurityContext, TrustedRuntimeRole

    if role not in _ALLOWED or substrate_adapter._role != role:
        raise ValueError("candidate role and dedicated substrate adapter differ")
    if (len(candidate_package_id) != 64 or len(runtime_run_id) != 64
            or any(ch not in "0123456789abcdef" for ch in candidate_package_id + runtime_run_id)):
        raise ValueError("candidate runtime identity is malformed")
    root_digest = hashlib.sha256(("autodev.g9-stage-b-root/v1\0" + candidate_package_id).encode()).hexdigest()
    nonce_digest = hashlib.sha256(("autodev.g9-stage-b-run/v1\0" + runtime_run_id).encode()).hexdigest()
    root_context = RootContextId(RawSha256(root_digest))
    generation = FixtureRuntimeGeneration(1)
    principals = {
        key: ServicePrincipalId("windows-role:" + key + ":" + value)
        for key, value in {"T": "S-1-5-21-711519901-190585334-3846127459-1016",
                           "C": "S-1-5-21-711519901-190585334-3846127459-1017",
                           "P": "S-1-5-21-711519901-190585334-3846127459-1018",
                           "M": "S-1-5-21-711519901-190585334-3846127459-1019"}.items()
    }
    binding = GateRuntimeBinding(root_context, generation, principals["C"], principals["P"],
                                 principals["M"], RawSha256(nonce_digest))
    contexts = {
        name: RuntimeSecurityContext(runtime_role, principals[service_role], root_context,
                                     generation.value, binding.runtime_binding_id)
        for name, runtime_role, service_role in (
            ("T", TrustedRuntimeRole.CONTROLLER, "T"),
            ("C", TrustedRuntimeRole.CONTROL_STATE_GATE, "C"),
            ("P", TrustedRuntimeRole.PUBLICATION_GATE, "P"),
            ("M", TrustedRuntimeRole.MERGE_GATE, "M"),
        )
    }
    backend = InMemoryCanonicalStateBackend()
    read_client = backend.read_client()
    audit = _AuditSink()
    registry = _Registry()
    runtime_identity = object()
    registry.activate_local(root_context, generation.value, "C", runtime_identity)

    if role == "T":
        import autodev_control.trusted.runtime_roles as runtime_module

        controller = runtime_module._new_controller(object(), read_client, {}, None)
        runtime = TrustedControllerRuntime(
            controller, read_client, substrate_adapter, {}, {}, {}, {}, {}, {},
            None, binding, audit,
        )
        constructed_type = "TrustedControllerRuntime"
        active = True
        canonical_occurrence = read_client.occurrence
    elif role == "C":
        runtime = ControlStateGateRuntime(
            binding, backend, audit, registry, object(), runtime_identity,
            contexts["T"], contexts["C"], object(), substrate_adapter, {}, {},
        )
        constructed_type = "ControlStateGateRuntime"
        active = runtime._is_active()
        canonical_occurrence = backend.occurrence
    elif role == "P":
        runtime = PublicationGateRuntime(
            binding, read_client, audit, object(), object(), contexts["T"], contexts["P"],
            _CallerVerifier(), substrate_adapter, _PublicationAuthority(substrate_adapter),
            _RoleFence(substrate_adapter, role), {}, {},
        )
        constructed_type = "PublicationGateRuntime"
        active = runtime._is_active()
        canonical_occurrence = read_client.occurrence
    else:
        runtime = MergeGateRuntime(
            binding, read_client, audit, object(), object(), contexts["T"], contexts["M"],
            _CallerVerifier(), substrate_adapter, _MergeAuthority(substrate_adapter),
            _RoleFence(substrate_adapter, role), {}, {},
        )
        constructed_type = "MergeGateRuntime"
        active = runtime._is_active()
        canonical_occurrence = read_client.occurrence
    role_fence = None
    fenced_effect_probe = None
    if role == "P":
        role_fence = substrate_adapter.read_publication_fence()
        fenced_effect_probe = runtime.authority_client.prepare_publication(None, None)
    elif role == "M":
        role_fence = substrate_adapter.read_merge_fence()
        fenced_effect_probe = runtime.authority_client.prepare_merge(None, None)
    identity = hashlib.sha256((
        "autodev.g9-realized-candidate-role/v1\0" + candidate_package_id + "\0"
        + runtime_run_id + "\0" + role + "\0" + constructed_type + "\0"
        + binding.runtime_binding_id.raw_sha256.value
    ).encode("ascii")).hexdigest()
    return {
        "role": role, "runtime_type": constructed_type,
        "runtime_role_identity": identity,
        "runtime_binding_id": binding.runtime_binding_id.raw_sha256.value,
        "runtime_active": bool(active),
        "canonical_occurrence_identity": hashlib.sha256(
            repr(canonical_occurrence).encode("utf-8")
        ).hexdigest(),
        "protected_fence": role_fence,
        "fenced_effect_probe_accepted": fenced_effect_probe,
        "independent_process_local_composition": True,
    }
