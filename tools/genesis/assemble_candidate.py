"""Deterministically assemble and locally validate a non-authoritative G9 package."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from types import MappingProxyType
from typing import Mapping

from autodev_control.trusted.errors import GenesisResourceGraphFailure
from autodev_control.trusted.genesis_resource_graph import (
    GENESIS_RESOURCE_GRAPH_CONFIG_ID,
    validate_genesis_resource_graph,
)
from autodev_control.trusted.manifest import CandidateTrustedManifest, load_candidate_trusted_manifest

from build_definition import (
    APPLICATION_BASE,
    R2_EXECUTABLE_BASE,
    BuiltArtifacts,
    RUNTIME_MEMBERS,
    build_from_git,
    canonical_json_bytes,
    deterministic_archive,
    sha256,
)
from external_profiles import (
    validate_fixture_substrate_profile,
    validate_root_fence_profile,
    derive_execution_isolation_dependency_id,
    derive_root_anchor_id,
    EXECUTION_ISOLATION_DOMAIN as _EXECUTION_ISOLATION_DOMAIN,
    EXECUTION_ISOLATION_PROFILE_FIELDS as _EXECUTION_ISOLATION_PROFILE_FIELDS,
)

_ROLES = ("T", "C", "P", "M")
_EXCLUSIONS = tuple(sorted((
    "tests/**",
    "src/autodev_control/trusted/gates.py",
    "src/autodev_control/trusted/fixture_audit.py",
    "src/autodev_control/trusted/fixture_capabilities.py",
    "src/autodev_control/trusted/fixture_transport.py",
    "src/autodev_control/trusted/fixture_platform.py",
)))
_FIXTURE_BINDINGS = {
    "f_read_verify_binding": "endpoint-f-read",
    "f_read_verify_mode": "READ_ONLY",
    "publication_authority_binding": "endpoint-publication",
    "merge_authority_binding": "endpoint-merge",
    "external_recovery_binding": "endpoint-external-recovery",
    "p_target_fence_binding": "endpoint-p-fence",
    "m_target_fence_binding": "endpoint-m-fence",
    "target_fence_namespace": "namespace-target-fence",
}
_SCHEMA_PATHS = (
    "schemas/issue-contract.schema.json",
    "schemas/review-verdict.schema.json",
)
_POLICY_PATHS = (
    "docs/ARCHITECTURE.md",
    "docs/STATE_MACHINE.md",
    "docs/REVIEW_MODEL.md",
    "docs/SELF_MODIFICATION.md",
    "docs/GENESIS_CONFORMANCE.md",
)
_R3_GIT_BLOB = "30d4efcaa2adb38acbc0df5635c3bcba4710fa18"
_R3_RAW_SHA256 = "36498b5d51227a553d452ee21d3fbc61aed7483dc9304939befddb2651acfd35"
_R3_BYTE_LENGTH = 41155
_STAGED_PYTHON_PATH = r"C:\AutodevG9\shared\python313\python.exe"
_STAGED_PYTHON_SHA256 = "081786173866d86cda1b06aa671848217fa0d635edb6dcd2218644466f4229cd"
_ROLE_PRINCIPALS = (
    {"role": "T", "account": r"Ray\autodev-g9-t", "sid": "S-1-5-21-711519901-190585334-3846127459-1016",
     "token_type": "PRIMARY", "administrator": False},
    {"role": "C", "account": r"Ray\autodev-g9-c", "sid": "S-1-5-21-711519901-190585334-3846127459-1017",
     "token_type": "PRIMARY", "administrator": False},
    {"role": "P", "account": r"Ray\autodev-g9-p", "sid": "S-1-5-21-711519901-190585334-3846127459-1018",
     "token_type": "PRIMARY", "administrator": False},
    {"role": "M", "account": r"Ray\autodev-g9-m", "sid": "S-1-5-21-711519901-190585334-3846127459-1019",
     "token_type": "PRIMARY", "administrator": False},
)
def _make_execution_isolation_profile(
    external_tcb_material: list[dict[str, str]],
) -> dict[str, object]:
    """Return the closed, non-candidate profile evidenced by the realized Windows run."""
    by_path = {item["path"]: item["sha256"] for item in external_tcb_material}
    if set(by_path) != {
        "tools/genesis/ipc.py", "tools/genesis/role_worker.py",
        "tools/genesis/windows_role_launcher.py", "tools/genesis/windows_role_runner.py",
        "tools/genesis/role_adapter.py", "tools/genesis/substrate_client.py",
        "tools/genesis/canonical_state_channel.py",
    }:
        raise ValueError("execution-isolation adapter material is not the exact seven-file set")
    return {
        "format": "autodev.g9-execution-isolation-profile/v1",
        "host_profile": {
            "profile_id": "autodev.g9.windows-dedicated-principals/v1",
            "platform": "Windows",
            "architecture": "AMD64",
            "domain": "Ray",
        },
        "role_principals": [dict(item) for item in _ROLE_PRINCIPALS],
        "python_runtime": {
            "identity": "CPython",
            "version": "3.13.14",
            "path": _STAGED_PYTHON_PATH,
            "sha256": _STAGED_PYTHON_SHA256,
        },
        "staging_profile": {
            "profile_id": "autodev.g9.protected-staging-acl/v1",
            "root": r"C:\AutodevG9",
            "shared_role_access": "RX",
            "shared_operator_administrator_system_access": "F",
            "private_role_access": "owner-only-M;other-role-absent;inheritance-disabled",
            "root_store_role_access": "DENY",
            "external_fence_release": "DENY",
        },
        "channel_profile": {
            "profile_id": "autodev.g9.t-to-cpm-role-bound-channels/v1",
            "format": "autodev.genesis-ipc/v1",
            "directions": ["T->C", "T->P", "T->M"],
            "destination_credentials": "ROLE_LOCAL_ONLY",
            "controller_destination_credentials": "NONE",
            "cross_role_messages": "REJECT",
        },
        "external_adapter_material": [
            {"path": item["path"], "sha256": item["sha256"]}
            for item in sorted(external_tcb_material, key=lambda value: value["path"])
        ],
        "role_interpreter_modules": [
            {"module_name": "ipc", "execution": "IMPORTED",
             "path": "tools/genesis/ipc.py", "sha256": by_path["tools/genesis/ipc.py"]},
            {"module_name": "role_worker", "execution": "SCRIPT",
             "path": "tools/genesis/role_worker.py", "sha256": by_path["tools/genesis/role_worker.py"]},
            {"module_name": "role_adapter", "execution": "IMPORTED",
             "path": "tools/genesis/role_adapter.py", "sha256": by_path["tools/genesis/role_adapter.py"]},
            {"module_name": "substrate_client", "execution": "IMPORTED",
             "path": "tools/genesis/substrate_client.py", "sha256": by_path["tools/genesis/substrate_client.py"]},
            {"module_name": "canonical_state_channel", "execution": "IMPORTED",
             "path": "tools/genesis/canonical_state_channel.py",
             "sha256": by_path["tools/genesis/canonical_state_channel.py"]},
        ],
        "production_github_mutation_credentials": "NONE",
    }


def _derive_execution_isolation_dependency_id(profile: dict[str, object]) -> str:
    """Compatibility spelling for the shared bound profile verifier."""
    return derive_execution_isolation_dependency_id(profile)


def _manifest_external_tcb_dependencies(graph: dict[str, object]) -> list[dict[str, str]]:
    """Mirror the exact graph dependency identities into the outer manifest."""
    return [
        {"dependency_id": item["dependency_id"], "assumption_resource": item["assumption_resource"]}
        for item in graph["external_tcb_roles"]
    ]


@dataclass(frozen=True, slots=True)
class CandidatePackage:
    source_bundle: bytes
    runtime_artifact: bytes
    build_definition: bytes
    dependency_lock: bytes
    graph: bytes
    manifest: bytes
    raw_resources: Mapping[str, bytes]
    deterministic_evidence: bytes
    deterministic_evidence_id: str
    candidate_package: bytes
    candidate_package_id: str
    manifest_id: str
    runtime_sha256: str
    source_bundle_sha256: str
    build_definition_sha256: str
    dependency_lock_sha256: str


def _json(value: object) -> bytes:
    return canonical_json_bytes(value)


def _resource_id(label: str, raw: bytes) -> str:
    return f"{label}-{sha256(raw)[:24]}"


def _write_entry(role: str, runtime_id: str) -> dict[str, str]:
    return {
        "format": "autodev.genesis-entry-point/v1",
        "role": role,
        "member_id": role,
        "runtime_artifact_resource": runtime_id,
        "module": "autodev_control.trusted.runtime_roles",
        "callable": {
            "T": "TrustedControllerRuntime",
            "C": "ControlStateGateRuntime",
            "P": "PublicationGateRuntime",
            "M": "MergeGateRuntime",
        }[role],
    }


def _make_graph_resources(
    runtime_id: str, execution_isolation_dependency_id: str,
    root_fence_dependency_id: str = "dep-root-activation-fence-test",
    fixture_substrate_dependency_id: str = "dep-fixture-effect-substrate-test",
    fixture_bindings: dict[str, str] | None = None,
) -> tuple[dict[str, bytes], dict[str, str], dict[str, object]]:
    bindings = _FIXTURE_BINDINGS if fixture_bindings is None else fixture_bindings
    raw: dict[str, bytes] = {}
    kinds: dict[str, str] = {}
    members: list[dict[str, str]] = []
    configs: list[dict[str, object]] = []
    entries: dict[str, dict[str, object]] = {}
    security: dict[str, dict[str, object]] = {}
    wiring: dict[str, dict[str, object]] = {}
    credential: dict[str, dict[str, object]] = {}

    implementation_id = "implementation"
    build_id = "build"
    lock_id = "lock"
    module_policy_id = "module-policy"
    graph_id = "graph"
    core_id = "core"
    conformance_id = "conformance"
    for resource_id, kind in (
        (implementation_id, "TRUSTED_CODE"), (build_id, "BUILD_DEFINITION"),
        (runtime_id, "RUNTIME_ARTIFACT"), (lock_id, "DEPENDENCY_LOCK"),
        (module_policy_id, "MODULE_LOADING_POLICY"), (graph_id, "TRUSTED_CONFIG"),
        (core_id, "CORE_POLICY"),
    ):
        kinds[resource_id] = kind

    channel_values: dict[str, dict[str, str]] = {}
    for destination in ("C", "P", "M"):
        channel_values[destination] = {
            "channel_id": f"authenticated-t-to-{destination.lower()}",
            "source_role": "T", "source_member_id": "T",
            "source_context_resource": "security-T",
            "destination_role": destination, "destination_member_id": destination,
            "destination_context_resource": f"security-{destination}",
            "root_context_binding": "root-context-candidate",
            "runtime_generation_binding": "runtime-generation-candidate",
            "source_runtime_binding": "runtime-binding-T",
            "destination_runtime_binding": f"runtime-binding-{destination}",
            "authenticated_channel_binding": f"channel-binding-{destination.lower()}",
            "verifier_binding": f"verifier-binding-{destination.lower()}",
        }

    for role in _ROLES:
        entry_id, security_id, wiring_id, credential_id = (
            f"entry-{role}", f"security-{role}", f"wiring-{role}", f"credential-{role}"
        )
        for resource_id, kind in (
            (entry_id, "ENTRY_POINT_CONFIG"),
            (security_id, "SECURITY_CONTEXT_CONFIG"),
            (wiring_id, "CAPABILITY_WIRING"),
            (credential_id, "CREDENTIAL_ROUTING"),
        ):
            kinds[resource_id] = kind
        principal = f"service-{role}-candidate"
        members.append({
            "role": role, "member_id": role, "service_principal": principal,
            "implementation_resource": implementation_id,
            "runtime_artifact_resource": runtime_id,
            "entry_point_config_resource": entry_id,
            "security_context_config_resource": security_id,
            "capability_wiring_resource": wiring_id,
            "credential_routing_resource": credential_id,
        })
        entries[entry_id] = _write_entry(role, runtime_id)
        incoming = [channel_values[role]] if role in channel_values else []
        security[security_id] = {
            "format": "autodev.genesis-security-context/v1",
            "role": role,
            "member_id": role,
            "context_id": security_id,
            "service_principal": principal,
            "runtime_binding": f"runtime-binding-{role}",
            "runtime_generation_binding": "runtime-generation-candidate",
            "root_context_binding": "root-context-candidate",
            "external_isolation_dependency_id": execution_isolation_dependency_id,
            "channels": [channel_values[item] for item in ("C", "P", "M")] if role == "T" else incoming,
        }
        access = {"T": "READ", "C": "READ_WRITE", "P": "READ", "M": "READ"}[role]
        state_binding = {
            "T": "endpoint-t-state-read", "C": "endpoint-c-state-writer",
            "P": "endpoint-c-state-read", "M": "endpoint-c-state-read",
        }[role]
        wiring[wiring_id] = {
            "format": "autodev.genesis-capability-wiring/v1",
            "role": role,
            "member_id": role,
            "canonical_state_access": access,
            "canonical_state_binding": state_binding,
            "f_read_verify_binding": bindings["f_read_verify_binding"],
            "target_fence_binding": {"T": "NONE", "C": "NONE", "P": bindings["p_target_fence_binding"], "M": bindings["m_target_fence_binding"]}[role],
            "publication_authority_binding": bindings["publication_authority_binding"] if role == "P" else "NONE",
            "merge_authority_binding": bindings["merge_authority_binding"] if role == "M" else "NONE",
            "external_recovery_binding": "NONE",
        }
        credential[credential_id] = {
            "format": "autodev.genesis-credential-routing/v1",
            "role": role,
            "member_id": role,
            "production_github_mutation_credentials": "NONE",
        }
    external = (
        ("ROOT_ACTIVATION_FENCE", root_fence_dependency_id, "assumption-root-fence"),
        ("EXECUTION_ISOLATION", execution_isolation_dependency_id, "assumption-execution-isolation"),
        ("FIXTURE_EFFECT_SUBSTRATE", fixture_substrate_dependency_id, "assumption-fixture-effects"),
    )
    external_roles: list[dict[str, object]] = []
    for role, dependency_id, assumption_id in external:
        kinds[assumption_id] = "EXTERNAL_TCB_ASSUMPTION_DOCUMENT"
        assumption = {"format": "autodev.genesis-external-tcb-assumption/v1",
                      "role": role, "dependency_id": dependency_id}
        graph_record: dict[str, object] = {
            "role": role, "dependency_id": dependency_id, "assumption_resource": assumption_id,
        }
        if role == "FIXTURE_EFFECT_SUBSTRATE":
            assumption["bindings"] = bindings
            graph_record["bindings"] = bindings
        raw[assumption_id] = _json(assumption)
        external_roles.append(graph_record)

    raw["entry-placeholder"] = b""  # removed after all deterministic config identifiers are fixed
    raw.pop("entry-placeholder")
    for category in (entries, security, wiring, credential):
        raw.update({resource_id: _json(value) for resource_id, value in category.items()})
    for resource_id, kind in ((graph_id, "TRUSTED_CONFIG"), (module_policy_id, "MODULE_LOADING_POLICY")):
        kinds[resource_id] = kind
    module_policy = {
        "format": "autodev.genesis-module-loading-policy/v1",
        "allowed_candidate_modules": list(sorted(RUNTIME_MEMBERS)),
        "explicitly_excluded_modules_or_prefixes": list(_EXCLUSIONS),
        "third_party_runtime_policy": {
            "standard_library_policy": "ALLOW",
            "third_party_module_allowlist": [
                "canonical_state_channel", "ipc", "role_adapter", "role_worker", "substrate_client",
            ],
        },
        "dynamic_import_fallback": "NONE",
    }
    raw[module_policy_id] = _json(module_policy)
    configs.insert(0, {
        "config_id": GENESIS_RESOURCE_GRAPH_CONFIG_ID,
        "resource_id": graph_id,
        "purpose": "GENESIS_RESOURCE_GRAPH",
        "expected_format": "autodev.genesis-resource-graph/v1",
        "schema_resource": None,
        "grammar_id": "autodev.genesis-resource-graph/v1",
    })
    policy_ids = ["policy-architecture", "policy-state-machine", "policy-review-model",
                  "policy-self-modification", "conformance"]
    schema_ids = ["schema-issue-contract", "schema-review-verdict"]
    graph: dict[str, object] = {
        "format": "autodev.genesis-resource-graph/v1",
        "genesis_scope": "fixture-only",
        "implementation_resource": implementation_id,
        "build_definition_resource": build_id,
        "dependency_lock_resource": lock_id,
        "runtime_artifact_resource": runtime_id,
        "module_loading_policy_resource": module_policy_id,
        "core_policy_resource": core_id,
        "genesis_conformance_resource": "conformance",
        "members": members,
        "policy_resources": policy_ids,
        "trusted_schema_resources": schema_ids,
        "trusted_config_bindings": configs,
        "external_tcb_roles": external_roles,
    }
    return raw, kinds, graph


def assemble_candidate(
    *, git_cwd: str = ".", root_fence_profile: dict[str, object] | None = None,
    fixture_substrate_profile: dict[str, object] | None = None,
    root_anchor_id: str | None = None,
) -> CandidatePackage:
    """Build twice from the authorized Git object and return the same byte image."""
    if root_fence_profile is None or fixture_substrate_profile is None or root_anchor_id is None:
        raise RuntimeError(
            "external root-admin and dedicated substrate host identities are required; "
            "final CP2 cannot be assembled from guessed/default principals"
        )
    root_fence_dependency_id = validate_root_fence_profile(root_fence_profile)
    fixture_substrate_dependency_id = validate_fixture_substrate_profile(fixture_substrate_profile)
    anchor_preimage = {
        "repository": root_fence_profile["repository"],
        "root_store_profile": root_fence_profile["root_store_profile_id"],
        "design_lineage": root_fence_profile["design_lineage"],
        "namespace": root_fence_profile["root_anchor_namespace"],
    }
    if root_anchor_id != derive_root_anchor_id(anchor_preimage):
        raise ValueError("root anchor identity differs from the frozen exact preimage")
    if root_fence_profile["root_anchor_namespace"] != anchor_preimage["namespace"]:
        raise ValueError("root-fence profile and anchor namespace do not match")
    bindings = {
        "f_read_verify_binding": fixture_substrate_profile["f_read_verify_endpoint"]["endpoint_id"],
        "f_read_verify_mode": "READ_ONLY",
        "publication_authority_binding": fixture_substrate_profile["publication_authority_endpoint"]["endpoint_id"],
        "merge_authority_binding": fixture_substrate_profile["merge_authority_endpoint"]["endpoint_id"],
        "external_recovery_binding": fixture_substrate_profile["external_recovery_endpoint"]["endpoint_id"],
        "p_target_fence_binding": fixture_substrate_profile["p_target_fence"]["endpoint_id"],
        "m_target_fence_binding": fixture_substrate_profile["m_target_fence"]["endpoint_id"],
        "target_fence_namespace": fixture_substrate_profile["target_fence_namespace"],
    }
    if root_fence_profile["root_admin_principal"]["sid"] == fixture_substrate_profile["service_principal"]["sid"]:
        raise ValueError("root administrator and substrate service principal must be distinct")
    first = build_from_git(git_cwd=git_cwd)
    second = build_from_git(git_cwd=git_cwd)
    if first != second:
        raise RuntimeError("independent deterministic builds differ")
    all_external_tcb_material = [
        {"path": f"tools/genesis/{name}",
         "sha256": sha256(Path(__file__).with_name(name).read_bytes())}
        for name in (
            "external_profiles.py", "root_admin.py", "fence_controller.py",
            "genesis_provenance.py", "post_merge_binding.py",
            "fixture_substrate.py", "role_adapter.py", "substrate_client.py",
            "canonical_state_channel.py",
            "windows_substrate_launcher.py",
            "ipc.py", "role_worker.py", "windows_role_launcher.py", "windows_role_runner.py",
        )
    ]
    all_external_tcb_material.sort(key=lambda item: item["path"])
    execution_isolation_material = [
        item for item in all_external_tcb_material if item["path"] in {
            "tools/genesis/ipc.py", "tools/genesis/role_worker.py",
            "tools/genesis/windows_role_launcher.py", "tools/genesis/windows_role_runner.py",
            "tools/genesis/role_adapter.py", "tools/genesis/substrate_client.py",
            "tools/genesis/canonical_state_channel.py",
        }
    ]
    execution_isolation_profile = _make_execution_isolation_profile(execution_isolation_material)
    execution_isolation_dependency_id = _derive_execution_isolation_dependency_id(
        execution_isolation_profile
    )
    build_definition = _json({
        "format": "autodev.genesis-build-definition/v1",
        "repository_application_base": APPLICATION_BASE,
        "r2_executable_baseline": R2_EXECUTABLE_BASE,
        "execution_isolation_dependency_id": execution_isolation_dependency_id,
        "root_fence_dependency_id": root_fence_dependency_id,
        "root_fence_profile": root_fence_profile,
        "fixture_substrate_dependency_id": fixture_substrate_dependency_id,
        "fixture_substrate_profile": fixture_substrate_profile,
        "root_anchor_id": root_anchor_id,
        "execution_isolation_profile": execution_isolation_profile,
        "build_tool": {
            "path": "tools/genesis/build_definition.py",
            "sha256": sha256((Path(__file__).with_name("build_definition.py")).read_bytes()),
        },
        "assembler": {
            "path": "tools/genesis/assemble_candidate.py",
            "sha256": sha256(Path(__file__).read_bytes()),
        },
        "external_tcb_material": all_external_tcb_material,
        "python_runtime": {
            "identity": "CPython", "version": platform.python_version(),
            "executable_sha256": sha256(Path(sys.executable).read_bytes()),
        },
        "runtime_member_count": 26,
        "source_to_runtime_mapping": [
            {"source": source, "runtime": runtime}
            for source, runtime in zip(
                __import__("build_definition").SOURCE_MEMBERS, RUNTIME_MEMBERS, strict=True
            )
        ],
        "archive": {"format": "ZIP", "compression": "STORED", "timestamp": "1980-01-01T00:00:00Z",
                    "member_order": "lexicographic", "mode": "0444"},
        "source_bundle_sha256": sha256(first.source_bundle),
        "runtime_artifact_sha256": sha256(first.runtime_artifact),
    })
    runtime_id = "runtime"
    raw, kinds, graph = _make_graph_resources(
        runtime_id, execution_isolation_dependency_id,
        root_fence_dependency_id, fixture_substrate_dependency_id, bindings,
    )
    conformance = _git_blob(APPLICATION_BASE, "docs/GENESIS_CONFORMANCE.md", git_cwd)
    conformance_blob = subprocess.run(
        ["git", "hash-object", "--stdin"], cwd=git_cwd, input=conformance,
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout.decode("ascii").strip()
    if (conformance_blob != _R3_GIT_BLOB or len(conformance) != _R3_BYTE_LENGTH
            or sha256(conformance) != _R3_RAW_SHA256):
        raise RuntimeError("current R3 resource does not match frozen v0.4 identity")
    raw.update({"implementation": first.source_bundle, "runtime": first.runtime_artifact,
                "build": build_definition,
                "core": _git_blob(APPLICATION_BASE, "docs/CORE_POLICY.md", git_cwd),
                "conformance": conformance})
    for path, resource_id in zip(_POLICY_PATHS[:4], (
        "policy-architecture", "policy-state-machine", "policy-review-model", "policy-self-modification"
    ), strict=True):
        raw[resource_id] = _git_blob(APPLICATION_BASE, path, git_cwd)
        kinds[resource_id] = "POLICY"
    for path, resource_id in zip(_SCHEMA_PATHS, ("schema-issue-contract", "schema-review-verdict"), strict=True):
        raw[resource_id] = _git_blob(APPLICATION_BASE, path, git_cwd)
        kinds[resource_id] = "TRUSTED_SCHEMA"
    kinds.update({"conformance": "POLICY", "core": "CORE_POLICY", "implementation": "TRUSTED_CODE",
                  "runtime": "RUNTIME_ARTIFACT", "build": "BUILD_DEFINITION"})

    # The lock binds the exact resource bytes and records the empty runtime dependency set.
    python_digest = sha256(Path(sys.executable).read_bytes())
    build_tools = sorted([
        {"name": "g9-source-runtime-builder", "version": "0.3.0",
         "sha256": sha256(Path(__file__).with_name("build_definition.py").read_bytes())},
        {"name": "g9-candidate-assembler", "version": "0.3.0",
         "sha256": sha256(Path(__file__).read_bytes())},
    ], key=lambda item: item["name"])
    lock = _json({
        "format": "autodev.genesis-dependency-lock/v1",
        "python_runtime": {"identity": "CPython", "version": platform.python_version(),
                           "sha256": python_digest},
        "build_backend": {"name": "python-stdlib", "version": platform.python_version(),
                          "sha256": python_digest},
        "build_tools": build_tools,
        "runtime_dependencies": [],
        "locked_resources": [
            {"role": role, "resource_id": resource_id, "sha256": sha256(value)}
            for role, resource_id, value in (
                ("IMPLEMENTATION", "implementation", raw["implementation"]),
                ("BUILD_DEFINITION", "build", build_definition),
                ("RUNTIME_ARTIFACT", "runtime", raw["runtime"]),
            )
        ],
    })
    raw["lock"] = lock
    kinds["lock"] = "DEPENDENCY_LOCK"
    graph_raw = _json(graph)
    raw["graph"] = graph_raw

    # Bind actual resource hashes only after all resource bytes are finalized.
    manifest_data = {
        "format": "autodev.trusted-manifest/v1", "kind": "genesis", "predecessor_manifest": None,
        "root_managed_resources": [
            {"resource_id": rid, "kind": kind, "sha256": sha256(raw[rid])}
            for rid, kind in sorted(kinds.items())
        ],
        "core_policy": "core",
        "policy_resources": ["policy-architecture", "policy-state-machine", "policy-review-model",
                              "policy-self-modification", "conformance"],
        "trusted_core_members": [
            {"member_id": role, "implementation_resource": "implementation",
             "runtime_artifact_resource": "runtime", "entry_point_config_resource": f"entry-{role}"}
            for role in _ROLES
        ],
        "trusted_schemas": ["schema-issue-contract", "schema-review-verdict"],
        "trusted_configs": [
            {"config_id": binding["config_id"], "resource": binding["resource_id"]}
            for binding in graph["trusted_config_bindings"]
        ],
        "external_tcb_dependencies": _manifest_external_tcb_dependencies(graph),
    }
    manifest_raw = _json(manifest_data)
    manifest = load_candidate_trusted_manifest(manifest_raw)
    if type(manifest) is not CandidateTrustedManifest:
        raise RuntimeError(f"candidate manifest did not validate: {manifest!r}")
    result = validate_genesis_resource_graph(manifest, raw)
    if type(result) is GenesisResourceGraphFailure:
        raise RuntimeError(f"R4 genesis graph rejected candidate: {result.code.value}")

    evidence = _json({
        "format": "autodev.genesis-deterministic-evidence/v1",
        "repository_application_base": APPLICATION_BASE,
        "r2_executable_baseline": R2_EXECUTABLE_BASE,
        "source_bundle_sha256": sha256(first.source_bundle),
        "runtime_artifact_sha256": sha256(first.runtime_artifact),
        "build_definition_sha256": sha256(build_definition),
        "dependency_lock_sha256": sha256(lock),
        "resource_graph_sha256": sha256(graph_raw),
        "manifest_sha256": sha256(manifest_raw),
        "r4_validation": "PASS",
        "runtime_dependencies": [],
        "execution_isolation_dependency_id": execution_isolation_dependency_id,
        "execution_isolation_profile": execution_isolation_profile,
        "root_fence_dependency_id": root_fence_dependency_id,
        "root_fence_profile": root_fence_profile,
        "fixture_substrate_dependency_id": fixture_substrate_dependency_id,
        "fixture_substrate_profile": fixture_substrate_profile,
        "root_anchor_id": root_anchor_id,
        "external_tcb_material": all_external_tcb_material,
    })
    evidence_id = _resource_id("D", evidence)
    package_preimage = _json({
        "format": "autodev.genesis-candidate-package/v1",
        "repository_application_base": APPLICATION_BASE,
        "r2_executable_baseline": R2_EXECUTABLE_BASE,
        "implementation_resource": {"resource_id": "implementation", "sha256": sha256(raw["implementation"])},
        "build_definition_resource": {"resource_id": "build", "sha256": sha256(raw["build"])},
        "dependency_lock_resource": {"resource_id": "lock", "sha256": sha256(raw["lock"])},
        "runtime_artifact_resource": {"resource_id": "runtime", "sha256": sha256(raw["runtime"])},
        "resource_graph_resource": {"resource_id": "graph", "sha256": sha256(graph_raw)},
        "r3_resource": {"resource_id": "conformance", "git_blob": conformance_blob,
                        "sha256": _R3_RAW_SHA256},
        "review_profile": "g9-exact-candidate-independent-review/v1",
        "expected_deployment_attestation_profile": "g9-fenced-readonly-four-role/v1",
        "expected_runtime_members": [
            {"role": role, "member_id": role, "runtime_binding": f"runtime-binding-{role}",
             "service_principal": f"service-{role}-candidate"} for role in _ROLES
        ],
        "root_anchor_id": root_anchor_id,
        "root_fence_dependency_id": root_fence_dependency_id,
        "root_fence_profile": root_fence_profile,
        "fixture_substrate_dependency_id": fixture_substrate_dependency_id,
        "fixture_substrate_profile": fixture_substrate_profile,
        "execution_isolation_dependency_id": execution_isolation_dependency_id,
        "execution_isolation_profile": execution_isolation_profile,
        "external_tcb_material": all_external_tcb_material,
        "deterministic_evidence": {"record_id": evidence_id, "sha256": sha256(evidence)},
        "manifest_sha256": sha256(manifest_raw),
        "resource_sha256": [{"resource_id": key, "sha256": sha256(value)}
                             for key, value in sorted(raw.items())],
        "deterministic_evidence_sha256": sha256(evidence),
    })
    package_id = sha256(package_preimage)
    package_descriptor = _json({"candidate_package_id": package_id, "preimage": json.loads(package_preimage)})
    package = deterministic_archive(tuple(sorted((
        ("candidate-package.json", package_descriptor),
        ("candidate-manifest.json", manifest_raw),
        ("deterministic-evidence.json", evidence),
        *((f"resources/{key}", value) for key, value in raw.items()),
    ))))
    return CandidatePackage(
        source_bundle=first.source_bundle, runtime_artifact=first.runtime_artifact,
        build_definition=build_definition, dependency_lock=lock, graph=graph_raw,
        manifest=manifest_raw, raw_resources=MappingProxyType(dict(raw)), deterministic_evidence=evidence,
        deterministic_evidence_id=evidence_id,
        candidate_package=package, candidate_package_id=package_id,
        manifest_id=manifest.manifest_id.raw_sha256.value,
        runtime_sha256=sha256(first.runtime_artifact),
        source_bundle_sha256=sha256(first.source_bundle),
        build_definition_sha256=sha256(build_definition),
        dependency_lock_sha256=sha256(lock),
    )


def _git_blob(base: str, path: str, cwd: str) -> bytes:
    import subprocess
    return subprocess.run(["git", "show", f"{base}:{path}"], cwd=cwd, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def write_package(package: CandidatePackage, output: Path) -> None:
    """Write reproducible candidate files; caller chooses a non-authoritative directory."""
    output.mkdir(parents=True, exist_ok=True)
    (output / "source-bundle.zip").write_bytes(package.source_bundle)
    (output / "runtime.zip").write_bytes(package.runtime_artifact)
    (output / "build-definition.json").write_bytes(package.build_definition)
    (output / "dependency-lock.json").write_bytes(package.dependency_lock)
    (output / "resource-graph.json").write_bytes(package.graph)
    (output / "candidate-manifest.json").write_bytes(package.manifest)
    (output / "deterministic-evidence.json").write_bytes(package.deterministic_evidence)
    (output / "candidate-package.zip").write_bytes(package.candidate_package)
    resource_dir = output / "resources"
    resource_dir.mkdir(exist_ok=True)
    for resource_id, raw in sorted(package.raw_resources.items()):
        (resource_dir / resource_id).write_bytes(raw)


if __name__ == "__main__":
    destination = Path(os.environ.get("GENESIS_OUTPUT", "build/genesis-candidate"))
    host_profile_path = os.environ.get("GENESIS_HOST_PROFILE")
    if not host_profile_path:
        raise SystemExit("GENESIS_HOST_PROFILE must identify the external, secret-free host profile")
    host_profile = json.loads(Path(host_profile_path).read_text(encoding="utf-8"))
    expected_fields = {"root_fence_profile", "fixture_substrate_profile", "root_anchor_id"}
    if type(host_profile) is not dict or set(host_profile) != expected_fields:
        raise SystemExit("external host profile has an open or incomplete field set")
    assembled = assemble_candidate(
        root_fence_profile=host_profile["root_fence_profile"],
        fixture_substrate_profile=host_profile["fixture_substrate_profile"],
        root_anchor_id=host_profile["root_anchor_id"],
    )
    write_package(assembled, destination)
    print(json.dumps({
        "candidate_package_id": assembled.candidate_package_id,
        "manifest_id": assembled.manifest_id,
        "runtime_sha256": assembled.runtime_sha256,
        "source_bundle_sha256": assembled.source_bundle_sha256,
        "build_definition_id": "build",
        "build_definition_sha256": assembled.build_definition_sha256,
        "dependency_lock_id": "lock",
        "dependency_lock_sha256": assembled.dependency_lock_sha256,
        "runtime_artifact_id": "runtime",
        "resource_graph_id": "graph",
        "resource_graph_sha256": sha256(assembled.graph),
        "manifest_sha256": sha256(assembled.manifest),
        "deterministic_evidence_sha256": sha256(assembled.deterministic_evidence),
        "resource_sha256": {key: sha256(value) for key, value in sorted(assembled.raw_resources.items())},
        "resource_count": len(assembled.raw_resources),
        "output": str(destination),
    }, sort_keys=True))
