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


def _make_graph_resources(runtime_id: str) -> tuple[dict[str, bytes], dict[str, str], dict[str, object]]:
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
            "external_isolation_dependency_id": "dep-execution-isolation",
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
            "f_read_verify_binding": _FIXTURE_BINDINGS["f_read_verify_binding"],
            "target_fence_binding": {"T": "NONE", "C": "NONE", "P": _FIXTURE_BINDINGS["p_target_fence_binding"], "M": _FIXTURE_BINDINGS["m_target_fence_binding"]}[role],
            "publication_authority_binding": _FIXTURE_BINDINGS["publication_authority_binding"] if role == "P" else "NONE",
            "merge_authority_binding": _FIXTURE_BINDINGS["merge_authority_binding"] if role == "M" else "NONE",
            "external_recovery_binding": "NONE",
        }
        credential[credential_id] = {
            "format": "autodev.genesis-credential-routing/v1",
            "role": role,
            "member_id": role,
            "production_github_mutation_credentials": "NONE",
        }
    external = (
        ("ROOT_ACTIVATION_FENCE", "dep-root-activation-fence", "assumption-root-fence"),
        ("EXECUTION_ISOLATION", "dep-execution-isolation", "assumption-execution-isolation"),
        ("FIXTURE_EFFECT_SUBSTRATE", "dep-fixture-effect-substrate", "assumption-fixture-effects"),
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
            assumption["bindings"] = _FIXTURE_BINDINGS
            graph_record["bindings"] = _FIXTURE_BINDINGS
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
        "third_party_runtime_policy": {"standard_library_policy": "ALLOW", "third_party_module_allowlist": []},
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


def assemble_candidate(*, git_cwd: str = ".") -> CandidatePackage:
    """Build twice from the authorized Git object and return the same byte image."""
    first = build_from_git(git_cwd=git_cwd)
    second = build_from_git(git_cwd=git_cwd)
    if first != second:
        raise RuntimeError("independent deterministic builds differ")
    external_tcb_material = [
        {"path": f"tools/genesis/{name}",
         "sha256": sha256(Path(__file__).with_name(name).read_bytes())}
        for name in ("ipc.py", "role_worker.py", "windows_role_launcher.py", "windows_role_runner.py")
    ]
    build_definition = _json({
        "format": "autodev.genesis-build-definition/v1",
        "repository_application_base": APPLICATION_BASE,
        "r2_executable_baseline": R2_EXECUTABLE_BASE,
        "build_tool": {
            "path": "tools/genesis/build_definition.py",
            "sha256": sha256((Path(__file__).with_name("build_definition.py")).read_bytes()),
        },
        "assembler": {
            "path": "tools/genesis/assemble_candidate.py",
            "sha256": sha256(Path(__file__).read_bytes()),
        },
        "external_tcb_material": external_tcb_material,
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
    raw, kinds, graph = _make_graph_resources(runtime_id)
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
        "external_tcb_dependencies": [
            {"dependency_id": dependency, "assumption_resource": assumption}
            for _, dependency, assumption in (
                ("ROOT_ACTIVATION_FENCE", "dep-root-activation-fence", "assumption-root-fence"),
                ("EXECUTION_ISOLATION", "dep-execution-isolation", "assumption-execution-isolation"),
                ("FIXTURE_EFFECT_SUBSTRATE", "dep-fixture-effect-substrate", "assumption-fixture-effects"),
            )
        ],
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
        "external_tcb_material": external_tcb_material,
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
        "root_trust_anchor_profile_identity": "external-root-trust-anchor-first-genesis/v1",
        "external_tcb_material": external_tcb_material,
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
    assembled = assemble_candidate()
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
