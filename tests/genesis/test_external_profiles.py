"""Closed external-TCB identities used by the G9 completion repair."""

from __future__ import annotations

import copy
import hashlib

import pytest

from external_profiles import (
    FIXTURE_SUBSTRATE_DOMAIN,
    ROOT_ANCHOR_DOMAIN,
    ROOT_FENCE_DOMAIN,
    ROOT_STORE_PROFILE_DOMAIN,
    canonical_json_bytes,
    derive_root_anchor_id,
    derive_acceptance_profile_id,
    derive_external_root_controller_identity,
    derive_root_namespace_acl_profile_id,
    derive_root_store_profile_id,
    validate_fixture_substrate_profile,
    validate_root_fence_profile,
)


def _material(path: str, digest: str = "a" * 64) -> dict[str, str]:
    return {"path": path, "sha256": digest}


def _root_profile() -> dict[str, object]:
    admin_sid, substrate_sid = "S-1-5-21-1-1001", "S-1-5-21-1-1020"
    role_sids = {role: f"S-1-5-21-1-{1100 + index}"
                 for index, role in enumerate(("T", "C", "P", "M"))}
    sddl = f"O:{admin_sid}G:S-1-5-18D:P(A;;FA;;;S-1-5-18)(A;;FA;;;{admin_sid})(A;;GR;;;{substrate_sid})"
    acl_profile_id = derive_root_namespace_acl_profile_id({
        "format": "autodev.g9-root-namespace-acl-profile/v1",
        "security_descriptor_sddl": sddl, "root_admin_sid": admin_sid,
        "substrate_sid": substrate_sid, "system_sid": "S-1-5-18",
        "candidate_role_sids": role_sids, "inherited_acl": "DENY", "candidate_role_access": "NO_ACCESS",
    })
    tools = [_material("tools/genesis/external_profiles.py"), _material("tools/genesis/root_admin.py")]
    acceptance = {
        "format": "autodev.g9-acceptance-profile/v1",
        "authority_model": "WINDOWS_EXTERNAL_ROOT_AUTHORITY",
        "eligible_bootstrap_approver": {"account": r"Ray\zhang", "sid": admin_sid,
                                          "administrator_required": True},
        "authentication_method": "CURRENT_PROCESS_PRIMARY_TOKEN_EXACT_SID_ELEVATED_ADMIN",
        "acceptance_record_format": "autodev.genesis-acceptance-record/v1",
        "acceptance_storage": "CANONICAL_ROOT_DB_APPEND_ONLY",
        "decision_domain": "GENESIS_BOOTSTRAP",
        "validity_model": "IDENTITY_AND_SESSION_BOUND_NO_TIME_TTL",
        "interactive_confirmation": "LOCAL_CONSOLE_EXACT_SUBJECT_CONFIRMATION",
        "acceptance_tool_material": tools,
        "production_github_mutation_credentials": "NONE",
    }
    acceptance_id = derive_acceptance_profile_id(acceptance)
    store_id = derive_root_store_profile_id(schema_sha256="b" * 64,
                                            acl_profile_id=acl_profile_id)
    return {
        "format": "autodev.g9-root-activation-fence-profile/v1",
        "repository": "RayZhang2024/autonomous-dev-control-plane",
        "design_lineage": "issue-55-g9-completion-repair-v0.5",
        "root_anchor_namespace": "autodev-v2-first-genesis-root",
        "root_store_profile": "autodev.g9-canonical-root-store/v1",
        "root_store_profile_id": store_id,
        "root_store_schema_sha256": "b" * 64,
        "root_namespace_acl_profile": {
            "profile_id": acl_profile_id, "security_descriptor_sddl": sddl,
            "root_admin_sid": admin_sid, "substrate_sid": substrate_sid,
            "system_sid": "S-1-5-18", "candidate_role_sids": role_sids,
        },
        "acceptance_profile": {"profile_id": acceptance_id,
            **{key: value for key, value in acceptance.items()
               if key not in ("format", "acceptance_tool_material")}},
        "root_admin_tool_material": tools,
        "fence_controller_material": [_material("tools/genesis/fence_controller.py")],
        "genesis_provenance_material": [
            _material("tools/genesis/genesis_provenance.py"),
            _material("tools/genesis/post_merge_binding.py"),
        ],
        "python_runtime": {
            "identity": "CPython", "version": "3.13.14",
            "path": r"C:\AutodevG9\shared\python313\python.exe", "sha256": "c" * 64,
        },
        "root_admin_principal": {"account": r"Ray\zhang", "sid": admin_sid,
                                 "administrator": True},
        "canonical_root_store": {
            "profile_id": store_id,
            "path": r"C:\AutodevG9\root\root.sqlite3",
        },
        "candidate_role_access": "NO_WRITE",
        "capability_release_authority": "EXTERNAL_ROOT_ADMIN_ONLY",
        "production_github_mutation_credentials": "NONE",
    }


def _substrate_profile() -> dict[str, object]:
    return {
        "format": "autodev.g9-fixture-effect-substrate-profile/v1",
        "implementation_material": [
            _material("tools/genesis/fixture_substrate.py"),
            _material("tools/genesis/windows_substrate_launcher.py"),
        ],
        "f_read_verify_endpoint": {
            "endpoint_id": "F-read-verify", "transport": "LOOPBACK_HMAC_JSON",
            "authority": "READ_VERIFY_ONLY",
        },
        "publication_authority_endpoint": {
            "endpoint_id": "publication-authority", "transport": "LOOPBACK_HMAC_JSON",
            "authority": "PUBLICATION_ONLY",
        },
        "merge_authority_endpoint": {
            "endpoint_id": "merge-authority", "transport": "LOOPBACK_HMAC_JSON",
            "authority": "MERGE_ONLY",
        },
        "p_target_fence": {
            "fence_id": "P-target-fence", "namespace": "candidate-P",
            "endpoint_id": "P-target", "initial_state": "FENCED",
        },
        "m_target_fence": {
            "fence_id": "M-target-fence", "namespace": "candidate-M",
            "endpoint_id": "M-target", "initial_state": "FENCED",
        },
        "target_fence_namespace": "g9-first-genesis-target-fences",
        "external_recovery_endpoint": {
            "endpoint_id": "external-start-held-recovery", "transport": "LOOPBACK_HMAC_JSON",
            "authority": "START_HELD_RECOVERY_ONLY",
        },
        "service_principal": {"account": r"Ray\autodev-g9-substrate",
                              "sid": "S-1-5-21-1-1020", "token_type": "PRIMARY",
                              "administrator": False},
        "role_exposure": {
            "T": ["F_READ_VERIFY"], "C": ["F_READ_VERIFY"],
            "P": ["F_READ_VERIFY", "P_TARGET_FENCE", "PUBLICATION_AUTHORITY"],
            "M": ["F_READ_VERIFY", "M_TARGET_FENCE", "MERGE_AUTHORITY"],
            "ORDINARY": [],
        },
        "production_github_mutation_credentials": "NONE",
    }


def test_root_anchor_id_uses_exact_domain_and_canonical_closed_preimage():
    preimage = {
        "repository": "RayZhang2024/autonomous-dev-control-plane",
        "root_store_profile": "autodev.g9-canonical-root-store/v1",
        "design_lineage": "issue-55-g9-completion-repair-v0.2",
        "namespace": "autodev-v2-first-genesis-root",
    }
    assert derive_root_anchor_id(preimage) == hashlib.sha256(
        ROOT_ANCHOR_DOMAIN + canonical_json_bytes(preimage)
    ).hexdigest()
    altered = dict(preimage, namespace="another-root")
    assert derive_root_anchor_id(altered) != derive_root_anchor_id(preimage)
    with pytest.raises(ValueError):
        derive_root_anchor_id(dict(preimage, extra="not-closed"))


def test_root_fence_profile_identity_binds_each_external_host_and_authority_fact():
    profile = _root_profile()
    identity = validate_root_fence_profile(profile)
    assert identity == "dep-root-activation-fence-" + hashlib.sha256(
        ROOT_FENCE_DOMAIN + canonical_json_bytes(profile)
    ).hexdigest()
    changed = copy.deepcopy(profile)
    changed["root_store_schema_sha256"] = "e" * 64
    store_id = derive_root_store_profile_id(
        schema_sha256=changed["root_store_schema_sha256"],
        acl_profile_id=changed["root_namespace_acl_profile"]["profile_id"],
    )
    changed["root_store_profile_id"] = store_id
    changed["canonical_root_store"]["profile_id"] = store_id
    assert validate_root_fence_profile(changed) != identity
    for field, value in (
        ("root_anchor_namespace", "different-namespace"),
        ("root_admin_principal", {"account": r"Ray\other", "sid": profile["root_admin_principal"]["sid"],
                                   "administrator": True}),
        ("python_runtime", dict(profile["python_runtime"], sha256="f" * 64)),
    ):
        changed = copy.deepcopy(profile)
        changed[field] = value
        assert validate_root_fence_profile(changed) != identity
    changed = copy.deepcopy(profile)
    changed["canonical_root_store"]["path"] = r"D:\other\root.sqlite3"
    with pytest.raises(ValueError):
        validate_root_fence_profile(changed)


def test_root_store_derivation_is_acyclic_and_binds_relation_formats_not_acceptance_profile():
    profile = _root_profile()
    store_id = profile["root_store_profile_id"]
    store_preimage = {
        "format": "autodev.g9-canonical-root-store/v1",
        "schema_sha256": profile["root_store_schema_sha256"],
        "canonical_path": r"C:\AutodevG9\root\root.sqlite3",
        "storage_semantics": "SQLITE_CREATE_IF_ABSENT_IMMEDIATE_TRANSACTIONS_APPEND_ONLY_HISTORY_V2",
        "relation_formats": {
            "acceptance": "autodev.genesis-acceptance-record/v1",
            "initialization": "autodev.genesis-root-initialization-record/v1",
            "release_verification": "autodev.genesis-release-verification/v1",
        },
        "root_namespace_acl_profile_id": profile["root_namespace_acl_profile"]["profile_id"],
    }
    assert store_id == hashlib.sha256(
        ROOT_STORE_PROFILE_DOMAIN + canonical_json_bytes(store_preimage)
    ).hexdigest()
    changed_acceptance = copy.deepcopy(profile)
    changed_acceptance["acceptance_profile"]["interactive_confirmation"] = "different-confirmation"
    # The acceptance identity is a sibling derivation; it does not feed root-store identity.
    assert derive_root_store_profile_id(
        schema_sha256=changed_acceptance["root_store_schema_sha256"],
        acl_profile_id=changed_acceptance["root_namespace_acl_profile"]["profile_id"],
    ) == store_id
    changed_schema_id = derive_root_store_profile_id(
        schema_sha256="d" * 64,
        acl_profile_id=profile["root_namespace_acl_profile"]["profile_id"],
    )
    changed_acl_id = derive_root_store_profile_id(
        schema_sha256=profile["root_store_schema_sha256"], acl_profile_id="e" * 64,
    )
    assert changed_schema_id != store_id
    assert changed_acl_id != store_id


def test_external_root_controller_identity_is_derived_from_bound_source_and_profile():
    profile = _root_profile()
    identity = derive_external_root_controller_identity(profile)
    assert identity["implementation_sha256"] == profile["fence_controller_material"][0]["sha256"]
    changed = copy.deepcopy(profile)
    changed["acceptance_profile"]["profile_id"] = "f" * 64
    assert derive_external_root_controller_identity(changed) != identity
    changed = copy.deepcopy(profile)
    changed["fence_controller_material"][0]["sha256"] = "0" * 64
    assert derive_external_root_controller_identity(changed) != identity
    changed = copy.deepcopy(profile)
    changed["genesis_provenance_material"][0]["sha256"] = "0" * 64
    assert derive_external_root_controller_identity(changed) != identity


@pytest.mark.parametrize("field,value", (
    ("candidate_role_access", "READ_WRITE"),
    ("capability_release_authority", "CANDIDATE"),
    ("production_github_mutation_credentials", "AVAILABLE"),
))
def test_root_fence_profile_rejects_candidate_authority_or_production_credentials(field, value):
    profile = _root_profile()
    profile[field] = value
    with pytest.raises(ValueError):
        validate_root_fence_profile(profile)


def test_fixture_substrate_identity_binds_exact_loopback_authority_and_role_exposure():
    profile = _substrate_profile()
    identity = validate_fixture_substrate_profile(profile)
    assert identity == "dep-fixture-effect-substrate-" + hashlib.sha256(
        FIXTURE_SUBSTRATE_DOMAIN + canonical_json_bytes(profile)
    ).hexdigest()
    changed = copy.deepcopy(profile)
    changed["implementation_material"][0]["sha256"] = "e" * 64
    assert validate_fixture_substrate_profile(changed) != identity
    changed = copy.deepcopy(profile)
    changed["p_target_fence"]["endpoint_id"] = "other-endpoint"
    assert validate_fixture_substrate_profile(changed) != identity


@pytest.mark.parametrize("mutate", (
    lambda p: p.update(extra="open"),
    lambda p: p["role_exposure"].update(T=["F_READ_VERIFY", "PUBLICATION_AUTHORITY"]),
    lambda p: p["role_exposure"].update(ORDINARY=["EXTERNAL_RECOVERY"]),
    lambda p: p["m_target_fence"].update(initial_state="RELEASED"),
    lambda p: p["publication_authority_endpoint"].update(transport="TCP_UNAUTHENTICATED"),
    lambda p: p.update(production_github_mutation_credentials="AVAILABLE"),
))
def test_fixture_substrate_rejects_open_or_overbroad_profiles(mutate):
    profile = _substrate_profile()
    mutate(profile)
    with pytest.raises(ValueError):
        validate_fixture_substrate_profile(profile)


def test_profile_fields_are_exact_and_no_secret_field_is_permitted():
    root = _root_profile()
    substrate = _substrate_profile()
    root["root_password"] = "not permitted"
    substrate["role_passwords"] = {}
    with pytest.raises(ValueError):
        validate_root_fence_profile(root)
    with pytest.raises(ValueError):
        validate_fixture_substrate_profile(substrate)
