"""External-root first-genesis release controller; no generic CAS is exposed."""

from __future__ import annotations

from pathlib import Path

from root_admin import ROOT_STORE_PATH, RetainedDeploymentSession, release_capability_fence


def release_first_genesis(
    database: Path = ROOT_STORE_PATH, *, expected_admin_sid: str,
    expected_fence_row: dict[str, object], acceptance_id: str,
    initialization_record_id: str, deployment_attestation: dict[str, object],
    deployment_session_id: str, live_observation: dict[str, object],
    explicit_release: bool, retained_session: RetainedDeploymentSession,
    expected_acl_sddl: str,
) -> dict[str, object]:
    """Perform only the frozen atomic FENCED/0 -> RELEASED/1 ceremony."""
    return release_capability_fence(
        database, expected_admin_sid=expected_admin_sid,
        expected_fence_row=expected_fence_row, acceptance_id=acceptance_id,
        initialization_record_id=initialization_record_id,
        deployment_attestation=deployment_attestation,
        deployment_session_id=deployment_session_id, live_observation=live_observation,
        explicit_release=explicit_release, retained_session=retained_session,
        expected_acl_sddl=expected_acl_sddl,
    )
