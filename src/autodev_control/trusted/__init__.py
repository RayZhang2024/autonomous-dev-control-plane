"""Candidate trusted-core primitives. Their construction confers no authority."""

from .authorization import (
    admit_delegated_authorization,
    admit_direct_authorization,
    load_candidate_authorization_proposal,
)
from .manifest import CandidateTrustedManifest, load_candidate_trusted_manifest
from .parsing import ParseLimits, ParsedJsonDocument, parse_trusted_json
from .resources import resolve_trusted_json_resource, verify_inline_resource_bytes
from .target_registration import admit_target_registration, load_candidate_target_registration

__all__ = [
    "CandidateTrustedManifest",
    "ParseLimits",
    "ParsedJsonDocument",
    "admit_delegated_authorization",
    "admit_direct_authorization",
    "admit_target_registration",
    "load_candidate_authorization_proposal",
    "load_candidate_target_registration",
    "load_candidate_trusted_manifest",
    "parse_trusted_json",
    "resolve_trusted_json_resource",
    "verify_inline_resource_bytes",
]
