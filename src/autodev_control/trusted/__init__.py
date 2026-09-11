"""Candidate trusted-core primitives. Their construction confers no authority."""

from .manifest import CandidateTrustedManifest, load_candidate_trusted_manifest
from .parsing import ParseLimits, ParsedJsonDocument, parse_trusted_json
from .resources import resolve_trusted_json_resource, verify_inline_resource_bytes

__all__ = [
    "CandidateTrustedManifest",
    "ParseLimits",
    "ParsedJsonDocument",
    "load_candidate_trusted_manifest",
    "parse_trusted_json",
    "resolve_trusted_json_resource",
    "verify_inline_resource_bytes",
]
