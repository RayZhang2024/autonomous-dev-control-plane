"""Fixture-only issuance for out-of-band authenticated caller provenance."""

from .identity import RawSha256
from .runtime_authority import AuthenticatedCallerContext, RuntimeSecurityContext


def issue_fixture_caller_context(
    channel_token: object, context: RuntimeSecurityContext,
    request_digest: RawSha256,
) -> AuthenticatedCallerContext:
    if (type(channel_token) is not object
            or type(context) is not RuntimeSecurityContext
            or type(request_digest) is not RawSha256):
        raise TypeError("exact fixture channel and runtime context required")
    value = object.__new__(AuthenticatedCallerContext)
    object.__setattr__(value, "context", context)
    object.__setattr__(value, "request_digest", request_digest)
    object.__setattr__(value, "_channel_token", channel_token)
    return value
