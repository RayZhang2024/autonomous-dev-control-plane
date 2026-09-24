"""Non-genesis legacy fixture capability-token compatibility values."""

from .scope import ServicePrincipalId


class _FixtureCapability:
    __slots__ = ("_nonce", "service_identity")

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("fixture capabilities are minted only by fixture composition")


class ControlStateCapability(_FixtureCapability):
    pass


class TargetPublicationCapability(_FixtureCapability):
    pass


class MergeCapability(_FixtureCapability):
    pass


def mint_fixture_capability(
    kind: type[_FixtureCapability], nonce: object,
    service_identity: ServicePrincipalId,
) -> _FixtureCapability:
    if (kind not in (ControlStateCapability, TargetPublicationCapability, MergeCapability)
            or type(service_identity) is not ServicePrincipalId):
        raise TypeError("exact fixture capability type and service identity required")
    value = object.__new__(kind)
    value._nonce = nonce
    value.service_identity = service_identity
    return value
