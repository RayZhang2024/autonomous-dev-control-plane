"""Lexically validated, security-distinct identifiers without external claims."""

from dataclasses import dataclass

from .errors import IdentityValidationError, IdentityValidationFailureCode


def _unicode_string(value: object, maximum: int) -> str:
    if type(value) is not str:
        raise IdentityValidationError(IdentityValidationFailureCode.INVALID_TYPE)
    if not 1 <= len(value) <= maximum:
        raise IdentityValidationError(IdentityValidationFailureCode.INVALID_LENGTH)
    return value


def _lower_hex(value: object, lengths: tuple[int, ...]) -> str:
    if type(value) is not str:
        raise IdentityValidationError(IdentityValidationFailureCode.INVALID_TYPE)
    if len(value) not in lengths or any(char not in "0123456789abcdef" for char in value):
        raise IdentityValidationError(IdentityValidationFailureCode.INVALID_FORMAT)
    return value


@dataclass(frozen=True, slots=True)
class LogicalIdentifier:
    value: str

    def __post_init__(self) -> None:
        _unicode_string(self.value, 512)


@dataclass(frozen=True, slots=True)
class ImmutableConfigId:
    value: str

    def __post_init__(self) -> None:
        _unicode_string(self.value, 512)


@dataclass(frozen=True, slots=True)
class GitRef:
    value: str

    def __post_init__(self) -> None:
        _unicode_string(self.value, 1024)


@dataclass(frozen=True, slots=True)
class GitSha:
    value: str

    def __post_init__(self) -> None:
        _lower_hex(self.value, (40, 64))


@dataclass(frozen=True, slots=True)
class RawSha256:
    value: str

    def __post_init__(self) -> None:
        _lower_hex(self.value, (64,))


@dataclass(frozen=True, slots=True)
class CandidateMaterializationId:
    raw_sha256: RawSha256

    def __post_init__(self) -> None:
        if type(self.raw_sha256) is not RawSha256:
            raise TypeError("raw_sha256 must be exactly RawSha256")


@dataclass(frozen=True, slots=True)
class MutationInventoryId:
    raw_sha256: RawSha256

    def __post_init__(self) -> None:
        if type(self.raw_sha256) is not RawSha256:
            raise TypeError("raw_sha256 must be exactly RawSha256")


@dataclass(frozen=True, slots=True)
class OperationStartBindingId:
    raw_sha256: RawSha256

    def __post_init__(self) -> None:
        if type(self.raw_sha256) is not RawSha256:
            raise TypeError("raw_sha256 must be exactly RawSha256")


@dataclass(frozen=True, slots=True)
class RootContextId:
    raw_sha256: RawSha256

    def __post_init__(self) -> None:
        if type(self.raw_sha256) is not RawSha256:
            raise TypeError("raw_sha256 must be exactly RawSha256")


@dataclass(frozen=True, slots=True)
class PreparedProtectedStartId:
    raw_sha256: RawSha256

    def __post_init__(self) -> None:
        if type(self.raw_sha256) is not RawSha256:
            raise TypeError("raw_sha256 must be exactly RawSha256")


@dataclass(frozen=True, slots=True)
class ProtectedEffectMarkerId:
    raw_sha256: RawSha256

    def __post_init__(self) -> None:
        if type(self.raw_sha256) is not RawSha256:
            raise TypeError("raw_sha256 must be exactly RawSha256")


@dataclass(frozen=True, slots=True)
class GateAuditEventId:
    raw_sha256: RawSha256

    def __post_init__(self) -> None:
        if type(self.raw_sha256) is not RawSha256:
            raise TypeError("raw_sha256 must be exactly RawSha256")
