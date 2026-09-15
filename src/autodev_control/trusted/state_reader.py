"""Read-only G6 GitHub state normalization and authoritative binding.

Normalization alone never establishes GitHub authenticity.  Authoritative
results additionally require an opaque root-managed transport binding and an
exact authenticated transport instance.  This module exposes no write API.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json

from .identity import GitRef, GitSha, ImmutableConfigId, LogicalIdentifier
from .operation import AuthoritativeStateBindingId
from .scope import CanonicalGitPath, GitHubRepositoryId, ServicePrincipalId

G6_MAX_CHANGED_FILE_PAGES = 1024
G6_MAX_CHANGED_FILES = 100_000


def _positive(value: object, name: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{name} must be an exact positive int")
    return value


def _tuple(values: object, expected: type, name: str, *, unique: bool = True) -> tuple:
    if type(values) is not tuple or any(type(item) is not expected for item in values):
        raise TypeError(f"{name} must be an exact tuple of {expected.__name__}")
    if unique and len(set(values)) != len(values):
        raise ValueError(f"{name} must be duplicate-free")
    return values


@dataclass(frozen=True, slots=True)
class GitHubIssueNumber:
    value: int

    def __post_init__(self) -> None:
        _positive(self.value, "issue number")


@dataclass(frozen=True, slots=True)
class GitHubPullRequestNumber:
    value: int

    def __post_init__(self) -> None:
        _positive(self.value, "pull request number")


@dataclass(frozen=True, slots=True)
class GitHubReadRequest:
    repository_id: GitHubRepositoryId

    def __post_init__(self) -> None:
        if type(self.repository_id) is not GitHubRepositoryId:
            raise TypeError("repository_id must be exactly GitHubRepositoryId")


@dataclass(frozen=True, slots=True)
class ReadRepositoryIdentity(GitHubReadRequest):
    pass


@dataclass(frozen=True, slots=True)
class ReadGitRef(GitHubReadRequest):
    ref: GitRef

    def __post_init__(self) -> None:
        GitHubReadRequest.__post_init__(self)
        if type(self.ref) is not GitRef:
            raise TypeError("ref must be exactly GitRef")


@dataclass(frozen=True, slots=True)
class ReadCommit(GitHubReadRequest):
    sha: GitSha

    def __post_init__(self) -> None:
        GitHubReadRequest.__post_init__(self)
        if type(self.sha) is not GitSha:
            raise TypeError("sha must be exactly GitSha")


@dataclass(frozen=True, slots=True)
class ReadCommitAncestry(GitHubReadRequest):
    ancestor: GitSha
    descendant: GitSha

    def __post_init__(self) -> None:
        GitHubReadRequest.__post_init__(self)
        if type(self.ancestor) is not GitSha or type(self.descendant) is not GitSha:
            raise TypeError("ancestry endpoints must be exact GitSha values")


@dataclass(frozen=True, slots=True)
class ReadIssueIdentity(GitHubReadRequest):
    issue_number: GitHubIssueNumber

    def __post_init__(self) -> None:
        GitHubReadRequest.__post_init__(self)
        if type(self.issue_number) is not GitHubIssueNumber:
            raise TypeError("issue_number has wrong exact type")


@dataclass(frozen=True, slots=True)
class ReadPullRequest(GitHubReadRequest):
    pull_request_number: GitHubPullRequestNumber

    def __post_init__(self) -> None:
        GitHubReadRequest.__post_init__(self)
        if type(self.pull_request_number) is not GitHubPullRequestNumber:
            raise TypeError("pull_request_number has wrong exact type")


@dataclass(frozen=True, slots=True)
class ReadChangedFileInventory(GitHubReadRequest):
    pull_request_number: GitHubPullRequestNumber

    def __post_init__(self) -> None:
        GitHubReadRequest.__post_init__(self)
        if type(self.pull_request_number) is not GitHubPullRequestNumber:
            raise TypeError("pull_request_number has wrong exact type")


@dataclass(frozen=True, slots=True)
class ReadMergeState(GitHubReadRequest):
    pull_request_number: GitHubPullRequestNumber

    def __post_init__(self) -> None:
        GitHubReadRequest.__post_init__(self)
        if type(self.pull_request_number) is not GitHubPullRequestNumber:
            raise TypeError("pull_request_number has wrong exact type")


@dataclass(frozen=True, slots=True)
class ReadRegisteredEventSensitiveState(GitHubReadRequest):
    fact_name: LogicalIdentifier

    def __post_init__(self) -> None:
        GitHubReadRequest.__post_init__(self)
        if type(self.fact_name) is not LogicalIdentifier:
            raise TypeError("fact_name must be exactly LogicalIdentifier")


class CommitAncestry(Enum):
    SAME = "SAME"
    ANCESTOR = "ANCESTOR"
    NOT_ANCESTOR = "NOT_ANCESTOR"
    INDETERMINATE = "INDETERMINATE"


class StateReadFailure(Enum):
    UNAVAILABLE = "UNAVAILABLE"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    MISMATCH = "MISMATCH"
    UNSUPPORTED = "UNSUPPORTED"
    INDETERMINATE = "INDETERMINATE"
    INCOMPLETE = "INCOMPLETE"
    STATE_MOVED = "STATE_MOVED"
    UNTRUSTED_TRANSPORT = "UNTRUSTED_TRANSPORT"


@dataclass(frozen=True, slots=True)
class NormalizedGitHubObservation:
    fact_key: str
    fact_value: tuple

    def __post_init__(self) -> None:
        if type(self.fact_key) is not str or not self.fact_key:
            raise ValueError("fact_key must be a non-empty string")
        if type(self.fact_value) is not tuple or not _deep_immutable_scalar_tuple(self.fact_value):
            raise TypeError("fact_value must be a deeply immutable scalar tuple")


def _deep_immutable_scalar_tuple(value: tuple) -> bool:
    return all(
        type(item) in (str, int, bool) or item is None
        or (type(item) is tuple and _deep_immutable_scalar_tuple(item))
        for item in value
    )


@dataclass(frozen=True, slots=True)
class GitHubNormalizationResult:
    observation: NormalizedGitHubObservation | None = None
    failure: StateReadFailure | None = None

    def __post_init__(self) -> None:
        if (self.observation is None) == (self.failure is None):
            raise ValueError("normalization result carries exactly one observation or failure")
        if self.observation is not None and type(self.observation) is not NormalizedGitHubObservation:
            raise TypeError("observation has wrong exact type")
        if self.failure is not None and type(self.failure) is not StateReadFailure:
            raise TypeError("failure has wrong exact type")


class GitHubStateNormalizer:
    """Pure response-shape normalizer; its output is never authoritative alone."""

    def normalize(self, request: GitHubReadRequest, response: object) -> GitHubNormalizationResult:
        if not isinstance(request, GitHubReadRequest):
            raise TypeError("GitHubReadRequest required")
        if type(response) is not dict:
            return GitHubNormalizationResult(failure=StateReadFailure.MALFORMED_RESPONSE)
        if response.get("repository_id") != request.repository_id.value:
            return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
        try:
            if response.get("absent") is True:
                return self._absence(request, response)
            if type(request) is ReadRepositoryIdentity:
                return self._repository(request, response)
            if type(request) is ReadGitRef:
                return self._ref(request, response)
            if type(request) is ReadCommit:
                return self._commit(request, response)
            if type(request) is ReadCommitAncestry:
                return self._ancestry(request, response)
            if type(request) is ReadIssueIdentity:
                return self._issue(request, response)
            if type(request) is ReadPullRequest:
                return self._pull_request(request, response)
            if type(request) is ReadMergeState:
                return self._merge(request, response)
            if type(request) is ReadRegisteredEventSensitiveState:
                return self._registered(request, response)
            if type(request) is ReadChangedFileInventory:
                return GitHubNormalizationResult(failure=StateReadFailure.INCOMPLETE)
        except (TypeError, ValueError, KeyError):
            return GitHubNormalizationResult(failure=StateReadFailure.MALFORMED_RESPONSE)
        return GitHubNormalizationResult(failure=StateReadFailure.UNSUPPORTED)

    @staticmethod
    def _absence(request, response):
        if type(request) is ReadGitRef:
            if set(response) != {"repository_id", "ref", "absent"}:
                return GitHubNormalizationResult(failure=StateReadFailure.MALFORMED_RESPONSE)
            if response["ref"] != request.ref.value:
                return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
            return _ok(
                f"ref:{request.ref.value}",
                (request.repository_id.value, request.ref.value, "ABSENT"),
            )
        if type(request) is ReadIssueIdentity:
            if set(response) != {"repository_id", "number", "absent"}:
                return GitHubNormalizationResult(failure=StateReadFailure.MALFORMED_RESPONSE)
            if response["number"] != request.issue_number.value:
                return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
            return _ok(
                f"issue:{request.issue_number.value}",
                (request.repository_id.value, request.issue_number.value, "ABSENT"),
            )
        if type(request) is ReadPullRequest:
            if set(response) != {"repository_id", "number", "absent"}:
                return GitHubNormalizationResult(failure=StateReadFailure.MALFORMED_RESPONSE)
            if response["number"] != request.pull_request_number.value:
                return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
            return _ok(
                f"pull-request:{request.pull_request_number.value}",
                (request.repository_id.value, request.pull_request_number.value, "ABSENT"),
            )
        return GitHubNormalizationResult(failure=StateReadFailure.MALFORMED_RESPONSE)

    @staticmethod
    def _repository(request, response):
        if set(response) != {"repository_id", "owner", "name"} or any(type(response[key]) is not str or not response[key] for key in ("owner", "name")):
            return GitHubNormalizationResult(failure=StateReadFailure.MALFORMED_RESPONSE)
        return _ok("repository", (request.repository_id.value, response["owner"], response["name"]))

    @staticmethod
    def _ref(request, response):
        if set(response) != {"repository_id", "ref", "sha"} or response["ref"] != request.ref.value:
            return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
        sha = GitSha(response["sha"])
        return _ok(f"ref:{request.ref.value}", (request.repository_id.value, request.ref.value, sha.value))

    @staticmethod
    def _commit(request, response):
        if set(response) != {"repository_id", "sha", "parents"} or response["sha"] != request.sha.value or type(response["parents"]) is not list:
            return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
        parents = tuple(GitSha(item).value for item in response["parents"])
        if len(set(parents)) != len(parents):
            return GitHubNormalizationResult(failure=StateReadFailure.MALFORMED_RESPONSE)
        return _ok(f"commit:{request.sha.value}", (request.repository_id.value, request.sha.value, parents))

    @staticmethod
    def _ancestry(request, response):
        required = {"repository_id", "ancestor", "descendant", "result"}
        if set(response) != required or response["ancestor"] != request.ancestor.value or response["descendant"] != request.descendant.value:
            return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
        result = CommitAncestry(response["result"])
        if request.ancestor == request.descendant and result is not CommitAncestry.SAME:
            return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
        if request.ancestor != request.descendant and result is CommitAncestry.SAME:
            return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
        if result is CommitAncestry.INDETERMINATE:
            return GitHubNormalizationResult(failure=StateReadFailure.INDETERMINATE)
        return _ok(
            f"ancestry:{request.ancestor.value}:{request.descendant.value}",
            (request.repository_id.value, request.ancestor.value, request.descendant.value, result.value),
        )

    @staticmethod
    def _issue(request, response):
        required = {"repository_id", "number", "issue_id", "state", "title", "body", "labels", "comments"}
        if set(response) != required or response["number"] != request.issue_number.value:
            return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
        if response["state"] not in ("open", "closed") or type(response["title"]) is not str or type(response["body"]) is not str or type(response["labels"]) is not list or type(response["comments"]) is not list:
            return GitHubNormalizationResult(failure=StateReadFailure.MALFORMED_RESPONSE)
        issue_id = LogicalIdentifier(response["issue_id"])
        # Mutable state, prose, labels and comments are deliberately excluded.
        return _ok(
            f"issue:{request.issue_number.value}",
            (request.repository_id.value, request.issue_number.value, issue_id.value),
        )

    @staticmethod
    def _pull_request(request, response):
        required = {
            "repository_id", "number", "state", "merged", "base_repository_id",
            "base_ref", "base_sha", "head_repository_id", "head_ref", "head_sha",
            "merge_sha", "title", "body",
        }
        if set(response) != required or response["number"] != request.pull_request_number.value:
            return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
        if response["state"] not in ("open", "closed") or type(response["merged"]) is not bool or type(response["title"]) is not str or type(response["body"]) is not str:
            return GitHubNormalizationResult(failure=StateReadFailure.MALFORMED_RESPONSE)
        base_repository = GitHubRepositoryId(response["base_repository_id"])
        head_repository = GitHubRepositoryId(response["head_repository_id"])
        if base_repository != request.repository_id:
            return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
        base_ref, head_ref = GitRef(response["base_ref"]), GitRef(response["head_ref"])
        base, head = GitSha(response["base_sha"]), GitSha(response["head_sha"])
        merge_sha = response["merge_sha"]
        if response["merged"]:
            if response["state"] != "closed":
                return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
            merge_sha = GitSha(merge_sha).value
        elif merge_sha is not None:
            return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
        return _ok(
            f"pull-request:{request.pull_request_number.value}",
            (
                request.repository_id.value, request.pull_request_number.value,
                response["state"], response["merged"],
                base_repository.value, base_ref.value, base.value,
                head_repository.value, head_ref.value, head.value, merge_sha,
            ),
        )

    @staticmethod
    def _merge(request, response):
        required = {"repository_id", "number", "merged", "merge_sha"}
        if set(response) != required or response["number"] != request.pull_request_number.value or type(response["merged"]) is not bool:
            return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
        merge_sha = response["merge_sha"]
        if response["merged"]:
            merge_sha = GitSha(merge_sha).value
        elif merge_sha is not None:
            return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
        return _ok(f"merge:{request.pull_request_number.value}", (request.repository_id.value, request.pull_request_number.value, response["merged"], merge_sha))

    @staticmethod
    def _registered(request, response):
        if set(response) != {"repository_id", "fact_name", "state", "value"} or response["fact_name"] != request.fact_name.value:
            return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
        if response["state"] not in ("PRESENT", "ABSENT"):
            return GitHubNormalizationResult(failure=StateReadFailure.MALFORMED_RESPONSE)
        value = response["value"]
        if response["state"] == "ABSENT" and value is not None:
            return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
        if type(value) not in (str, int, bool) and value is not None:
            return GitHubNormalizationResult(failure=StateReadFailure.MALFORMED_RESPONSE)
        return _ok(f"registered:{request.fact_name.value}", (request.repository_id.value, request.fact_name.value, response["state"], value))


def _ok(key: str, value: tuple) -> GitHubNormalizationResult:
    return GitHubNormalizationResult(observation=NormalizedGitHubObservation(key, value))


@dataclass(frozen=True, slots=True, init=False)
class TrustedGitHubReadTransportBinding:
    config_id: ImmutableConfigId
    expected_api_host_identity: ImmutableConfigId
    authentication_mode_identity: ImmutableConfigId
    service_identity: ServicePrincipalId
    permitted_repository_ids: tuple[GitHubRepositoryId, ...]
    transport_profile_id: ImmutableConfigId

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("transport binding must come from root-managed configuration")


class AuthenticatedGitHubReadTransport:
    """Opaque production transport handle; no constructor or write surface."""

    __slots__ = ("_binding", "_executor")

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("authenticated transport must come from the trusted transport boundary")

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("authenticated transport binding is immutable")

    @property
    def binding(self) -> TrustedGitHubReadTransportBinding:
        return self._binding

    def read(self, request: GitHubReadRequest, cursor: str | None = None) -> object:
        return self._executor(request, cursor)


@dataclass(frozen=True, slots=True, init=False)
class RegisteredStateFactDescriptor:
    descriptor_id: LogicalIdentifier
    request: GitHubReadRequest

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("registered fact descriptors must come from trusted configuration")


@dataclass(frozen=True, slots=True, init=False)
class AuthoritativeObservationProfile:
    profile_id: ImmutableConfigId
    registered_fact_descriptors: tuple[RegisteredStateFactDescriptor, ...]

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("observation profile must come from trusted configuration")


@dataclass(frozen=True, slots=True)
class AuthoritativeStateSnapshot:
    repository_id: GitHubRepositoryId
    observation_profile_id: ImmutableConfigId
    transport_config_id: ImmutableConfigId
    observations: tuple[NormalizedGitHubObservation, ...]

    def __post_init__(self) -> None:
        if type(self.repository_id) is not GitHubRepositoryId or type(self.observation_profile_id) is not ImmutableConfigId or type(self.transport_config_id) is not ImmutableConfigId:
            raise TypeError("authoritative snapshot identity has wrong exact type")
        _tuple(self.observations, NormalizedGitHubObservation, "observations")
        keys = tuple(item.fact_key for item in self.observations)
        if keys != tuple(sorted(keys)) or len(set(keys)) != len(keys):
            raise ValueError("observations must be uniquely canonically ordered")


class AuthoritativeStateReadStatus(Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


@dataclass(frozen=True, slots=True)
class AuthoritativeStateReadResult:
    status: AuthoritativeStateReadStatus
    snapshot: AuthoritativeStateSnapshot | None = None
    binding_id: AuthoritativeStateBindingId | None = None
    failure: StateReadFailure | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not AuthoritativeStateReadStatus:
            raise TypeError("authoritative read status has wrong exact type")
        if self.status is AuthoritativeStateReadStatus.SUCCESS:
            if type(self.snapshot) is not AuthoritativeStateSnapshot or type(self.binding_id) is not AuthoritativeStateBindingId or self.failure is not None:
                raise ValueError("successful authoritative read must carry snapshot and binding only")
        elif self.snapshot is not None or self.binding_id is not None or type(self.failure) is not StateReadFailure:
            raise ValueError("failed authoritative read cannot carry authoritative state")


class GitHubStateReader:
    __slots__ = ("_binding", "_transport", "_normalizer", "_sealed")

    def __init__(
        self,
        transport_binding: TrustedGitHubReadTransportBinding,
        transport: AuthenticatedGitHubReadTransport,
        normalizer: GitHubStateNormalizer | None = None,
    ) -> None:
        if type(transport_binding) is not TrustedGitHubReadTransportBinding:
            raise TypeError("exact trusted transport binding required")
        exact_binding_fields = (
            (transport_binding.config_id, ImmutableConfigId),
            (transport_binding.expected_api_host_identity, ImmutableConfigId),
            (transport_binding.authentication_mode_identity, ImmutableConfigId),
            (transport_binding.service_identity, ServicePrincipalId),
            (transport_binding.transport_profile_id, ImmutableConfigId),
        )
        if any(type(value) is not expected for value, expected in exact_binding_fields):
            raise TypeError("trusted transport binding contains malformed identities")
        _tuple(transport_binding.permitted_repository_ids, GitHubRepositoryId, "permitted_repository_ids")
        if type(transport) is not AuthenticatedGitHubReadTransport or transport.binding != transport_binding:
            raise TypeError("exact authenticated transport bound to configuration required")
        if normalizer is not None and type(normalizer) is not GitHubStateNormalizer:
            raise TypeError("exact GitHubStateNormalizer required")
        object.__setattr__(self, "_binding", transport_binding)
        object.__setattr__(self, "_transport", transport)
        object.__setattr__(self, "_normalizer", normalizer or GitHubStateNormalizer())
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("authoritative reader transport cannot be replaced")
        object.__setattr__(self, name, value)

    def read_authoritative(
        self,
        repository_id: GitHubRepositoryId,
        profile: AuthoritativeObservationProfile,
    ) -> AuthoritativeStateReadResult:
        if type(repository_id) is not GitHubRepositoryId or type(profile) is not AuthoritativeObservationProfile:
            raise TypeError("trusted repository/profile inputs required")
        if type(profile.profile_id) is not ImmutableConfigId:
            return _failure(StateReadFailure.MALFORMED_RESPONSE)
        if repository_id not in self._binding.permitted_repository_ids:
            return _failure(StateReadFailure.MISMATCH)
        descriptors = profile.registered_fact_descriptors
        if type(descriptors) is not tuple or any(type(item) is not RegisteredStateFactDescriptor for item in descriptors):
            return _failure(StateReadFailure.MALFORMED_RESPONSE)
        request_types = (
            ReadRepositoryIdentity, ReadGitRef, ReadCommit, ReadCommitAncestry,
            ReadIssueIdentity, ReadPullRequest, ReadChangedFileInventory,
            ReadMergeState, ReadRegisteredEventSensitiveState,
        )
        if any(
            type(descriptor.descriptor_id) is not LogicalIdentifier
            or type(descriptor.request) not in request_types
            for descriptor in descriptors
        ):
            return _failure(StateReadFailure.MALFORMED_RESPONSE)
        if not descriptors or len({item.descriptor_id for item in descriptors}) != len(descriptors):
            return _failure(StateReadFailure.INCOMPLETE)
        observations: list[NormalizedGitHubObservation] = []
        for descriptor in descriptors:
            if descriptor.request.repository_id != repository_id:
                return _failure(StateReadFailure.MISMATCH)
            result = self._read_one(descriptor.request)
            if result.failure is not None:
                return _failure(result.failure)
            observations.append(result.observation)
        ordered = tuple(sorted(observations, key=lambda item: item.fact_key))
        if len({item.fact_key for item in ordered}) != len(ordered):
            return _failure(StateReadFailure.INCOMPLETE)
        snapshot = AuthoritativeStateSnapshot(
            repository_id, profile.profile_id, self._binding.config_id, ordered
        )
        return AuthoritativeStateReadResult(
            AuthoritativeStateReadStatus.SUCCESS,
            snapshot,
            _authoritative_binding(snapshot),
        )

    def _read_one(self, request: GitHubReadRequest) -> GitHubNormalizationResult:
        if type(request) is ReadChangedFileInventory:
            return self._changed_files(request)
        try:
            raw = self._transport.read(request)
        except Exception:
            return GitHubNormalizationResult(failure=StateReadFailure.UNAVAILABLE)
        return self._normalizer.normalize(request, raw)

    def _changed_files(self, request: ReadChangedFileInventory) -> GitHubNormalizationResult:
        context_request = ReadPullRequest(request.repository_id, request.pull_request_number)
        try:
            before_raw = self._transport.read(context_request)
            before = self._normalizer.normalize(context_request, before_raw)
            if before.failure is not None:
                return before
            cursor = None
            files: list[tuple] = []
            seen_paths: set[str] = set()
            seen_cursors: set[str] = set()
            page_count = 0
            while True:
                page_count += 1
                if page_count > G6_MAX_CHANGED_FILE_PAGES:
                    return GitHubNormalizationResult(failure=StateReadFailure.INCOMPLETE)
                page = self._transport.read(request, cursor)
                if type(page) is not dict or set(page) != {"repository_id", "number", "items", "next_cursor", "complete"}:
                    return GitHubNormalizationResult(failure=StateReadFailure.MALFORMED_RESPONSE)
                if page["repository_id"] != request.repository_id.value or page["number"] != request.pull_request_number.value:
                    return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
                if type(page["items"]) is not list or type(page["complete"]) is not bool:
                    return GitHubNormalizationResult(failure=StateReadFailure.MALFORMED_RESPONSE)
                for item in page["items"]:
                    if type(item) is not dict or set(item) != {"path", "status", "previous_path", "blob_sha"}:
                        return GitHubNormalizationResult(failure=StateReadFailure.MALFORMED_RESPONSE)
                    path, status = CanonicalGitPath(item["path"]).value, item["status"]
                    previous_path, blob = item["previous_path"], item["blob_sha"]
                    if path in seen_paths or status not in ("added", "modified", "removed", "renamed"):
                        return GitHubNormalizationResult(failure=StateReadFailure.MALFORMED_RESPONSE)
                    if status == "renamed":
                        previous_path = CanonicalGitPath(previous_path).value
                        if previous_path == path:
                            return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
                    elif previous_path is not None:
                        return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
                    if status == "removed":
                        if blob is not None:
                            return GitHubNormalizationResult(failure=StateReadFailure.MISMATCH)
                    else:
                        blob = GitSha(blob).value
                    seen_paths.add(path)
                    files.append((path, status, previous_path, blob))
                    if len(files) > G6_MAX_CHANGED_FILES:
                        return GitHubNormalizationResult(failure=StateReadFailure.INCOMPLETE)
                next_cursor = page["next_cursor"]
                if next_cursor is not None and (type(next_cursor) is not str or not next_cursor or next_cursor in seen_cursors):
                    return GitHubNormalizationResult(failure=StateReadFailure.INCOMPLETE)
                if page["complete"]:
                    if next_cursor is not None:
                        return GitHubNormalizationResult(failure=StateReadFailure.INCOMPLETE)
                    break
                if next_cursor is None:
                    return GitHubNormalizationResult(failure=StateReadFailure.INCOMPLETE)
                seen_cursors.add(next_cursor)
                cursor = next_cursor
            after_raw = self._transport.read(context_request)
            after = self._normalizer.normalize(context_request, after_raw)
            if after.failure is not None:
                if after.failure is StateReadFailure.MISMATCH:
                    return GitHubNormalizationResult(failure=StateReadFailure.STATE_MOVED)
                return after
            if before.observation != after.observation:
                return GitHubNormalizationResult(failure=StateReadFailure.STATE_MOVED)
            return _ok(
                f"changed-files:{request.pull_request_number.value}",
                (request.repository_id.value, request.pull_request_number.value, tuple(sorted(files))),
            )
        except (TypeError, ValueError, KeyError):
            return GitHubNormalizationResult(failure=StateReadFailure.MALFORMED_RESPONSE)
        except Exception:
            return GitHubNormalizationResult(failure=StateReadFailure.UNAVAILABLE)


def authoritative_state_binding(snapshot: AuthoritativeStateSnapshot) -> AuthoritativeStateBindingId:
    if type(snapshot) is not AuthoritativeStateSnapshot:
        raise TypeError("exact AuthoritativeStateSnapshot required")
    payload = (
        "autodev.authoritative-state-binding/v1",
        snapshot.repository_id.value,
        snapshot.observation_profile_id.value,
        snapshot.transport_config_id.value,
        tuple((item.fact_key, item.fact_value) for item in snapshot.observations),
    )
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return AuthoritativeStateBindingId(hashlib.sha256(raw).hexdigest())


_authoritative_binding = authoritative_state_binding


def authoritative_state_binding_from_result(
    result: AuthoritativeStateReadResult,
) -> AuthoritativeStateBindingId:
    if type(result) is not AuthoritativeStateReadResult or result.status is not AuthoritativeStateReadStatus.SUCCESS:
        raise ValueError("authoritative state binding requires a complete successful read")
    return result.binding_id


def _failure(reason: StateReadFailure) -> AuthoritativeStateReadResult:
    return AuthoritativeStateReadResult(AuthoritativeStateReadStatus.FAILURE, failure=reason)
