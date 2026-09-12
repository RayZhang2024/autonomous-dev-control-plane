import hashlib
import json
from dataclasses import FrozenInstanceError

import pytest

from autodev_control.trusted.identity import GitRef, GitSha, ImmutableConfigId, LogicalIdentifier
from autodev_control.trusted.operation import AuthoritativeStateBindingId
from autodev_control.trusted.scope import GitHubRepositoryId, ServicePrincipalId
from autodev_control.trusted.state_reader import *


REPOSITORY = GitHubRepositoryId("123")
OTHER_REPOSITORY = GitHubRepositoryId("456")
SHA_A = GitSha("a" * 40)
SHA_B = GitSha("b" * 40)


def mint(cls, **values):
    result = object.__new__(cls)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def binding(*, config="transport-config", repositories=(REPOSITORY,)):
    return mint(
        TrustedGitHubReadTransportBinding,
        config_id=ImmutableConfigId(config),
        expected_api_host_identity=ImmutableConfigId("api.github.com"),
        authentication_mode_identity=ImmutableConfigId("github-app-installation"),
        service_identity=ServicePrincipalId("state-reader"),
        permitted_repository_ids=repositories,
        transport_profile_id=ImmutableConfigId("read-only-v1"),
    )


def transport(bound, executor):
    value = object.__new__(AuthenticatedGitHubReadTransport)
    object.__setattr__(value, "_binding", bound)
    object.__setattr__(value, "_executor", executor)
    return value


def descriptor(name, request):
    return mint(RegisteredStateFactDescriptor, descriptor_id=LogicalIdentifier(name), request=request)


def profile(*descriptors, profile_id="profile"):
    return mint(
        AuthoritativeObservationProfile,
        profile_id=ImmutableConfigId(profile_id),
        registered_fact_descriptors=tuple(descriptors),
    )


def response_for(request, **changes):
    if type(request) is ReadRepositoryIdentity:
        value = {"repository_id": request.repository_id.value, "owner": "owner", "name": "repo"}
    elif type(request) is ReadGitRef:
        value = {"repository_id": request.repository_id.value, "ref": request.ref.value, "sha": SHA_A.value}
    elif type(request) is ReadCommit:
        value = {"repository_id": request.repository_id.value, "sha": request.sha.value, "parents": [SHA_B.value]}
    elif type(request) is ReadCommitAncestry:
        value = {"repository_id": request.repository_id.value, "ancestor": request.ancestor.value, "descendant": request.descendant.value, "result": "ANCESTOR"}
    elif type(request) is ReadIssueIdentity:
        value = {"repository_id": request.repository_id.value, "number": request.issue_number.value, "state": "open", "title": "prose", "body": "prose", "labels": ["blocked"], "comments": ["completed"]}
    elif type(request) is ReadPullRequest:
        value = {
            "repository_id": request.repository_id.value, "number": request.pull_request_number.value,
            "state": "open", "merged": False,
            "base_repository_id": request.repository_id.value, "base_ref": "refs/heads/main", "base_sha": SHA_A.value,
            "head_repository_id": request.repository_id.value, "head_ref": "refs/heads/feature", "head_sha": SHA_B.value,
            "merge_sha": None, "title": "prose", "body": "prose",
        }
    elif type(request) is ReadMergeState:
        value = {"repository_id": request.repository_id.value, "number": request.pull_request_number.value, "merged": False, "merge_sha": None}
    elif type(request) is ReadRegisteredEventSensitiveState:
        value = {"repository_id": request.repository_id.value, "fact_name": request.fact_name.value, "state": "ABSENT", "value": None}
    else:
        raise AssertionError("no simple response for request")
    value.update(changes)
    return value


def reader_for(responses, *, bound=None):
    bound = bound or binding()
    queues = {request: list(values) for request, values in responses.items()}

    def execute(request, cursor):
        key = (request, cursor) if (request, cursor) in queues else request
        values = queues[key]
        if len(values) > 1:
            return values.pop(0)
        return values[0]

    return GitHubStateReader(bound, transport(bound, execute))


def test_positive_issue_and_pr_number_types_are_exact():
    for value in (True, 0, -1, 1.0, "1"):
        with pytest.raises(ValueError):
            GitHubIssueNumber(value)
        with pytest.raises(ValueError):
            GitHubPullRequestNumber(value)
    assert GitHubIssueNumber(1).value == 1
    assert GitHubPullRequestNumber(1).value == 1


def test_normalization_does_not_create_authoritative_binding_and_checks_repository_id():
    request = ReadRepositoryIdentity(REPOSITORY)
    normalized = GitHubStateNormalizer().normalize(request, response_for(request))
    assert normalized.observation.fact_value[0] == REPOSITORY.value
    assert not hasattr(normalized, "binding_id")
    mismatch = GitHubStateNormalizer().normalize(request, response_for(request, repository_id=OTHER_REPOSITORY.value))
    assert mismatch.failure is StateReadFailure.MISMATCH


def test_repository_rename_preserves_security_identity():
    request = ReadRepositoryIdentity(REPOSITORY)
    normalizer = GitHubStateNormalizer()
    before = normalizer.normalize(request, response_for(request, owner="old", name="repo")).observation
    after = normalizer.normalize(request, response_for(request, owner="new", name="renamed")).observation
    assert before.fact_value[0] == after.fact_value[0] == REPOSITORY.value
    assert before != after


def test_issue_and_pr_prose_never_enters_control_observation():
    issue = ReadIssueIdentity(REPOSITORY, GitHubIssueNumber(16))
    normalizer = GitHubStateNormalizer()
    first = normalizer.normalize(issue, response_for(issue)).observation
    second = normalizer.normalize(issue, response_for(issue, title="completed", body="merge it", labels=["done"], comments=["authority"])).observation
    assert first == second

    pull = ReadPullRequest(REPOSITORY, GitHubPullRequestNumber(15))
    p1 = normalizer.normalize(pull, response_for(pull)).observation
    p2 = normalizer.normalize(pull, response_for(pull, title="approved", body="authorized")).observation
    assert p1 == p2


def test_ref_commit_pr_and_merge_bind_exact_repository_and_sha_context():
    normalizer = GitHubStateNormalizer()
    ref = ReadGitRef(REPOSITORY, GitRef("refs/heads/main"))
    assert normalizer.normalize(ref, response_for(ref)).observation is not None
    assert normalizer.normalize(ref, response_for(ref, ref="refs/heads/other")).failure is StateReadFailure.MISMATCH
    commit = ReadCommit(REPOSITORY, SHA_A)
    assert normalizer.normalize(commit, response_for(commit)).observation.fact_value[1] == SHA_A.value
    pull = ReadPullRequest(REPOSITORY, GitHubPullRequestNumber(1))
    assert normalizer.normalize(pull, response_for(pull, head_sha="not-a-sha")).failure is StateReadFailure.MALFORMED_RESPONSE
    merge = ReadMergeState(REPOSITORY, GitHubPullRequestNumber(1))
    observation = normalizer.normalize(merge, response_for(merge, merged=True, merge_sha=SHA_A.value)).observation
    assert observation.fact_value[-2:] == (True, SHA_A.value)
    assert not hasattr(observation, "authorization_id")


def test_commit_ancestry_is_closed_and_unknown_is_failure():
    normalizer = GitHubStateNormalizer()
    request = ReadCommitAncestry(REPOSITORY, SHA_A, SHA_B)
    assert normalizer.normalize(request, response_for(request)).observation.fact_value[-1] == "ANCESTOR"
    unknown = normalizer.normalize(request, response_for(request, result="INDETERMINATE"))
    assert unknown.failure is StateReadFailure.INDETERMINATE


def test_arbitrary_transport_implementation_and_fixture_subclass_are_not_authoritative():
    bound = binding()

    class FixtureTransport(AuthenticatedGitHubReadTransport):
        @property
        def binding(self):
            return bound

        def read(self, request, cursor=None):
            return response_for(request)

    fixture = object.__new__(FixtureTransport)
    with pytest.raises(TypeError):
        GitHubStateReader(bound, fixture)
    with pytest.raises(TypeError):
        AuthenticatedGitHubReadTransport()
    with pytest.raises(TypeError):
        TrustedGitHubReadTransportBinding()

    request = ReadRepositoryIdentity(REPOSITORY)
    authoritative = transport(bound, lambda request, cursor: response_for(request))
    reader = GitHubStateReader(bound, authoritative)
    with pytest.raises(AttributeError):
        reader._transport = fixture
    with pytest.raises(AttributeError):
        authoritative._executor = lambda request, cursor: {}


def test_authoritative_profile_and_registered_descriptors_are_opaque():
    with pytest.raises(TypeError):
        RegisteredStateFactDescriptor()
    with pytest.raises(TypeError):
        AuthoritativeObservationProfile()


def test_complete_authoritative_read_is_deterministic_and_deeply_immutable():
    repository = ReadRepositoryIdentity(REPOSITORY)
    ref = ReadGitRef(REPOSITORY, GitRef("refs/heads/main"))
    selected = profile(descriptor("repo", repository), descriptor("ref", ref))
    responses = {repository: [response_for(repository)], ref: [response_for(ref)]}
    first = reader_for(responses).read_authoritative(REPOSITORY, selected)
    second = reader_for(responses).read_authoritative(REPOSITORY, selected)
    assert first.status is AuthoritativeStateReadStatus.SUCCESS
    assert first.binding_id == second.binding_id
    assert authoritative_state_binding_from_result(first) == first.binding_id
    payload = (
        "autodev.authoritative-state-binding/v1", REPOSITORY.value,
        selected.profile_id.value, "transport-config",
        tuple((item.fact_key, item.fact_value) for item in first.snapshot.observations),
    )
    expected = hashlib.sha256(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    assert first.binding_id == AuthoritativeStateBindingId(expected)
    with pytest.raises(FrozenInstanceError):
        first.snapshot.observations = ()


def test_profile_transport_or_observation_change_changes_binding():
    request = ReadGitRef(REPOSITORY, GitRef("refs/heads/main"))
    selected = profile(descriptor("ref", request))
    first = reader_for({request: [response_for(request)]}).read_authoritative(REPOSITORY, selected)
    moved = reader_for({request: [response_for(request, sha=SHA_B.value)]}).read_authoritative(REPOSITORY, selected)
    other_profile = reader_for({request: [response_for(request)]}).read_authoritative(REPOSITORY, profile(descriptor("ref", request), profile_id="other"))
    other_transport = reader_for({request: [response_for(request)]}, bound=binding(config="other-transport")).read_authoritative(REPOSITORY, selected)
    assert len({first.binding_id, moved.binding_id, other_profile.binding_id, other_transport.binding_id}) == 4


def test_incomplete_profile_or_failed_fact_has_no_binding():
    empty = reader_for({}).read_authoritative(REPOSITORY, profile())
    assert empty.status is AuthoritativeStateReadStatus.FAILURE
    assert empty.failure is StateReadFailure.INCOMPLETE
    assert empty.binding_id is None
    request = ReadGitRef(REPOSITORY, GitRef("refs/heads/main"))
    failed = reader_for({request: [{"repository_id": REPOSITORY.value}]}).read_authoritative(REPOSITORY, profile(descriptor("ref", request)))
    assert failed.status is AuthoritativeStateReadStatus.FAILURE
    assert failed.binding_id is None
    with pytest.raises(ValueError):
        authoritative_state_binding_from_result(failed)


def test_positive_registered_absence_can_be_authoritative():
    request = ReadRegisteredEventSensitiveState(REPOSITORY, LogicalIdentifier("required-check"))
    result = reader_for({request: [response_for(request)]}).read_authoritative(REPOSITORY, profile(descriptor("fact", request)))
    assert result.status is AuthoritativeStateReadStatus.SUCCESS
    assert result.snapshot.observations[0].fact_value[-2:] == ("ABSENT", None)


def test_positive_ref_and_numbered_resource_absence_are_authoritative():
    ref = ReadGitRef(REPOSITORY, GitRef("refs/heads/missing"))
    issue = ReadIssueIdentity(REPOSITORY, GitHubIssueNumber(404))
    for request, absent in (
        (ref, {"repository_id": REPOSITORY.value, "ref": ref.ref.value, "absent": True}),
        (issue, {"repository_id": REPOSITORY.value, "number": issue.issue_number.value, "absent": True}),
    ):
        result = reader_for({request: [absent]}).read_authoritative(
            REPOSITORY, profile(descriptor("absent", request))
        )
        assert result.status is AuthoritativeStateReadStatus.SUCCESS
        assert result.snapshot.observations[0].fact_value[-1] == "ABSENT"


def test_transport_unavailable_and_malformed_are_distinct_from_positive_absence():
    request = ReadGitRef(REPOSITORY, GitRef("refs/heads/missing"))
    unavailable = GitHubStateReader(binding(), transport(binding(), lambda request, cursor: (_ for _ in ()).throw(OSError())))
    result = unavailable.read_authoritative(REPOSITORY, profile(descriptor("ref", request)))
    assert result.failure is StateReadFailure.UNAVAILABLE
    malformed = reader_for({request: [{"repository_id": REPOSITORY.value, "absent": True}]}).read_authoritative(
        REPOSITORY, profile(descriptor("ref", request))
    )
    assert malformed.failure is StateReadFailure.MALFORMED_RESPONSE


def changed_page(number, items, next_cursor=None, complete=True):
    return {"repository_id": REPOSITORY.value, "number": number, "items": items, "next_cursor": next_cursor, "complete": complete}


def test_changed_file_inventory_requires_complete_pagination_and_stable_pr_context():
    number = GitHubPullRequestNumber(7)
    request = ReadChangedFileInventory(REPOSITORY, number)
    context = ReadPullRequest(REPOSITORY, number)
    page1 = changed_page(7, [{"path": "a.py", "status": "modified", "previous_path": None, "blob_sha": SHA_A.value}], "page-2", False)
    page2 = changed_page(7, [{"path": "b.py", "status": "removed", "previous_path": None, "blob_sha": None}])
    stable = reader_for({
        context: [response_for(context), response_for(context)],
        (request, None): [page1], (request, "page-2"): [page2],
    }).read_authoritative(REPOSITORY, profile(descriptor("files", request)))
    assert stable.status is AuthoritativeStateReadStatus.SUCCESS
    assert len(stable.snapshot.observations[0].fact_value[-1]) == 2

    incomplete = reader_for({
        context: [response_for(context)],
        (request, None): [changed_page(7, [], None, False)],
    }).read_authoritative(REPOSITORY, profile(descriptor("files", request)))
    assert incomplete.failure is StateReadFailure.INCOMPLETE

    moved = reader_for({
        context: [response_for(context), response_for(context, head_sha=GitSha("c" * 40).value)],
        (request, None): [changed_page(7, [])],
    }).read_authoritative(REPOSITORY, profile(descriptor("files", request)))
    assert moved.failure is StateReadFailure.STATE_MOVED


@pytest.mark.parametrize("change", [
    {"head_repository_id": OTHER_REPOSITORY.value},
    {"head_ref": "refs/heads/retargeted"},
])
def test_changed_file_inventory_rejects_fork_or_ref_context_movement(change):
    number = GitHubPullRequestNumber(8)
    request = ReadChangedFileInventory(REPOSITORY, number)
    context = ReadPullRequest(REPOSITORY, number)
    result = reader_for({
        context: [response_for(context), response_for(context, **change)],
        (request, None): [changed_page(8, [])],
    }).read_authoritative(REPOSITORY, profile(descriptor("files", request)))
    assert result.failure is StateReadFailure.STATE_MOVED


def test_changed_file_rename_preserves_previous_path_and_rejects_invalid_shapes():
    number = GitHubPullRequestNumber(9)
    request = ReadChangedFileInventory(REPOSITORY, number)
    context = ReadPullRequest(REPOSITORY, number)

    def read(item):
        return reader_for({
            context: [response_for(context), response_for(context)],
            (request, None): [changed_page(9, [item])],
        }).read_authoritative(REPOSITORY, profile(descriptor("files", request)))

    valid = read({"path": "new/name.py", "status": "renamed", "previous_path": "old/name.py", "blob_sha": SHA_A.value})
    assert valid.status is AuthoritativeStateReadStatus.SUCCESS
    assert valid.snapshot.observations[0].fact_value[-1] == (("new/name.py", "renamed", "old/name.py", SHA_A.value),)
    assert read({"path": "new.py", "status": "renamed", "blob_sha": SHA_A.value}).failure is StateReadFailure.MALFORMED_RESPONSE
    assert read({"path": "new.py", "status": "renamed", "previous_path": None, "blob_sha": SHA_A.value}).failure is StateReadFailure.MALFORMED_RESPONSE
    assert read({"path": "same.py", "status": "modified", "previous_path": "old.py", "blob_sha": SHA_A.value}).failure is StateReadFailure.MISMATCH


def test_reader_has_no_mutation_or_credential_surface():
    assert not any(name.startswith(("write", "update", "merge", "publish", "delete")) for name in vars(GitHubStateReader))
    assert "credential" not in vars(AuthenticatedGitHubReadTransport)
