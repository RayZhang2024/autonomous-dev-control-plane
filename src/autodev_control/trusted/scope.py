"""Nominal G3 identities, risk relation, refs, and logical mutation-scope algebra."""

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

from .errors import IdentityValidationError
from .identity import LogicalIdentifier, RawSha256

G3_MAX_SCOPE_RULES = 1024
G3_MAX_CAPABILITIES = 9
G3_MAX_PROFILE_IDS = 256
G3_MAX_PROTECTED_REFS = 256
G3_MAX_DELEGATION_DEPTH = 64


class TaskCapability(Enum):
    IMPLEMENTATION = "implementation"
    CANDIDATE_MATERIALIZATION = "candidate_materialization"
    TARGET_PUBLISH = "target_publish"
    DETERMINISTIC_VALIDATION = "deterministic_validation"
    SEMANTIC_REVIEW = "semantic_review"
    CONTROLLED_RUNTIME = "controlled_runtime"
    EXTERNAL_OBSERVATION = "external_observation"
    REPAIR = "repair"
    MERGE = "merge"


class AuthorizationKind(Enum):
    DIRECT_HUMAN = "direct_human"
    DELEGATED = "delegated"


class RiskTier(Enum):
    ROUTINE = "routine"
    SUPERVISED = "supervised"


class ChangeType(Enum):
    ADD = "add"
    MODIFY = "modify"
    DELETE = "delete"
    MODE_CHANGE = "mode_change"


def _logical(value: object) -> None:
    LogicalIdentifier(value)


@dataclass(frozen=True, slots=True)
class HumanPrincipalId:
    value: str

    def __post_init__(self) -> None:
        _logical(self.value)


@dataclass(frozen=True, slots=True)
class ServicePrincipalId:
    value: str

    def __post_init__(self) -> None:
        _logical(self.value)


@dataclass(frozen=True, slots=True)
class TaskId:
    value: str

    def __post_init__(self) -> None:
        _logical(self.value)


@dataclass(frozen=True, slots=True)
class ContractId:
    value: str

    def __post_init__(self) -> None:
        _logical(self.value)


@dataclass(frozen=True, slots=True)
class AuthenticationEventId:
    value: str

    def __post_init__(self) -> None:
        _logical(self.value)


@dataclass(frozen=True, slots=True)
class GitHubRepositoryId:
    value: str

    def __post_init__(self) -> None:
        if (
            type(self.value) is not str
            or not 1 <= len(self.value) <= 20
            or not self.value.isascii()
            or not self.value.isdecimal()
            or self.value[0] == "0"
        ):
            raise ValueError("invalid canonical GitHub repository ID")


@dataclass(frozen=True, slots=True)
class TargetRegistrationId:
    raw_sha256: RawSha256

    def __post_init__(self) -> None:
        if type(self.raw_sha256) is not RawSha256:
            raise TypeError("raw_sha256 must be exactly RawSha256")


@dataclass(frozen=True, slots=True)
class AuthorizationId:
    raw_sha256: RawSha256

    def __post_init__(self) -> None:
        if type(self.raw_sha256) is not RawSha256:
            raise TypeError("raw_sha256 must be exactly RawSha256")


@dataclass(frozen=True, slots=True)
class CanonicalGitPath:
    value: str

    def __post_init__(self) -> None:
        value = self.value
        if type(value) is not str or not 1 <= len(value) <= 4096:
            raise ValueError("invalid logical Git path")
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise ValueError("invalid logical Git path")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("invalid logical Git path") from error
        if (
            value.startswith("/")
            or value.endswith("/")
            or "\x00" in value
            or "\\" in value
        ):
            raise ValueError("invalid logical Git path")
        components = value.split("/")
        if any(component in ("", ".", "..") for component in components):
            raise ValueError("invalid logical Git path")


@dataclass(frozen=True, slots=True)
class CanonicalBranchRef:
    value: str

    def __post_init__(self) -> None:
        value = self.value
        forbidden = " ~^:?*[\\"
        if type(value) is not str or not 1 <= len(value) <= 1024:
            raise ValueError("invalid canonical branch ref")
        if not value.startswith("refs/heads/") or value == "refs/heads/":
            raise ValueError("invalid canonical branch ref")
        if any(ord(char) <= 0x1F or ord(char) == 0x7F or char in forbidden for char in value):
            raise ValueError("invalid canonical branch ref")
        if ".." in value or "@{" in value or "//" in value or value.endswith(("/", ".")):
            raise ValueError("invalid canonical branch ref")
        tail = value[len("refs/heads/") :]
        if any(
            not component or component.startswith(".") or component.endswith(".lock")
            for component in tail.split("/")
        ):
            raise ValueError("invalid canonical branch ref")


@dataclass(frozen=True, slots=True)
class RepositorySelector:
    pass


@dataclass(frozen=True, slots=True)
class ExactPathSelector:
    path: CanonicalGitPath

    def __post_init__(self) -> None:
        if type(self.path) is not CanonicalGitPath:
            raise TypeError("path must be exactly CanonicalGitPath")


@dataclass(frozen=True, slots=True)
class PathPrefixSelector:
    path_prefix: CanonicalGitPath

    def __post_init__(self) -> None:
        if type(self.path_prefix) is not CanonicalGitPath:
            raise TypeError("path_prefix must be exactly CanonicalGitPath")


MutationSelector = RepositorySelector | ExactPathSelector | PathPrefixSelector


def _exact_tuple_of(values: object, item_type: type, maximum: int | None = None) -> tuple:
    if type(values) is not tuple:
        raise TypeError("canonical collection must be exactly tuple")
    if maximum is not None and len(values) > maximum:
        raise ValueError("canonical collection exceeds hard maximum")
    seen: set[object] = set()
    for value in values:
        if type(value) is not item_type:
            raise TypeError("canonical collection item has wrong exact type")
        if value in seen:
            raise ValueError("duplicate canonical identity")
        seen.add(value)
    return values


@dataclass(frozen=True, slots=True)
class MutationScopeRule:
    selector: MutationSelector
    change_types: tuple[ChangeType, ...]

    def __post_init__(self) -> None:
        if type(self.selector) not in (RepositorySelector, ExactPathSelector, PathPrefixSelector):
            raise TypeError("selector has wrong exact type")
        _exact_tuple_of(self.change_types, ChangeType, len(ChangeType))
        if not self.change_types:
            raise ValueError("change_types must be non-empty")

    def semantic_key(self) -> tuple[object, frozenset[ChangeType]]:
        return (self.selector, frozenset(self.change_types))


@dataclass(frozen=True, slots=True)
class MutationScope:
    rules: tuple[MutationScopeRule, ...]

    def __post_init__(self) -> None:
        if type(self.rules) is not tuple or len(self.rules) > G3_MAX_SCOPE_RULES:
            raise ValueError("invalid mutation scope")
        seen: set[tuple[object, frozenset[ChangeType]]] = set()
        for rule in self.rules:
            if type(rule) is not MutationScopeRule:
                raise TypeError("scope rule has wrong exact type")
            key = rule.semantic_key()
            if key in seen:
                raise ValueError("duplicate semantic scope rule")
            seen.add(key)


def selector_contains(parent: MutationSelector, child: MutationSelector) -> bool:
    if type(parent) is RepositorySelector:
        return True
    if type(parent) is ExactPathSelector:
        return type(child) is ExactPathSelector and parent.path == child.path
    if type(parent) is PathPrefixSelector:
        prefix = parent.path_prefix.value
        if type(child) is ExactPathSelector:
            value = child.path.value
        elif type(child) is PathPrefixSelector:
            value = child.path_prefix.value
        else:
            return False
        return value == prefix or value.startswith(prefix + "/")
    return False


def selector_overlaps(left: MutationSelector, right: MutationSelector) -> bool:
    return selector_contains(left, right) or selector_contains(right, left)


def scope_contains(parent: MutationScope, child: MutationScope) -> bool:
    if type(parent) is not MutationScope or type(child) is not MutationScope:
        raise TypeError("scope arguments must be exact MutationScope")
    return all(
        any(selector_contains(parent_rule.selector, child_rule.selector) and change in parent_rule.change_types
            for parent_rule in parent.rules)
        for child_rule in child.rules
        for change in child_rule.change_types
    )


def scopes_overlap(left: MutationScope, right: MutationScope) -> bool:
    if type(left) is not MutationScope or type(right) is not MutationScope:
        raise TypeError("scope arguments must be exact MutationScope")
    return any(
        selector_overlaps(left_rule.selector, right_rule.selector)
        and bool(set(left_rule.change_types).intersection(right_rule.change_types))
        for left_rule in left.rules
        for right_rule in right.rules
    )


@dataclass(frozen=True, slots=True)
class RiskRelation:
    relations: tuple[tuple[RiskTier, RiskTier], ...]

    def __post_init__(self) -> None:
        if type(self.relations) is not tuple:
            raise TypeError("relations must be exactly tuple")
        relation_set: set[tuple[RiskTier, RiskTier]] = set()
        for edge in self.relations:
            if (
                type(edge) is not tuple
                or len(edge) != 2
                or type(edge[0]) is not RiskTier
                or type(edge[1]) is not RiskTier
            ):
                raise TypeError("risk edge must contain exact RiskTier values")
            if edge in relation_set:
                raise ValueError("duplicate risk edge")
            relation_set.add(edge)
        if any((tier, tier) not in relation_set for tier in RiskTier):
            raise ValueError("risk relation must be reflexive")
        for left, middle in relation_set:
            for middle_again, right in relation_set:
                if middle is middle_again and (left, right) not in relation_set:
                    raise ValueError("risk relation must be transitive")

    def leq(self, left: RiskTier, right: RiskTier) -> bool:
        if type(left) is not RiskTier or type(right) is not RiskTier:
            raise TypeError("risk operands must be exact RiskTier")
        return (left, right) in self.relations


def compare_risk(relation: RiskRelation, lower: RiskTier, upper: RiskTier) -> bool | None:
    if relation.leq(lower, upper):
        return True
    if relation.leq(upper, lower):
        return False
    return None


@dataclass(frozen=True, slots=True)
class ScopeParseProblem:
    kind: str


@dataclass(frozen=True, slots=True)
class ParsedMutationScope:
    rules: tuple[MutationScopeRule, ...]
    has_duplicates: bool


def _field_problem(value: object, fields: tuple[str, ...]) -> str | None:
    if type(value) is not MappingProxyType:
        return "type"
    if any(field not in value for field in fields):
        return "missing"
    allowed = frozenset(fields)
    if any(field not in allowed for field in value):
        return "unknown"
    return None


def parse_mutation_scope_json(
    value: object, *, defer_duplicates: bool = False
) -> MutationScope | ParsedMutationScope | ScopeParseProblem:
    if type(value) is not tuple:
        return ScopeParseProblem("type")
    if len(value) > G3_MAX_SCOPE_RULES:
        return ScopeParseProblem("value")
    rules: list[MutationScopeRule] = []
    keys: set[tuple[object, frozenset[ChangeType]]] = set()
    has_duplicates = False
    for item in value:
        problem = _field_problem(item, ("selector", "change_types"))
        if problem is not None:
            return ScopeParseProblem(problem)
        selector_value = item["selector"]
        if type(selector_value) is not MappingProxyType:
            return ScopeParseProblem("type")
        if type(item["change_types"]) is not tuple:
            return ScopeParseProblem("type")
        if "kind" not in selector_value:
            return ScopeParseProblem("missing")
        if type(selector_value["kind"]) is not str:
            return ScopeParseProblem("type")
        kind = selector_value["kind"]
        expected = {"repository": ("kind",), "exact_path": ("kind", "path"), "path_prefix": ("kind", "path_prefix")}
        if kind not in expected:
            return ScopeParseProblem("value")
        problem = _field_problem(selector_value, expected[kind])
        if problem is not None:
            return ScopeParseProblem(problem)
        try:
            if kind == "repository":
                selector: MutationSelector = RepositorySelector()
            elif kind == "exact_path":
                if type(selector_value["path"]) is not str:
                    return ScopeParseProblem("type")
                selector = ExactPathSelector(CanonicalGitPath(selector_value["path"]))
            else:
                if type(selector_value["path_prefix"]) is not str:
                    return ScopeParseProblem("type")
                selector = PathPrefixSelector(CanonicalGitPath(selector_value["path_prefix"]))
        except ValueError:
            return ScopeParseProblem("value")
        if len(item["change_types"]) > len(ChangeType):
            return ScopeParseProblem("value")
        changes: list[ChangeType] = []
        seen_changes: set[ChangeType] = set()
        for raw_change in item["change_types"]:
            if type(raw_change) is not str:
                return ScopeParseProblem("type")
            try:
                change = ChangeType(raw_change)
            except ValueError:
                return ScopeParseProblem("value")
            if change in seen_changes:
                if not defer_duplicates:
                    return ScopeParseProblem("duplicate")
                has_duplicates = True
                continue
            seen_changes.add(change)
            changes.append(change)
        if not changes:
            return ScopeParseProblem("empty")
        rule = MutationScopeRule(selector, tuple(changes))
        key = rule.semantic_key()
        if key in keys:
            if not defer_duplicates:
                return ScopeParseProblem("duplicate")
            has_duplicates = True
        keys.add(key)
        rules.append(rule)
    parsed_rules = tuple(rules)
    if defer_duplicates:
        return ParsedMutationScope(parsed_rules, has_duplicates)
    return MutationScope(parsed_rules)
