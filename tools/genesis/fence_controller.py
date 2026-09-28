"""External-only capability-fence controller for non-authoritative G9 tooling."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from root_admin import ROOT_STORE_PATH, _require_external_root_admin, compare_and_swap_fence


def set_fence(
    database: Path, *, expected_admin_sid: str, candidate_package_id: str,
    expected_revision: int, state: str,
) -> dict[str, object]:
    """Apply one profile-bound external-admin CAS; candidate roles have no entrypoint."""
    _require_external_root_admin(expected_admin_sid)
    revision = compare_and_swap_fence(
        database, expected_admin_sid=expected_admin_sid,
        candidate_package_id=candidate_package_id,
        expected_revision=expected_revision, new_state=state,
    )
    return {
        "candidate_package_id": candidate_package_id,
        "state": state,
        "revision": revision,
        "authority": "EXTERNAL_ROOT_ADMIN_ONLY",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="External G9 capability fence CAS")
    parser.add_argument("--database", type=Path, default=ROOT_STORE_PATH)
    parser.add_argument("--expected-admin-sid", required=True)
    parser.add_argument("--candidate-package-id", required=True)
    parser.add_argument("--expected-revision", required=True, type=int)
    parser.add_argument("--state", required=True, choices=("FENCED", "RELEASED"))
    args = parser.parse_args()
    try:
        result = set_fence(
            args.database, expected_admin_sid=args.expected_admin_sid,
            candidate_package_id=args.candidate_package_id,
            expected_revision=args.expected_revision, state=args.state,
        )
    except Exception as exc:
        print(json.dumps({"status": "FAILED_CLOSED", "failure_type": type(exc).__name__},
                         sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
