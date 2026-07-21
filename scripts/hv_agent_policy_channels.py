"""Deterministic policy-channel selection, promotion, and rollback state.

The public authority repository owns one channel document.  Consumers select a
lock by immutable repository node ID, while promotion tooling advances the
stable lock only after exact canary evidence and retains one rollback lock
until post-promotion smoke evidence is complete.
"""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import re
from typing import Any


CHANNEL_SCHEMA = "hv-agent-policy-channels:v1"
EVIDENCE_SCHEMA = "hv-agent-policy-channel-evidence:v1"
LOCK_SCHEMA = "hv-agent-policy-lock:v1"
LOCK_FIELDS = {
    "schema", "artifact", "generation", "policy_revision",
    "source_commit", "source_tree_sha256",
}
STATE_FIELDS = {
    "schema", "revision", "default_channel", "channels", "assignments",
    "promotion", "transition",
}
PROMOTION_FIELDS = {
    "phase", "candidate", "previous_stable", "canary_repository_ids",
    "smoke_repository_ids", "canary_evidence_sha256",
}
TRANSITION_FIELDS = {
    "action", "from_revision", "to_revision", "artifact",
    "previous_artifact", "evidence_sha256",
}
EVIDENCE_FIELDS = {
    "schema", "phase", "state_revision", "artifact", "generation", "results", "errors",
}
RESULT_FIELDS = {
    "repository_id", "default_branch", "head_oid", "workflow_path", "run_id",
    "started_at", "conclusion", "selected_channel", "selected_artifact",
}
EVIDENCE_ERROR_FIELDS = {"repository_id", "code"}
EVIDENCE_ERROR_CODES = {"collection-failed"}
CHANNEL_NAME = re.compile(r"[a-z][a-z0-9-]{0,31}")
REPOSITORY_ID = re.compile(r"R_[A-Za-z0-9]+")
ARTIFACT = re.compile(r"ghcr\.io/happyvertical/agent-policy@sha256:[0-9a-f]{64}")
OID = re.compile(r"[0-9a-f]{40}")
TREE = re.compile(r"[0-9a-f]{64}")
WORKFLOW = re.compile(r"\.github/workflows/[A-Za-z0-9._-]+\.ya?ml")
CONCLUSIONS = {"success", "failure", "cancelled", "timed_out"}
RESERVED_CHANNELS = {"stable", "candidate", "rollback"}
AUTHORITY_REPOSITORY_ID = "R_kgDOQ09NVg"


class PolicyChannelError(ValueError):
    """Raised when a channel transition would weaken or race policy state."""


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def policy_lock_errors(value: Any, label: str = "policy lock") -> list[str]:
    if not isinstance(value, dict):
        return [f"{label} must be an object"]
    errors: list[str] = []
    if set(value) != LOCK_FIELDS:
        errors.append(f"{label} has unexpected or missing fields")
    if value.get("schema") != LOCK_SCHEMA:
        errors.append(f"{label} has an unsupported schema")
    artifact = value.get("artifact")
    if not isinstance(artifact, str) or not ARTIFACT.fullmatch(artifact):
        errors.append(f"{label} artifact must be the immutable HappyVertical policy digest")
    generation = value.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        errors.append(f"{label} generation must be a positive integer")
    revision = value.get("policy_revision")
    if not isinstance(revision, str) or not revision:
        errors.append(f"{label} policy_revision must be a non-empty string")
    commit = value.get("source_commit")
    if not isinstance(commit, str) or not OID.fullmatch(commit):
        errors.append(f"{label} source_commit must be a lowercase 40-character Git OID")
    tree = value.get("source_tree_sha256")
    if not isinstance(tree, str) or not TREE.fullmatch(tree):
        errors.append(f"{label} source_tree_sha256 must be a lowercase SHA-256")
    return errors


def _repository_ids(value: Any, label: str) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    if not isinstance(value, list):
        return [], [f"{label} must be an array"]
    ids: list[str] = []
    for repository_id in value:
        if not isinstance(repository_id, str) or not REPOSITORY_ID.fullmatch(repository_id):
            errors.append(f"{label} contains an invalid repository node ID")
            continue
        ids.append(repository_id)
    if len(ids) != len(set(ids)):
        errors.append(f"{label} must not contain duplicates")
    if ids != sorted(ids):
        errors.append(f"{label} must be sorted")
    return ids, errors


def channel_state_errors(value: Any, label: str = "policy channel state") -> list[str]:
    if not isinstance(value, dict):
        return [f"{label} must be an object"]
    errors: list[str] = []
    if set(value) != STATE_FIELDS:
        errors.append(f"{label} has unexpected or missing fields")
    if value.get("schema") != CHANNEL_SCHEMA:
        errors.append(f"{label} has an unsupported schema")
    revision = value.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        errors.append(f"{label} revision must be a positive integer")
    if value.get("default_channel") != "stable":
        errors.append(f"{label} default_channel must be stable")

    channels = value.get("channels")
    if not isinstance(channels, dict):
        channels = {}
        errors.append(f"{label} channels must be an object")
    if "stable" not in channels:
        errors.append(f"{label} channels must contain stable")
    for name, lock in channels.items():
        if not isinstance(name, str) or not CHANNEL_NAME.fullmatch(name):
            errors.append(f"{label} contains invalid channel name {name!r}")
            continue
        errors.extend(policy_lock_errors(lock, f"{label} channel {name}"))

    assignments = value.get("assignments")
    if not isinstance(assignments, dict):
        assignments = {}
        errors.append(f"{label} assignments must be an object")
    for repository_id, channel in assignments.items():
        if not isinstance(repository_id, str) or not REPOSITORY_ID.fullmatch(repository_id):
            errors.append(f"{label} assignment has invalid repository node ID")
        if not isinstance(channel, str) or channel not in channels:
            errors.append(f"{label} assignment {repository_id} selects an unknown channel")
        if channel == "rollback":
            errors.append(f"{label} rollback cannot be assigned directly")

    transition = value.get("transition")
    if not isinstance(transition, dict) or set(transition) != TRANSITION_FIELDS:
        errors.append(f"{label} transition has unexpected or missing fields")
    else:
        action = transition.get("action")
        if action not in {
            "bootstrap", "set-channel", "sync-fleet", "prepare", "abort",
            "promote", "finalize", "rollback",
        }:
            errors.append(f"{label} transition action is invalid")
        from_revision = transition.get("from_revision")
        to_revision = transition.get("to_revision")
        if isinstance(from_revision, bool) or not isinstance(from_revision, int) \
                or from_revision < 0:
            errors.append(f"{label} transition from_revision is invalid")
        if isinstance(to_revision, bool) or not isinstance(to_revision, int) \
                or to_revision < 1:
            errors.append(f"{label} transition to_revision is invalid")
        if isinstance(revision, int) and to_revision != revision:
            errors.append(f"{label} transition does not end at the current revision")
        if isinstance(from_revision, int) and isinstance(to_revision, int) \
                and to_revision != from_revision + 1:
            errors.append(f"{label} transition must advance exactly one revision")
        for key in ["artifact", "previous_artifact"]:
            artifact = transition.get(key)
            if artifact is not None and (
                not isinstance(artifact, str) or not ARTIFACT.fullmatch(artifact)
            ):
                errors.append(f"{label} transition {key} is invalid")
        evidence = transition.get("evidence_sha256")
        if evidence is not None and (
            not isinstance(evidence, str) or not TREE.fullmatch(evidence)
        ):
            errors.append(f"{label} transition evidence_sha256 is invalid")
        stable = channels.get("stable")
        exact_bootstrap = (
            action == "bootstrap"
            and revision == 1
            and transition.get("from_revision") == 0
            and transition.get("to_revision") == 1
            and transition.get("artifact") == (
                stable.get("artifact") if isinstance(stable, dict) else None
            )
            and transition.get("previous_artifact") is None
            and transition.get("evidence_sha256") is None
            and set(channels) == {"stable"}
            and assignments == {}
            and value.get("promotion") is None
        )
        if revision == 1 and not exact_bootstrap:
            errors.append(f"{label} revision 1 must be the exact stable bootstrap")
        elif revision != 1 and action == "bootstrap":
            errors.append(f"{label} bootstrap is permitted only at revision 1")

    promotion = value.get("promotion")
    if promotion is None:
        if "candidate" in channels or "rollback" in channels:
            errors.append(f"{label} reserved transition channels require active promotion state")
        if any(channel == "candidate" for channel in assignments.values()):
            errors.append(f"{label} candidate assignments require active promotion state")
        return errors
    if not isinstance(promotion, dict) or set(promotion) != PROMOTION_FIELDS:
        errors.append(f"{label} promotion has unexpected or missing fields")
        return errors

    phase = promotion.get("phase")
    if phase not in {"canary", "smoke"}:
        errors.append(f"{label} promotion phase is invalid")
    candidate = promotion.get("candidate")
    previous = promotion.get("previous_stable")
    errors.extend(policy_lock_errors(candidate, f"{label} promotion candidate"))
    errors.extend(policy_lock_errors(previous, f"{label} promotion previous_stable"))
    canary_ids, canary_errors = _repository_ids(
        promotion.get("canary_repository_ids"),
        f"{label} promotion canary_repository_ids",
    )
    smoke_ids, smoke_errors = _repository_ids(
        promotion.get("smoke_repository_ids"),
        f"{label} promotion smoke_repository_ids",
    )
    errors.extend(canary_errors)
    errors.extend(smoke_errors)
    if not canary_ids:
        errors.append(f"{label} promotion requires at least one canary repository")
    if not smoke_ids:
        errors.append(f"{label} promotion requires at least one smoke repository")
    if AUTHORITY_REPOSITORY_ID not in canary_ids:
        errors.append(f"{label} promotion canary ring must include protected authority")
    if not set(canary_ids).issubset(smoke_ids):
        errors.append(f"{label} promotion smoke ring must include the complete canary ring")
    held_smoke = [
        repository_id for repository_id in smoke_ids
        if repository_id in assignments and assignments[repository_id] != "candidate"
    ]
    if held_smoke:
        errors.append(f"{label} promotion smoke ring contains held repositories")
    evidence = promotion.get("canary_evidence_sha256")
    if phase == "canary":
        if channels.get("candidate") != candidate:
            errors.append(f"{label} canary phase candidate channel does not match promotion")
        if "rollback" in channels:
            errors.append(f"{label} canary phase cannot expose rollback")
        for repository_id in canary_ids:
            if assignments.get(repository_id) != "candidate":
                errors.append(f"{label} canary repository {repository_id} is not assigned")
        if evidence is not None:
            errors.append(f"{label} canary phase cannot have canary evidence")
    elif phase == "smoke":
        if "candidate" in channels:
            errors.append(f"{label} smoke phase cannot retain candidate channel")
        if channels.get("stable") != candidate or channels.get("rollback") != previous:
            errors.append(f"{label} smoke phase stable/rollback channels do not match promotion")
        if any(channel == "candidate" for channel in assignments.values()):
            errors.append(f"{label} smoke phase cannot retain candidate assignments")
        if not isinstance(evidence, str) or not TREE.fullmatch(evidence):
            errors.append(f"{label} smoke phase requires canary evidence")
    return errors


def require_valid_state(value: Any) -> dict[str, Any]:
    errors = channel_state_errors(value)
    if errors:
        raise PolicyChannelError("invalid policy channel state:\n" + "\n".join(errors))
    return copy.deepcopy(value)


def require_revision(state: dict[str, Any], expected_revision: int) -> None:
    if state["revision"] != expected_revision:
        raise PolicyChannelError(
            f"policy channel revision changed: expected {expected_revision}, "
            f"found {state['revision']}"
        )


def _transition(
    state: dict[str, Any], action: str, *, artifact: str | None,
    previous_artifact: str | None, evidence_sha256: str | None = None,
) -> dict[str, Any]:
    previous_revision = state["revision"]
    state["revision"] = previous_revision + 1
    state["transition"] = {
        "action": action,
        "from_revision": previous_revision,
        "to_revision": state["revision"],
        "artifact": artifact,
        "previous_artifact": previous_artifact,
        "evidence_sha256": evidence_sha256,
    }
    errors = channel_state_errors(state)
    if errors:
        raise PolicyChannelError("transition produced invalid state:\n" + "\n".join(errors))
    return state


def bootstrap_state(lock: dict[str, Any]) -> dict[str, Any]:
    errors = policy_lock_errors(lock)
    if errors:
        raise PolicyChannelError("invalid bootstrap lock:\n" + "\n".join(errors))
    state = {
        "schema": CHANNEL_SCHEMA,
        "revision": 1,
        "default_channel": "stable",
        "channels": {"stable": copy.deepcopy(lock)},
        "assignments": {},
        "promotion": None,
        "transition": {
            "action": "bootstrap",
            "from_revision": 0,
            "to_revision": 1,
            "artifact": lock["artifact"],
            "previous_artifact": None,
            "evidence_sha256": None,
        },
    }
    return require_valid_state(state)


def select_lock(state: dict[str, Any], repository_id: str) -> tuple[str, dict[str, Any]]:
    state = require_valid_state(state)
    if not REPOSITORY_ID.fullmatch(repository_id):
        raise PolicyChannelError("repository_id must be an immutable GitHub repository node ID")
    channel = state["assignments"].get(repository_id, state["default_channel"])
    return channel, copy.deepcopy(state["channels"][channel])


def set_channel(
    state: dict[str, Any], name: str, lock: dict[str, Any], *, expected_revision: int,
) -> dict[str, Any]:
    state = require_valid_state(state)
    require_revision(state, expected_revision)
    if not CHANNEL_NAME.fullmatch(name) or name in RESERVED_CHANNELS:
        raise PolicyChannelError("named compatibility channels cannot use reserved channel names")
    errors = policy_lock_errors(lock)
    if errors:
        raise PolicyChannelError("invalid channel lock:\n" + "\n".join(errors))
    stable = state["channels"]["stable"]
    proven_locks = [stable]
    rollback = state["channels"].get("rollback")
    if rollback is not None:
        proven_locks.append(rollback)
    if lock not in proven_locks:
        raise PolicyChannelError(
            "a new compatibility channel must copy current stable or retained rollback"
        )
    previous = state["channels"].get(name)
    state["channels"][name] = copy.deepcopy(lock)
    return _transition(
        state, "set-channel", artifact=lock["artifact"],
        previous_artifact=previous and previous["artifact"],
    )


def sync_fleet_assignments(
    state: dict[str, Any], fleet: dict[str, Any], *, expected_revision: int,
) -> dict[str, Any]:
    state = require_valid_state(state)
    require_revision(state, expected_revision)
    desired = desired_fleet_assignments(state, fleet)
    promotion = state.get("promotion")
    if isinstance(promotion, dict):
        for repository_id in promotion["canary_repository_ids"]:
            if repository_id in desired:
                raise PolicyChannelError(
                    f"held repository {repository_id} cannot join the active canary ring"
                )
            if promotion.get("phase") == "canary":
                desired[repository_id] = "candidate"
        promotion["smoke_repository_ids"] = [
            repository_id for repository_id in promotion["smoke_repository_ids"]
            if repository_id not in desired
        ]
    previous = copy.deepcopy(state["assignments"])
    state["assignments"] = dict(sorted(desired.items()))
    return _transition(
        state, "sync-fleet", artifact=state["channels"]["stable"]["artifact"],
        previous_artifact=(
            state["channels"]["stable"]["artifact"] if previous != desired else None
        ),
    )


def desired_fleet_assignments(
    state: dict[str, Any], fleet: dict[str, Any],
) -> dict[str, str]:
    repositories = fleet.get("repositories") if isinstance(fleet, dict) else None
    if not isinstance(repositories, list):
        raise PolicyChannelError("fleet repositories must be an array")
    desired: dict[str, str] = {}
    for entry in repositories:
        if not isinstance(entry, dict):
            raise PolicyChannelError("fleet repository entries must be objects")
        channel = entry.get("policy_channel", "stable")
        if channel == "stable":
            continue
        if not isinstance(channel, str) or channel not in state["channels"] \
                or channel in {"candidate", "rollback"}:
            raise PolicyChannelError(
                f"fleet repository {entry.get('repository')} selects unknown or reserved "
                f"policy channel {channel!r}"
            )
        repository_id = entry.get("repository_node_id")
        if not isinstance(repository_id, str) or not REPOSITORY_ID.fullmatch(repository_id):
            raise PolicyChannelError(
                f"fleet repository {entry.get('repository')} needs repository_node_id "
                "for a non-stable policy channel"
            )
        desired[repository_id] = channel
    return desired


def prepare_candidate(
    state: dict[str, Any], candidate: dict[str, Any], *, expected_revision: int,
    canary_repository_ids: list[str], smoke_repository_ids: list[str],
    fleet: dict[str, Any] | None = None,
) -> dict[str, Any]:
    state = require_valid_state(state)
    require_revision(state, expected_revision)
    if state["promotion"] is not None:
        raise PolicyChannelError("another policy promotion is already active")
    if fleet is not None:
        state["assignments"] = dict(sorted(desired_fleet_assignments(state, fleet).items()))
    errors = policy_lock_errors(candidate, "candidate lock")
    if errors:
        raise PolicyChannelError("invalid candidate lock:\n" + "\n".join(errors))
    stable = state["channels"]["stable"]
    if candidate["generation"] <= stable["generation"]:
        raise PolicyChannelError("candidate generation must be strictly newer than stable")
    canary_ids = sorted(canary_repository_ids)
    for repository_id in canary_ids:
        if repository_id in state["assignments"]:
            raise PolicyChannelError(
                f"repository {repository_id} is held on {state['assignments'][repository_id]} "
                "and cannot join the canary ring"
            )
    smoke_ids = sorted(
        repository_id for repository_id in smoke_repository_ids
        if repository_id not in state["assignments"]
    )
    _, errors = _repository_ids(canary_ids, "canary_repository_ids")
    _, smoke_errors = _repository_ids(smoke_ids, "smoke_repository_ids")
    errors.extend(smoke_errors)
    if not canary_ids:
        errors.append("canary_repository_ids requires at least one repository")
    if not smoke_ids:
        errors.append("smoke_repository_ids requires at least one repository")
    if AUTHORITY_REPOSITORY_ID not in canary_ids:
        errors.append("the protected authority repository must be in the canary ring")
    if not set(canary_ids).issubset(smoke_ids):
        errors.append("smoke_repository_ids must include the complete canary ring")
    if errors:
        raise PolicyChannelError("invalid promotion rings:\n" + "\n".join(errors))
    state["channels"]["candidate"] = copy.deepcopy(candidate)
    for repository_id in canary_ids:
        state["assignments"][repository_id] = "candidate"
    state["assignments"] = dict(sorted(state["assignments"].items()))
    state["promotion"] = {
        "phase": "canary",
        "candidate": copy.deepcopy(candidate),
        "previous_stable": copy.deepcopy(stable),
        "canary_repository_ids": canary_ids,
        "smoke_repository_ids": smoke_ids,
        "canary_evidence_sha256": None,
    }
    return _transition(
        state, "prepare", artifact=candidate["artifact"],
        previous_artifact=stable["artifact"],
    )


def evidence_errors(
    evidence: Any, state: dict[str, Any], phase: str, expected_ids: list[str],
    *, require_success: bool,
) -> list[str]:
    if not isinstance(evidence, dict):
        return ["policy channel evidence must be an object"]
    errors: list[str] = []
    if set(evidence) != EVIDENCE_FIELDS:
        errors.append("policy channel evidence has unexpected or missing fields")
    if evidence.get("schema") != EVIDENCE_SCHEMA:
        errors.append("policy channel evidence has an unsupported schema")
    if evidence.get("phase") != phase:
        errors.append(f"policy channel evidence phase must be {phase}")
    if evidence.get("state_revision") != state["revision"]:
        errors.append("policy channel evidence targets a stale state revision")
    promotion = state.get("promotion") or {}
    candidate = promotion.get("candidate") or {}
    if evidence.get("artifact") != candidate.get("artifact"):
        errors.append("policy channel evidence artifact does not match the candidate")
    if evidence.get("generation") != candidate.get("generation"):
        errors.append("policy channel evidence generation does not match the candidate")
    results = evidence.get("results")
    if not isinstance(results, list):
        return [*errors, "policy channel evidence results must be an array"]
    collection_errors = evidence.get("errors")
    if not isinstance(collection_errors, list):
        return [*errors, "policy channel evidence errors must be an array"]
    seen: set[str] = set()
    failed_collection: set[str] = set()
    expected = set(expected_ids)
    for failure in collection_errors:
        if not isinstance(failure, dict) or set(failure) != EVIDENCE_ERROR_FIELDS:
            errors.append("policy channel evidence error has unexpected or missing fields")
            continue
        repository_id = failure.get("repository_id")
        if not isinstance(repository_id, str) or repository_id not in expected:
            errors.append("policy channel evidence error contains an unexpected repository")
        elif repository_id in failed_collection:
            errors.append(f"policy channel evidence errors duplicate repository {repository_id}")
        else:
            failed_collection.add(repository_id)
        if failure.get("code") not in EVIDENCE_ERROR_CODES:
            errors.append("policy channel evidence error code is invalid")
    for result in results:
        if not isinstance(result, dict) or set(result) != RESULT_FIELDS:
            errors.append("policy channel evidence result has unexpected or missing fields")
            continue
        repository_id = result.get("repository_id")
        if not isinstance(repository_id, str) or repository_id not in expected:
            errors.append("policy channel evidence contains an unexpected repository")
        elif repository_id in seen:
            errors.append(f"policy channel evidence duplicates repository {repository_id}")
        else:
            seen.add(repository_id)
        branch = result.get("default_branch")
        if not isinstance(branch, str) or not branch or branch.startswith("refs/"):
            errors.append("policy channel evidence default_branch is invalid")
        head_oid = result.get("head_oid")
        if not isinstance(head_oid, str) or not OID.fullmatch(head_oid):
            errors.append("policy channel evidence head_oid is invalid")
        workflow = result.get("workflow_path")
        if not isinstance(workflow, str) or not WORKFLOW.fullmatch(workflow):
            errors.append("policy channel evidence workflow_path is invalid")
        run_id = result.get("run_id")
        if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id < 1:
            errors.append("policy channel evidence run_id is invalid")
        started_at = result.get("started_at")
        try:
            parsed = dt.datetime.fromisoformat(str(started_at).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
        except ValueError:
            errors.append("policy channel evidence started_at is invalid")
        conclusion = result.get("conclusion")
        if conclusion not in CONCLUSIONS:
            errors.append("policy channel evidence conclusion is invalid")
        if require_success and conclusion != "success":
            errors.append(f"policy channel evidence repository {repository_id} did not succeed")
        expected_channel = "candidate" if phase == "canary" else "stable"
        if require_success and result.get("selected_channel") != expected_channel:
            errors.append(
                f"policy channel evidence repository {repository_id} did not select "
                f"the {expected_channel} channel"
            )
        selected_artifact = result.get("selected_artifact")
        if selected_artifact is not None and (
            not isinstance(selected_artifact, str) or not ARTIFACT.fullmatch(selected_artifact)
        ):
            errors.append("policy channel evidence selected_artifact is invalid")
        if require_success and selected_artifact != candidate.get("artifact"):
            errors.append(
                f"policy channel evidence repository {repository_id} did not load "
                "the candidate artifact"
            )
        selected_channel = result.get("selected_channel")
        if selected_channel is not None and selected_channel not in {"candidate", "stable"}:
            errors.append("policy channel evidence selected_channel is invalid")
    if seen & failed_collection:
        errors.append("policy channel evidence cannot record a result and error for one repository")
    if require_success and (seen != expected or failed_collection):
        errors.append("policy channel evidence does not cover the complete successful ring")
    if not require_success:
        if not seen and not failed_collection:
            errors.append("failure evidence must contain at least one expected repository")
        if not failed_collection and results and all(
            result.get("conclusion") == "success"
            for result in results if isinstance(result, dict)
        ):
            errors.append("failure evidence must contain a failed, cancelled, or timed-out run")
    return errors


def promote_candidate(
    state: dict[str, Any], evidence: dict[str, Any], *, expected_revision: int,
) -> dict[str, Any]:
    state = require_valid_state(state)
    require_revision(state, expected_revision)
    promotion = state.get("promotion")
    if not isinstance(promotion, dict) or promotion.get("phase") != "canary":
        raise PolicyChannelError("policy promotion is not in canary phase")
    errors = evidence_errors(
        evidence, state, "canary", promotion["canary_repository_ids"],
        require_success=True,
    )
    if errors:
        raise PolicyChannelError("invalid canary evidence:\n" + "\n".join(errors))
    digest = canonical_sha256(evidence)
    candidate = promotion["candidate"]
    previous = promotion["previous_stable"]
    state["channels"]["stable"] = copy.deepcopy(candidate)
    state["channels"]["rollback"] = copy.deepcopy(previous)
    state["channels"].pop("candidate", None)
    for repository_id in promotion["canary_repository_ids"]:
        if state["assignments"].get(repository_id) == "candidate":
            state["assignments"].pop(repository_id)
    promotion["phase"] = "smoke"
    promotion["canary_evidence_sha256"] = digest
    return _transition(
        state, "promote", artifact=candidate["artifact"],
        previous_artifact=previous["artifact"], evidence_sha256=digest,
    )


def finalize_promotion(
    state: dict[str, Any], evidence: dict[str, Any], *, expected_revision: int,
) -> dict[str, Any]:
    state = require_valid_state(state)
    require_revision(state, expected_revision)
    promotion = state.get("promotion")
    if not isinstance(promotion, dict) or promotion.get("phase") != "smoke":
        raise PolicyChannelError("policy promotion is not in smoke phase")
    errors = evidence_errors(
        evidence, state, "smoke", promotion["smoke_repository_ids"],
        require_success=True,
    )
    if errors:
        raise PolicyChannelError("invalid smoke evidence:\n" + "\n".join(errors))
    digest = canonical_sha256(evidence)
    previous = promotion["previous_stable"]
    candidate = promotion["candidate"]
    state["channels"].pop("rollback", None)
    state["promotion"] = None
    return _transition(
        state, "finalize", artifact=candidate["artifact"],
        previous_artifact=previous["artifact"], evidence_sha256=digest,
    )


def abort_candidate(
    state: dict[str, Any], evidence: dict[str, Any], *, expected_revision: int,
) -> dict[str, Any]:
    state = require_valid_state(state)
    require_revision(state, expected_revision)
    promotion = state.get("promotion")
    if not isinstance(promotion, dict) or promotion.get("phase") != "canary":
        raise PolicyChannelError("policy promotion is not in canary phase")
    errors = evidence_errors(
        evidence, state, "canary", promotion["canary_repository_ids"],
        require_success=False,
    )
    if errors:
        raise PolicyChannelError("invalid canary failure evidence:\n" + "\n".join(errors))
    digest = canonical_sha256(evidence)
    candidate = promotion["candidate"]
    previous = promotion["previous_stable"]
    state["channels"].pop("candidate", None)
    for repository_id in promotion["canary_repository_ids"]:
        if state["assignments"].get(repository_id) == "candidate":
            state["assignments"].pop(repository_id)
    state["promotion"] = None
    return _transition(
        state, "abort", artifact=previous["artifact"],
        previous_artifact=candidate["artifact"], evidence_sha256=digest,
    )


def rollback_promotion(
    state: dict[str, Any], evidence: dict[str, Any], *, expected_revision: int,
) -> dict[str, Any]:
    state = require_valid_state(state)
    require_revision(state, expected_revision)
    promotion = state.get("promotion")
    if not isinstance(promotion, dict) or promotion.get("phase") != "smoke":
        raise PolicyChannelError("policy promotion is not in smoke phase")
    errors = evidence_errors(
        evidence, state, "smoke", promotion["smoke_repository_ids"],
        require_success=False,
    )
    if errors:
        raise PolicyChannelError("invalid smoke failure evidence:\n" + "\n".join(errors))
    digest = canonical_sha256(evidence)
    candidate = promotion["candidate"]
    previous = promotion["previous_stable"]
    state["channels"]["stable"] = copy.deepcopy(previous)
    state["channels"].pop("rollback", None)
    state["promotion"] = None
    return _transition(
        state, "rollback", artifact=previous["artifact"],
        previous_artifact=candidate["artifact"], evidence_sha256=digest,
    )


def transition_errors(
    previous: Any, candidate: Any, evidence: Any | None = None,
) -> list[str]:
    """Prove that candidate is exactly one permitted transition from previous."""
    previous_errors = channel_state_errors(previous, "active policy channel state")
    candidate_errors = channel_state_errors(candidate, "candidate policy channel state")
    if previous_errors or candidate_errors:
        return [*previous_errors, *candidate_errors]
    assert isinstance(previous, dict) and isinstance(candidate, dict)
    transition = candidate["transition"]
    if candidate["revision"] != previous["revision"] + 1 \
            or transition["from_revision"] != previous["revision"] \
            or transition["to_revision"] != candidate["revision"]:
        return ["candidate policy channel transition is stale or non-sequential"]
    action = transition["action"]
    try:
        if action == "prepare":
            promotion = candidate.get("promotion")
            if not isinstance(promotion, dict):
                raise PolicyChannelError("prepare transition lacks promotion state")
            expected = prepare_candidate(
                previous,
                promotion["candidate"],
                expected_revision=previous["revision"],
                canary_repository_ids=promotion["canary_repository_ids"],
                smoke_repository_ids=promotion["smoke_repository_ids"],
                fleet={
                    "repositories": [
                        {
                            "repository": f"node/{repository_id}",
                            "repository_node_id": repository_id,
                            "policy_channel": channel,
                        }
                        for repository_id, channel in candidate["assignments"].items()
                        if channel != "candidate"
                    ],
                },
            )
        elif action in {"promote", "finalize", "abort", "rollback"}:
            if not isinstance(evidence, dict):
                raise PolicyChannelError(f"{action} transition requires exact ring evidence")
            function = {
                "promote": promote_candidate,
                "finalize": finalize_promotion,
                "abort": abort_candidate,
                "rollback": rollback_promotion,
            }[action]
            expected = function(
                previous, evidence, expected_revision=previous["revision"],
            )
        elif action == "set-channel":
            changed = [
                name for name in set(previous["channels"]) | set(candidate["channels"])
                if previous["channels"].get(name) != candidate["channels"].get(name)
            ]
            if len(changed) != 1 or changed[0] in RESERVED_CHANNELS \
                    or changed[0] not in candidate["channels"]:
                raise PolicyChannelError(
                    "set-channel must change exactly one named compatibility channel"
                )
            expected = set_channel(
                previous, changed[0], candidate["channels"][changed[0]],
                expected_revision=previous["revision"],
            )
        elif action == "sync-fleet":
            fleet_entries = [
                {
                    "repository": f"node/{repository_id}",
                    "repository_node_id": repository_id,
                    "policy_channel": channel,
                }
                for repository_id, channel in candidate["assignments"].items()
                if channel != "candidate"
            ]
            expected = sync_fleet_assignments(
                previous, {"repositories": fleet_entries},
                expected_revision=previous["revision"],
            )
        else:
            raise PolicyChannelError(f"{action} cannot follow an active channel state")
    except (KeyError, PolicyChannelError) as exc:
        return [str(exc)]
    if expected != candidate:
        return [f"candidate state is not the exact result of its {action} transition"]
    return []
