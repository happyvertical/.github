#!/usr/bin/env python3
"""Pure HappyVertical claim and pull-request lifecycle evaluation.

The checked-out control-plane CLI and the sanitized OCI runtime both import
this module. GitHub reads and mutations stay in those wrappers; lifecycle
decisions live here so source and packaged enforcement cannot drift.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from collections.abc import Collection, Iterable
from typing import Any


CLAIM_MARKER = "<!-- hv-agent-claim:v1 -->"
HEARTBEAT_MARKER = "<!-- hv-agent-heartbeat:v1 -->"
OWNER_REPAIR_MARKER = "<!-- hv-agent-claim-owner-repair:v1 -->"
RUN_MARKER = "<!-- hv-agent-run:v1 -->"
CLAIM_LABEL = "agent: implementation"
BLOCKED_LABEL = "status: blocked"
LEASE_SECONDS = 14_400
TRUSTED_AUTHOR_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}
RELEASE_REASONS = {
    "review", "blocked", "abandoned", "expired", "duplicate", "race-lost",
}
PR_BOUND_RELEASE_REASONS = {"review", "blocked"}
MERGE_ELIGIBLE_RELEASE_REASONS = {"review"}
# The three rejection shapes `hv-agent release` passes through on its way to a
# settled cycle, named once so the explanation in `release_settlement_pending`
# cannot drift from the messages it explains (#380).
LIVE_CLAIM_WITHOUT_LABEL_ERROR = "has a live claim but lacks agent: implementation"
LABEL_WITHOUT_LIVE_CLAIM_ERROR = (
    "has agent: implementation without exactly one valid live claim"
)
MISSING_RELEASE_EVIDENCE_ERROR = "lacks an immutable owner-created release status"
RELEASE_SETTLEMENT_ERRORS = (
    LIVE_CLAIM_WITHOUT_LABEL_ERROR,
    LABEL_WITHOUT_LIVE_CLAIM_ERROR,
    MISSING_RELEASE_EVIDENCE_ERROR,
)
GIT_OID_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
GIT_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
ROLLOUT_METADATA_GENERATION = 27
REPOSITORY_NODE_ID_PATTERN = re.compile(r"R_[A-Za-z0-9]+")
AUTHORITY_SUBSTRATE_PREDECESSOR_SCHEMA = "hv-agent-authority-substrate-predecessor:v1"
AUTHORITY_SUBSTRATE_PREDECESSOR_FIELDS = {
    "schema", "generation", "source_commit", "components",
}
AUTHORITY_SUBSTRATE_GAP_PREDECESSOR_SCHEMA = (
    "hv-agent-authority-substrate-predecessor:v2"
)
AUTHORITY_SUBSTRATE_GAP_PREDECESSOR_FIELDS = {
    "schema", "artifact_generation", "selected_predecessor",
    "gap_generations", "components",
}
AUTHORITY_SUBSTRATE_SELECTED_LOCK_FIELDS = {
    "schema", "artifact", "generation", "policy_revision",
    "source_commit", "source_tree_sha256",
}
AUTHORITY_SUBSTRATE_SELECTED_LOCK_ROLLOUT_FIELDS = (
    AUTHORITY_SUBSTRATE_SELECTED_LOCK_FIELDS | {"rollout"}
)
CLOSING_PRS_QUERY = """\
query($owner:String!,$name:String!,$number:Int!,$endCursor:String){
  repository(owner:$owner,name:$name){
    issue(number:$number){
      closedByPullRequestsReferences(
        first:100,after:$endCursor,includeClosedPrs:true
      ){
        nodes{
          id number isDraft state body headRefName headRefOid
          mergeQueueEntry{id}
          repository{nameWithOwner}
        }
        pageInfo{hasNextPage endCursor}
      }
    }
  }
  rateLimit{cost remaining resetAt}
}"""
PULL_REQUEST_QUEUE_QUERY = """\
query($owner:String!,$name:String!,$number:Int!){
  repository(owner:$owner,name:$name){
    pullRequest(number:$number){id mergeQueueEntry{id}}
  }
  rateLimit{cost remaining resetAt}
}"""
DEQUEUE_PULL_REQUEST_MUTATION = """\
mutation($id:ID!){
  dequeuePullRequest(input:{id:$id}){mergeQueueEntry{id}}
}"""
PULL_REQUEST_ACTIONS = {
    "opened", "edited", "synchronize", "reopened", "ready_for_review",
    "converted_to_draft", "labeled", "unlabeled",
}
VALIDATION_PULL_REQUEST_ACTIONS = {"opened", "synchronize", "reopened"}
LIFECYCLE_ONLY_PULL_REQUEST_ACTIONS = (
    PULL_REQUEST_ACTIONS - VALIDATION_PULL_REQUEST_ACTIONS
)
TRUSTED_BASE_CHECKOUT_REF = (
    "github.event.pull_request.head.repo.full_name==github.repository&&"
    "github.event.pull_request.head.sha||github.sha"
)
TRUSTED_BASE_HOSTED_GATE = (
    "github.event_name=='merge_group'||"
    "(github.event_name=='pull_request_target'&&"
    "contains(fromJSON('[\"opened\",\"synchronize\",\"reopened\"]'),"
    "github.event.action))"
)
TRUSTED_BASE_SELF_HOSTED_GATE = (
    "github.event_name=='merge_group'||"
    "(github.event_name=='pull_request_target'&&"
    "github.event.pull_request.head.repo.full_name==github.repository&&"
    "contains(fromJSON('[\"opened\",\"synchronize\",\"reopened\"]'),"
    "github.event.action))"
)
TRUSTED_BASE_REUSABLE_REF = "github.event.pull_request.head.sha||github.sha"

TRACKER_PROVIDERS = ("github", "work")


def tracker_provider(manifest: dict[str, Any]) -> str:
    """The declared issue-tracker provider, defaulting to the historical GitHub."""
    tracker = manifest.get("tracker", {})
    if not isinstance(tracker, dict):
        return "github"
    return str(tracker.get("provider", "github"))


def forge_repository(manifest: dict[str, Any]) -> str:
    """
    Resolve the repository that hosts code, pull requests, checks, and merges.

    A manifest predating the tracker/forge split has no `forge` block and lets
    `tracker.repository` serve both roles, so that stays the fallback while the
    tracker is GitHub. Once the tracker is Work the fallback is meaningless, so
    this fails closed rather than guessing a repository to operate on.
    """
    forge = manifest.get("forge")
    if isinstance(forge, dict) and forge.get("repository"):
        return str(forge["repository"])
    if tracker_provider(manifest) == "github":
        tracker = manifest.get("tracker", {})
        repository = tracker.get("repository") if isinstance(tracker, dict) else None
        if repository:
            return str(repository)
        raise ValueError("project manifest is missing tracker.repository")
    raise ValueError(
        "project manifest declares a Work tracker without a forge block; "
        "add forge.provider and forge.repository"
    )


def require_github_tracker(manifest: dict[str, Any], command: str) -> None:
    """
    Refuse tracker authority this build cannot exercise.

    The manifest schema accepts `tracker.provider: work` so repositories can be
    described ahead of the cutover, but no Work API client ships yet. Falling
    through to the GitHub path would operate on the wrong tracker, so a Work
    manifest stops here with an actionable message instead.
    """
    provider = tracker_provider(manifest)
    if provider == "github":
        return
    raise ValueError(
        f"{command} requires a GitHub tracker; this manifest declares "
        f"tracker.provider: {provider}, and the Work tracker client is not "
        "available in this policy build"
    )


def validation_workflow_evidence_required(
    event_name: str | None, event_action: str | None,
) -> bool:
    if event_name == "workflow_dispatch":
        return True
    if event_name != "pull_request":
        return False
    # A missing action means a previous-release vendored workflow that never
    # passed EVENT_ACTION; an unrecognized action means GitHub introduced a
    # new one. Both fail closed to requiring validation evidence.
    return event_action not in VALIDATION_PULL_REQUEST_ACTIONS


def validation_workflow_transition_error(
    pull_request: dict[str, Any],
    workflow_path: str,
    timeline: list[dict[str, Any]],
) -> str | None:
    """Require this PR to retrigger full CI after its latest base retarget."""
    number = pull_request.get("number")
    head_oid = str(pull_request.get("headRefOid") or "")
    base_oid = str(pull_request.get("baseRefOid") or "")
    if isinstance(number, bool) or not isinstance(number, int) \
            or not GIT_OID_PATTERN.fullmatch(head_oid) \
            or not GIT_OID_PATTERN.fullmatch(base_oid):
        return (
            "pull request lacks a valid number and current head/base revision pair; "
            "reread GitHub and rerun full validation"
        )
    if not all(isinstance(event, dict) for event in timeline):
        return (
            "pull request timeline contains invalid event state; reread GitHub before "
            "merge evaluation"
        )
    base_changes = [
        (index, event)
        for index, event in enumerate(timeline)
        if event.get("event") == "base_ref_changed"
    ]
    if not base_changes:
        return None
    last_base_index, _last_base_event = base_changes[-1]
    for event in timeline[last_base_index + 1:]:
        kind = event.get("event")
        if kind == "reopened":
            return None
        if kind == "committed" and event.get("sha") == head_oid:
            return None
        force_oid = event.get("commit_id") or event.get("after_commit_id") \
            or event.get("after_commit_oid")
        if kind == "head_ref_force_pushed" and force_oid == head_oid:
            return None
    return (
        f"PR #{number} has no PR-specific {workflow_path} trigger after its latest "
        "base retarget; close and reopen this pull request or update its head to "
        "start full validation; activity on another same-head pull request and "
        "later lifecycle-only events cannot repair this state"
    )


def exact_managed_workflow_block(
    text: str,
    expected: str,
    start_marker: str,
    end_marker: str,
    marker_indent: int,
) -> bool:
    """Match one generated block and reject semantic continuation after its marker."""
    prefix = " " * marker_indent
    if text.count(prefix + start_marker) != 1 or text.count(prefix + end_marker) != 1:
        return False
    pattern = re.compile(
        rf"(?ms)^{re.escape(prefix + start_marker)}\n.*?"
        rf"^{re.escape(prefix + end_marker)}\n?"
    )
    matches = list(pattern.finditer(text))
    if len(matches) != 1 or matches[0].group(0) != expected:
        return False
    for line in text[matches[0].end():].splitlines():
        stripped = line.lstrip(" ")
        if not stripped or stripped.startswith("#"):
            continue
        indentation = len(line) - len(stripped)
        return indentation <= marker_indent
    return True


def top_level_mapping_section_span(text: str, key: str) -> tuple[int, int] | None:
    """Return the byte span below one simple top-level block mapping key."""
    lines = text.splitlines(keepends=True)
    key_pattern = re.compile(
        rf'''^(?:{re.escape(key)}|["']{re.escape(key)}["'])[ \t]*:'''
        r'''(?:[ \t]+(.*?))?[ \t]*(?:\r?\n)?$'''
    )
    matches: list[tuple[int, int, str]] = []
    offset = 0
    for index, line in enumerate(lines):
        match = key_pattern.match(line)
        if match is not None:
            matches.append((index, offset + len(line), match.group(1) or ""))
        offset += len(line)
    if len(matches) != 1:
        return None
    line_index, start, tail = matches[0]
    if tail and not tail.startswith("#"):
        return None
    end = len(text)
    offset = start
    for line in lines[line_index + 1:]:
        stripped = line.strip()
        if stripped and not line.lstrip().startswith("#") \
                and not line.startswith((" ", "\t")):
            end = offset
            break
        offset += len(line)
    return start, end


def managed_block_in_top_level_mapping(
    text: str,
    start_marker: str,
    end_marker: str,
    marker_indent: int,
    key: str = "jobs",
) -> bool:
    """Require one marked block to be a direct child region of a root mapping."""
    section = top_level_mapping_section_span(text, key)
    if section is None:
        return False
    prefix = " " * marker_indent
    pattern = re.compile(
        rf"(?ms)^{re.escape(prefix + start_marker)}\n.*?"
        rf"^{re.escape(prefix + end_marker)}\n?"
    )
    matches = list(pattern.finditer(text))
    return len(matches) == 1 \
        and section[0] <= matches[0].start() < matches[0].end() <= section[1]


def exact_managed_top_level_mapping_child_block(
    text: str,
    expected: str,
    start_marker: str,
    end_marker: str,
    marker_indent: int,
    key: str = "jobs",
) -> bool:
    """Match an exact managed block structurally nested under a root mapping."""
    return exact_managed_workflow_block(
        text, expected, start_marker, end_marker, marker_indent,
    ) and managed_block_in_top_level_mapping(
        text, start_marker, end_marker, marker_indent, key,
    )


def insert_top_level_mapping_child(text: str, key: str, block: str) -> str:
    """Insert a rendered child at the start of one root block mapping."""
    section = top_level_mapping_section_span(text, key)
    if section is None:
        raise ValueError(f"expected one top-level {key} block mapping")
    separator = "" if block.endswith("\n\n") else "\n"
    return text[:section[0]] + block + separator + text[section[0]:]


def _yaml_mapping_entry(
    lines: list[str], key: str,
) -> tuple[int, int, str] | None:
    """Return one direct mapping child without treating comments as YAML."""
    entries: list[tuple[int, int, str, str]] = []
    pattern = re.compile(
        r'''^( +)([A-Za-z_][A-Za-z0-9_-]*|["'][A-Za-z_][A-Za-z0-9_-]*["'])'''
        r''':(?:[ \t]+(.*?))?[ \t]*$'''
    )
    for index, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = pattern.match(line)
        if match:
            entries.append((
                index,
                len(match.group(1)),
                match.group(2).strip("'\""),
                match.group(3) or "",
            ))
    if not entries:
        return None
    direct_indent = min(entry[1] for entry in entries)
    matches = [
        (index, indent, tail)
        for index, indent, name, tail in entries
        if indent == direct_indent and name == key
    ]
    return matches[0] if len(matches) == 1 else None


def _yaml_mapping_section(
    lines: list[str], key: str,
) -> tuple[list[str], str] | None:
    entry = _yaml_mapping_entry(lines, key)
    if entry is None:
        return None
    index, indent, tail = entry
    end = len(lines)
    for candidate_index in range(index + 1, len(lines)):
        candidate = lines[candidate_index]
        if not candidate.strip() or candidate.lstrip().startswith("#"):
            continue
        candidate_indent = len(candidate) - len(candidate.lstrip(" "))
        if candidate_indent <= indent:
            end = candidate_index
            break
    return lines[index + 1:end], tail


def _yaml_direct_entries(lines: list[str]) -> list[tuple[int, int, str, str]]:
    """Return direct mapping entries with simple quoted or unquoted keys."""
    entries: list[tuple[int, int, str, str]] = []
    pattern = re.compile(
        r'''^( +)([A-Za-z_][A-Za-z0-9_-]*|["'][A-Za-z_][A-Za-z0-9_-]*["'])'''
        r''':(?:[ \t]+(.*?))?[ \t]*$'''
    )
    for index, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = pattern.match(line)
        if match:
            entries.append((
                index,
                len(match.group(1)),
                match.group(2).strip("'\""),
                match.group(3) or "",
            ))
    if not entries:
        return []
    direct_indent = min(indent for _, indent, _, _ in entries)
    return [entry for entry in entries if entry[1] == direct_indent]


def _yaml_unparsed_direct_mapping_lines(lines: list[str]) -> list[str]:
    """Return direct YAML entries outside the deliberately small safe key grammar."""
    candidates: list[tuple[int, str]] = []
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indentation = len(line) - len(line.lstrip(" "))
        candidates.append((indentation, line))
    if not candidates:
        return []
    direct_indent = min(indent for indent, _line in candidates)
    safe = re.compile(
        r'''^ *(?:[A-Za-z_][A-Za-z0-9_-]*|["'][A-Za-z_][A-Za-z0-9_-]*["'])'''
        r''':(?:[ \t]+.*)?[ \t]*$'''
    )
    return [
        line.strip() for indent, line in candidates
        if indent == direct_indent and safe.match(line) is None
    ]


def _yaml_direct_keys(lines: list[str]) -> list[str]:
    return [key for _, _, key, _ in _yaml_direct_entries(lines)]


def _legacy_lifecycle_dispatch_only(trigger_lines: list[str]) -> bool:
    """Recognize the generated lifecycle-only dispatch contract and no mixed inputs."""
    dispatch = _yaml_mapping_section(trigger_lines, "workflow_dispatch")
    if dispatch is None or _yaml_unparsed_direct_mapping_lines(dispatch[0]) \
            or _yaml_direct_keys(dispatch[0]) != ["inputs"]:
        return False
    inputs = _yaml_mapping_section(dispatch[0], "inputs")
    if inputs is None or _yaml_unparsed_direct_mapping_lines(inputs[0]) \
            or _yaml_direct_keys(inputs[0]) != ["pr_number"]:
        return False
    pr_number = _yaml_mapping_section(inputs[0], "pr_number")
    if pr_number is None or _yaml_unparsed_direct_mapping_lines(pr_number[0]):
        return False
    keys = _yaml_direct_keys(pr_number[0])
    return (
        set(keys).issubset({"description", "required", "type"})
        and "required" in keys
        and "type" in keys
        and _yaml_boolean(pr_number[0], "required") == "true"
        and _yaml_scalar(pr_number[0], "type") == "number"
    )


def _yaml_strip_flow_comment(line: str) -> str:
    """Drop a trailing comment from one physical flow-collection line."""
    match = re.search(r"(?:^|[ \t])#", line)
    return line[: match.start()] if match else line


def _yaml_flow_sequence_text(tail: str, nested: list[str]) -> str | None:
    """Join a single- or multi-line flow sequence value into one string.

    The flow tokens accepted downstream cannot contain quotes or `#`, so
    stripping whitespace-led comments per physical line is unambiguous.
    Returns None when the value does not open a flow sequence at all.
    """
    head = _yaml_strip_flow_comment(tail).strip()
    continuation = [
        stripped
        for line in nested
        for stripped in [_yaml_strip_flow_comment(line).strip()]
        if stripped
    ]
    if head.startswith("["):
        return "\n".join([head, *continuation])
    if head:
        return None
    if not continuation or not continuation[0].startswith("["):
        return None
    return "\n".join(continuation)


def _yaml_flow_list(text: str) -> set[str] | None:
    """Parse a flow list of simple quoted or unquoted literal tokens."""
    token = r'''(?:"([A-Za-z0-9_./-]+)"|'([A-Za-z0-9_./-]+)'|([A-Za-z0-9_./-]+))'''
    if not re.fullmatch(
        rf'''\[\s*{token}(?:\s*,\s*{token})*\s*,?\s*\]''', text,
    ):
        return None
    values: set[str] = set()
    for match in re.finditer(token, text):
        values.add(next(value for value in match.groups() if value is not None))
    return values


def _yaml_list(lines: list[str], key: str) -> set[str] | None:
    section = _yaml_mapping_section(lines, key)
    entry = _yaml_mapping_entry(lines, key)
    if section is None or entry is None:
        return None
    nested, tail = section
    flow_text = _yaml_flow_sequence_text(tail, nested)
    if flow_text is not None:
        return _yaml_flow_list(flow_text)
    if tail and not tail.startswith("#"):
        return None
    values = set()
    item_pattern = re.compile(
        r'''^ +-\s*(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9_./-]+))'''
        r'''(?:[ \t]+#.*)?[ \t]*$'''
    )
    for line in nested:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = item_pattern.match(line)
        if not match:
            return None
        values.add(next(value for value in match.groups() if value is not None))
    return values


def _yaml_literal_branches(lines: list[str]) -> set[str] | None:
    """Parse only unambiguous literal branch allowlists."""
    if _yaml_mapping_entry(lines, "branches") is None:
        return None
    branches = _yaml_list(lines, "branches")
    if not branches or any(
        not re.fullmatch(r"[A-Za-z0-9_./-]+", branch) for branch in branches
    ):
        return None
    return branches


def _yaml_raw_scalar(lines: list[str], key: str) -> str | None:
    section = _yaml_mapping_section(lines, key)
    if section is None:
        return None
    nested, tail = section
    if any(
        line.strip() and not line.lstrip().startswith("#")
        for line in nested
    ):
        return None
    value = re.split(r"[ \t]+#", tail, maxsplit=1)[0].strip()
    return value or None


def _yaml_scalar(lines: list[str], key: str) -> str | None:
    value = _yaml_raw_scalar(lines, key)
    return value.strip("'\"") if value else None


def _yaml_boolean(lines: list[str], key: str) -> str | None:
    """Return only an unquoted YAML boolean literal."""
    value = _yaml_raw_scalar(lines, key)
    return value if value in {"true", "false"} else None


def _yaml_block_scalar_header(value: str) -> bool:
    """Recognize YAML literal/folded headers with chomping and indent indicators."""
    return re.fullmatch(
        r"[|>](?:(?:[+-][1-9]?)|(?:[1-9][+-]?))?", value,
    ) is not None


def _yaml_double_quoted_semantic_view(text: str) -> str:
    """Decode numeric YAML escapes inside double-quoted scalars for safety scans."""
    quoted = re.compile(r'"(?:[^"\\]|\\[\s\S])*"')

    def decode(match: re.Match[str]) -> str:
        value = match.group(0)
        content = value[1:-1]
        output: list[str] = []
        index = 0
        widths = {"x": 2, "u": 4, "U": 8}
        while index < len(content):
            if content[index] != "\\" or index + 1 >= len(content):
                output.append(content[index])
                index += 1
                continue
            escape = content[index + 1]
            if escape == "\\":
                output.append("\\")
                index += 2
                continue
            if escape in {"\r", "\n"}:
                index += 2
                if escape == "\r" and index < len(content) \
                        and content[index] == "\n":
                    index += 1
                while index < len(content) and content[index] in {" ", "\t"}:
                    index += 1
                continue
            width = widths.get(escape)
            digits = content[index + 2:index + 2 + (width or 0)]
            if width and len(digits) == width and re.fullmatch(r"[0-9A-Fa-f]+", digits):
                try:
                    output.append(chr(int(digits, 16)))
                except ValueError:
                    output.append(content[index:index + 2 + width])
                index += 2 + width
                continue
            output.extend(("\\", escape))
            index += 2
        return '"' + "".join(output) + '"'

    return quoted.sub(decode, text)


def _github_expression_bodies(text: str) -> list[str]:
    """Return GitHub expression bodies without ending on braces inside strings."""
    bodies: list[str] = []
    offset = 0
    while True:
        start = text.find("${{", offset)
        if start < 0:
            return bodies
        index = start + 3
        quote: str | None = None
        while index < len(text):
            char = text[index]
            if quote is not None:
                if char == quote:
                    if quote == "'" and index + 1 < len(text) \
                            and text[index + 1] == "'":
                        index += 2
                        continue
                    quote = None
                elif quote == '"' and char == "\\":
                    index += 2
                    continue
                index += 1
                continue
            if char in {"'", '"'}:
                quote = char
                index += 1
                continue
            if text.startswith("}}", index):
                bodies.append(text[start + 3:index])
                offset = index + 2
                break
            index += 1
        else:
            bodies.append(text[start + 3:])
            return bodies


def _workflow_call_input_names(text: str) -> set[str] | None:
    """Return statically declared workflow_call inputs, or None when ambiguous."""
    lines = text.splitlines()
    on_pattern = re.compile(
        r'^(?:on|["\']on["\']):(?:[ \t]+#.*)?[ \t]*$'
    )
    on_indexes = [index for index, line in enumerate(lines) if on_pattern.match(line)]
    if len(on_indexes) != 1:
        return None
    end = len(lines)
    for index in range(on_indexes[0] + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            end = index
            break
    trigger_lines = lines[on_indexes[0] + 1:end]
    call_keys = _yaml_direct_keys(trigger_lines)
    if call_keys.count("workflow_call") > 1:
        return None
    call = _yaml_mapping_section(trigger_lines, "workflow_call")
    if call is None:
        return set()
    if call[1] == "{}" and not any(
        line.strip() and not line.lstrip().startswith("#") for line in call[0]
    ):
        return set()
    if (call[1] and not call[1].startswith("#")) \
            or _yaml_unparsed_direct_mapping_lines(call[0]):
        return None
    call_child_keys = _yaml_direct_keys(call[0])
    if call_child_keys.count("inputs") > 1:
        return None
    inputs = _yaml_mapping_section(call[0], "inputs")
    if inputs is None:
        return set()
    if inputs[1] == "{}" and not any(
        line.strip() and not line.lstrip().startswith("#") for line in inputs[0]
    ):
        return set()
    if (inputs[1] and not inputs[1].startswith("#")) \
            or _yaml_unparsed_direct_mapping_lines(inputs[0]):
        return None
    input_names = _yaml_direct_keys(inputs[0])
    if len(input_names) != len(set(input_names)):
        return None
    return {name.casefold() for name in input_names}


def _expression_uses_retired_dispatch_inputs(
    expression: str, workflow_call_inputs: set[str],
) -> bool:
    """Distinguish retained static workflow_call inputs from retired dispatch use."""
    static_property = re.compile(
        r'''(?:["']\s*\]\s*)?\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_-]*)'''
        r'''|\[\s*["']([^"']+)["']\s*\])'''
    )
    for context in re.finditer(r"\binputs\b", expression, flags=re.IGNORECASE):
        property_match = static_property.match(expression[context.end():])
        if property_match is None:
            return True
        name = next(value for value in property_match.groups() if value is not None)
        if name.casefold() == "pr_number" \
                or name.casefold() not in workflow_call_inputs:
            return True
    return False


def _top_level_mapping_lines(text: str, key: str) -> list[str] | None:
    """Return one root mapping's child lines without accepting inline YAML."""
    section = top_level_mapping_section_span(text, key)
    if section is None:
        return None
    return text[section[0]:section[1]].splitlines()


def _yaml_expression_value(lines: list[str], key: str) -> str | None:
    """Read one simple or folded scalar and normalize its GitHub expression."""
    section = _yaml_mapping_section(lines, key)
    if section is None:
        return None
    nested, tail = section
    raw = re.split(r"[ \t]+#", tail, maxsplit=1)[0].strip()
    nested_values = [
        line.strip()
        for line in nested
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if _yaml_block_scalar_header(raw):
        if not nested_values:
            return None
        raw = " ".join(nested_values)
    elif nested_values:
        return None
    if not raw:
        return None
    if raw.startswith("${{") and raw.endswith("}}"):
        raw = raw[3:-2].strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {"'", '"'}:
        raw = raw[1:-1]
    return re.sub(r"\s+", "", raw)


def _trusted_base_job_blocks(
    text: str,
) -> tuple[list[tuple[str, list[str]]], list[str]]:
    """Parse only direct YAML jobs; trusted-base admission fails closed otherwise."""
    nested = _top_level_mapping_lines(text, "jobs")
    if nested is None:
        return [], ["trusted-base validation workflow requires one top-level jobs mapping"]
    if _yaml_unparsed_direct_mapping_lines(nested):
        return [], ["trusted-base validation workflow jobs contain unsupported or escaped job ids"]
    entries = _yaml_direct_entries(nested)
    if not entries:
        return [], ["trusted-base validation workflow jobs mapping has no parseable direct jobs"]
    blocks: list[tuple[str, list[str]]] = []
    errors: list[str] = []
    seen: set[str] = set()
    for position, (index, _indent, job_id, tail) in enumerate(entries):
        if job_id in seen:
            errors.append(f"trusted-base validation workflow duplicates job {job_id}")
            continue
        seen.add(job_id)
        if tail and not tail.startswith("#"):
            errors.append(
                f"trusted-base validation job {job_id} uses an unsupported inline definition"
            )
            continue
        end = entries[position + 1][0] if position + 1 < len(entries) else len(nested)
        block = nested[index + 1:end]
        if _yaml_unparsed_direct_mapping_lines(block):
            errors.append(
                f"trusted-base validation job {job_id} contains unsupported or escaped keys"
            )
            continue
        blocks.append((job_id, block))
    return blocks, errors


def _trusted_base_checkout_refs(lines: list[str]) -> list[str | None]:
    """Return every direct checkout ref; malformed checkout steps return None."""
    refs: list[str | None] = []
    checkout = re.compile(
        r"^( *)(?:-[ \t]+)?(?:uses|['\"]uses['\"]):[ \t]*actions/checkout@"
    )
    step = re.compile(r"^( *)-[ \t]+")
    for index, line in enumerate(lines):
        match = checkout.match(line)
        if match is None:
            continue
        direct_step = re.match(r"^( *)-[ \t]+", line)
        if direct_step is not None:
            start = index
        else:
            uses_indent = len(match.group(1))
            start = None
            for candidate in range(index - 1, -1, -1):
                step_match = step.match(lines[candidate])
                if step_match is not None and len(step_match.group(1)) < uses_indent:
                    start = candidate
                    break
        if start is None:
            refs.append(None)
            continue
        end = len(lines)
        step_indent = len(step.match(lines[start]).group(1))
        for candidate in range(index + 1, len(lines)):
            step_match = step.match(lines[candidate])
            if step_match is not None and len(step_match.group(1)) <= step_indent:
                end = candidate
                break
            if lines[candidate].strip() and not lines[candidate].lstrip().startswith("#") \
                    and len(lines[candidate]) - len(lines[candidate].lstrip(" ")) < step_indent:
                end = candidate
                break
        step_lines = lines[start + 1:end]
        with_section = _yaml_mapping_section(step_lines, "with")
        refs.append(
            _yaml_expression_value(with_section[0], "ref")
            if with_section is not None else None
        )
    return refs


def _trusted_base_self_hosted_runner(job_lines: list[str]) -> bool:
    """Treat every non-GitHub-hosted or dynamic target as self-hosted."""
    value = _yaml_expression_value(job_lines, "runs-on")
    if value is None:
        return False
    if "${{" in value or value.startswith("["):
        return True
    hosted = re.fullmatch(
        r"(?:ubuntu|windows|macos)-(?:latest|[0-9]+(?:\.[0-9]+)?)", value,
    )
    return hosted is None


def _trusted_base_reusable_ref(job_lines: list[str]) -> str | None:
    with_section = _yaml_mapping_section(job_lines, "with")
    return _yaml_expression_value(with_section[0], "checkout_ref") \
        if with_section is not None else None


def _trusted_base_fork_rejection(
    blocks: list[tuple[str, list[str]]], protected_jobs: set[str],
) -> bool:
    """Require a hosted all-success fan-in so a skipped fork job fails CI."""
    for _job_id, lines in blocks:
        if _yaml_expression_value(lines, "if") != "always()":
            continue
        needs = _yaml_list(lines, "needs")
        if needs is None or not protected_jobs.issubset(needs):
            continue
        body = "\n".join(lines)
        if re.search(
            r"for\s+result\s+in\s+.+?;\s*do.*?"
            r"if\s+\[\s+\"?\$result\"?\s*!=\s*success\s*\];\s*then.*?"
            r"\bexit\s+1\b",
            body,
            flags=re.DOTALL,
        ):
            return True
    return False


def trusted_base_validation_workflow_errors(
    text: str, trigger_lines: list[str], pull_request_target: tuple[list[str], str],
) -> list[str]:
    """Verify the sole public trusted-base wrapper permitted for code validation."""
    errors: list[str] = []
    target_lines, target_tail = pull_request_target
    if target_tail and not target_tail.startswith("#"):
        errors.append(
            "validation workflow on.pull_request_target uses an unsupported inline definition"
        )
    if _yaml_unparsed_direct_mapping_lines(target_lines):
        errors.append(
            "validation workflow pull_request_target contains unsupported or escaped keys"
        )
    target_keys = _yaml_direct_keys(target_lines)
    if set(target_keys) - {"types", "branches"}:
        errors.append(
            "validation workflow pull_request_target contains unsupported keys: "
            + ", ".join(sorted(set(target_keys) - {"types", "branches"}))
        )
    if _yaml_list(target_lines, "types") != VALIDATION_PULL_REQUEST_ACTIONS:
        errors.append(
            "validation workflow on.pull_request_target.types must equal opened, synchronize, reopened"
        )
    if "branches" in target_keys and _yaml_literal_branches(target_lines) is None:
        errors.append(
            "validation workflow pull_request_target.branches must contain only literal "
            "base branch names"
        )
    trigger_keys = _yaml_direct_keys(trigger_lines)
    if set(trigger_keys) - {"pull_request_target", "merge_group"}:
        errors.append(
            "trusted-base validation workflow may contain only pull_request_target "
            "and merge_group triggers"
        )
    if trigger_keys.count("pull_request_target") != 1:
        errors.append("trusted-base validation workflow requires exactly one pull_request_target trigger")

    env_lines = _top_level_mapping_lines(text, "env")
    checkout_ref = _yaml_expression_value(env_lines, "CHECKOUT_REF") \
        if env_lines is not None else None
    if checkout_ref != TRUSTED_BASE_CHECKOUT_REF:
        errors.append(
            "trusted-base validation workflow CHECKOUT_REF must select the PR head only "
            "when head.repo.full_name equals github.repository and otherwise github.sha"
        )
    semantic_text = _yaml_double_quoted_semantic_view(text)
    checkout_ref_assignments = [
        line for line in semantic_text.splitlines()
        if not line.lstrip().startswith("#")
        and re.match(r"^\s*[^:#]*CHECKOUT_REF[^:#]*:\s*", line)
    ]
    if len(checkout_ref_assignments) != 1:
        errors.append(
            "trusted-base validation workflow must declare CHECKOUT_REF once at the "
            "top level and may not override it in a job or step"
        )

    checkout_refs = _trusted_base_checkout_refs(text.splitlines())
    if not checkout_refs:
        errors.append("trusted-base validation workflow must check out CHECKOUT_REF explicitly")
    elif any(value != "env.CHECKOUT_REF" for value in checkout_refs):
        errors.append(
            "trusted-base validation workflow actions/checkout steps must use env.CHECKOUT_REF"
        )

    blocks, job_errors = _trusted_base_job_blocks(text)
    errors.extend(job_errors)
    protected_jobs: set[str] = set()
    for job_id, job_lines in blocks:
        uses = _yaml_expression_value(job_lines, "uses")
        self_hosted = _trusted_base_self_hosted_runner(job_lines)
        protected = uses is not None or self_hosted
        if not protected:
            if "github.event.pull_request.head" in "\n".join(job_lines):
                errors.append(
                    f"trusted-base hosted job {job_id} may not reference the untrusted PR head"
                )
            if _trusted_base_checkout_refs(job_lines) and \
                    _yaml_expression_value(job_lines, "if") != TRUSTED_BASE_HOSTED_GATE:
                errors.append(
                    f"trusted-base hosted job {job_id} must use the exact full-validation "
                    "pull_request_target gate"
                )
            continue
        protected_jobs.add(job_id)
        if _yaml_expression_value(job_lines, "if") != TRUSTED_BASE_SELF_HOSTED_GATE:
            errors.append(
                f"trusted-base self-hosted job {job_id} must enforce same-repository "
                "pull_request_target admission"
            )
        if uses is not None:
            if not re.fullmatch(r"\./\.github/workflows/[A-Za-z0-9_./-]+\.ya?ml", uses):
                errors.append(
                    f"trusted-base reusable job {job_id} must call a local reusable workflow"
                )
            if _trusted_base_reusable_ref(job_lines) != TRUSTED_BASE_REUSABLE_REF:
                errors.append(
                    f"trusted-base reusable job {job_id} must pass checkout_ref as the "
                    "same-repository PR head or merge-group sha"
                )
        else:
            refs = _trusted_base_checkout_refs(job_lines)
            if not refs or any(value != "env.CHECKOUT_REF" for value in refs):
                errors.append(
                    f"trusted-base self-hosted job {job_id} must check out env.CHECKOUT_REF"
                )
    if not protected_jobs:
        errors.append(
            "trusted-base validation workflow requires at least one same-repository "
            "self-hosted or reusable validation job"
        )
    elif not _trusted_base_fork_rejection(blocks, protected_jobs):
        errors.append(
            "trusted-base validation workflow requires an always-running hosted fan-in "
            "that fails when a protected fork job is skipped"
        )
    return errors


def workflow_trigger_errors(text: str) -> list[str]:
    """Structurally validate dedicated lifecycle triggers without a YAML dependency."""
    lines = text.splitlines()
    if _yaml_unparsed_direct_mapping_lines(lines):
        return ["workflow contains unsupported or escaped top-level keys"]
    on_pattern = re.compile(
        r'^(?:on|["\']on["\']):(?:[ \t]+#.*)?[ \t]*$'
    )
    on_indexes = [index for index, line in enumerate(lines) if on_pattern.match(line)]
    if len(on_indexes) != 1:
        return ["workflow must contain exactly one top-level on mapping"]
    start = on_indexes[0] + 1
    end = len(lines)
    for index in range(start, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            end = index
            break
    trigger_lines = lines[start:end]
    errors: list[str] = []
    if _yaml_unparsed_direct_mapping_lines(trigger_lines):
        errors.append("top-level on contains unsupported or escaped keys")

    pull_request = _yaml_mapping_section(trigger_lines, "pull_request")
    if pull_request is None or (pull_request[1] and not pull_request[1].startswith("#")):
        errors.append("top-level on.pull_request mapping is missing")
    else:
        actions = _yaml_list(pull_request[0], "types")
        if actions != PULL_REQUEST_ACTIONS:
            missing = sorted(PULL_REQUEST_ACTIONS - (actions or set()))
            extra = sorted((actions or set()) - PULL_REQUEST_ACTIONS)
            errors.append(
                "on.pull_request.types differs from lifecycle contract"
                + (f"; missing {', '.join(missing)}" if missing else "")
                + (f"; unexpected {', '.join(extra)}" if extra else "")
            )

    merge_group = _yaml_mapping_section(trigger_lines, "merge_group")
    if merge_group is None or (merge_group[1] and not merge_group[1].startswith("#")):
        errors.append("top-level on.merge_group mapping is missing")
    elif _yaml_list(merge_group[0], "types") != {"checks_requested"}:
        errors.append("on.merge_group.types must equal checks_requested")

    dispatch = _yaml_mapping_section(trigger_lines, "workflow_dispatch")
    if dispatch is None or (dispatch[1] and not dispatch[1].startswith("#")):
        errors.append("top-level on.workflow_dispatch mapping is missing")
    else:
        inputs = _yaml_mapping_section(dispatch[0], "inputs")
        pr_number = (
            _yaml_mapping_section(inputs[0], "pr_number")
            if inputs is not None else None
        )
        if pr_number is None or (
            pr_number[1] and not pr_number[1].startswith("#")
        ):
            errors.append("on.workflow_dispatch.inputs.pr_number mapping is missing")
        else:
            if _yaml_boolean(pr_number[0], "required") != "true":
                errors.append(
                    "on.workflow_dispatch.inputs.pr_number.required must equal true"
                )
            if _yaml_scalar(pr_number[0], "type") != "number":
                errors.append(
                    "on.workflow_dispatch.inputs.pr_number.type must equal number"
                )
    return errors


def validation_workflow_trigger_errors(
    text: str, *, include_check_contexts: bool = True,
) -> list[str]:
    """Reject metadata activity in a workflow that publishes required code checks."""
    lines = text.splitlines()
    if _yaml_unparsed_direct_mapping_lines(lines):
        return [
            "validation workflow contains unsupported or escaped top-level keys"
        ]
    on_pattern = re.compile(
        r'^(?:on|["\']on["\']):(?:[ \t]+#.*)?[ \t]*$'
    )
    on_indexes = [index for index, line in enumerate(lines) if on_pattern.match(line)]
    if len(on_indexes) != 1:
        return ["validation workflow must contain exactly one top-level on mapping"]
    start = on_indexes[0] + 1
    end = len(lines)
    for index in range(start, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            end = index
            break
    trigger_lines = lines[start:end]
    errors: list[str] = []
    if _yaml_unparsed_direct_mapping_lines(trigger_lines):
        errors.append(
            "validation workflow top-level on contains unsupported or escaped keys"
        )
    trigger_keys = _yaml_direct_keys(trigger_lines)
    if len(trigger_keys) != len(set(trigger_keys)):
        errors.append("validation workflow top-level on contains duplicate event keys")
    pull_request = _yaml_mapping_section(trigger_lines, "pull_request")
    pull_request_target = _yaml_mapping_section(trigger_lines, "pull_request_target")
    trusted_base = pull_request_target is not None
    if trusted_base:
        if pull_request is not None:
            errors.append(
                "trusted-base validation workflow may not also subscribe to pull_request"
            )
        errors.extend(
            trusted_base_validation_workflow_errors(
                text, trigger_lines, pull_request_target,
            )
        )
    else:
        if pull_request is None or (pull_request[1] and not pull_request[1].startswith("#")):
            return ["validation workflow top-level on.pull_request mapping is missing"]
        actions = _yaml_list(pull_request[0], "types")
        if actions is None:
            return ["validation workflow on.pull_request.types must be a literal list"]
        if _yaml_unparsed_direct_mapping_lines(pull_request[0]):
            errors.append(
                "validation workflow pull_request contains unsupported or escaped keys"
            )
        missing = sorted(VALIDATION_PULL_REQUEST_ACTIONS - actions)
        metadata = sorted(actions - VALIDATION_PULL_REQUEST_ACTIONS)
        if missing:
            errors.append(
                "validation workflow is missing code pull_request actions: "
                + ", ".join(missing)
            )
        if metadata:
            errors.append(
                "validation workflow subscribes to lifecycle-only pull_request actions: "
                + ", ".join(metadata)
            )
        pull_keys = set(_yaml_direct_keys(pull_request[0]))
        unsupported_filters = sorted(
            pull_keys & {"paths", "paths-ignore", "branches-ignore"}
        )
        if unsupported_filters:
            errors.append(
                "validation workflow has suppressive pull_request filters: "
                + ", ".join(unsupported_filters)
            )
        unsupported_keys = sorted(
            pull_keys
            - {"types", "branches", "paths", "paths-ignore", "branches-ignore"}
        )
        if unsupported_keys:
            errors.append(
                "validation workflow pull_request contains unsupported keys: "
                + ", ".join(unsupported_keys)
            )
        if "branches" in pull_keys:
            branches = _yaml_literal_branches(pull_request[0])
            if branches is None:
                errors.append(
                    "validation workflow pull_request.branches must contain only literal "
                    "base branch names"
                )
    merge_group = _yaml_mapping_section(trigger_lines, "merge_group")
    if merge_group is None or (merge_group[1] and not merge_group[1].startswith("#")):
        errors.append("validation workflow top-level on.merge_group mapping is missing")
    elif _yaml_list(merge_group[0], "types") != {"checks_requested"}:
        errors.append("validation workflow on.merge_group.types must equal checks_requested")
    elif set(_yaml_direct_keys(merge_group[0])) != {"types"}:
        errors.append("validation workflow on.merge_group may contain only types")
    elif _yaml_unparsed_direct_mapping_lines(merge_group[0]):
        errors.append(
            "validation workflow merge_group contains unsupported or escaped keys"
        )
    dispatch = _yaml_mapping_section(trigger_lines, "workflow_dispatch")
    if dispatch is not None:
        if dispatch[1] and not dispatch[1].startswith("#"):
            errors.append(
                "validation workflow workflow_dispatch uses an unsupported inline definition"
            )
        elif _yaml_unparsed_direct_mapping_lines(dispatch[0]):
            errors.append(
                "validation workflow workflow_dispatch contains unsupported or escaped keys"
            )
        else:
            dispatch_keys = _yaml_direct_keys(dispatch[0])
            if len(dispatch_keys) != len(set(dispatch_keys)):
                errors.append(
                    "validation workflow workflow_dispatch contains duplicate keys"
                )
            unsupported_dispatch = sorted(set(dispatch_keys) - {"inputs"})
            if unsupported_dispatch:
                errors.append(
                    "validation workflow workflow_dispatch contains unsupported keys: "
                    + ", ".join(unsupported_dispatch)
                )
            inputs = _yaml_mapping_section(dispatch[0], "inputs")
            if inputs is not None and inputs[1] and not inputs[1].startswith("#"):
                errors.append(
                    "validation workflow workflow_dispatch.inputs uses an unsupported "
                    "inline definition"
                )
            elif inputs is not None and _yaml_unparsed_direct_mapping_lines(inputs[0]):
                errors.append(
                    "validation workflow workflow_dispatch.inputs contains unsupported "
                    "or escaped keys"
                )
            elif inputs is not None:
                input_keys = _yaml_direct_keys(inputs[0])
                if len(input_keys) != len(set(input_keys)):
                    errors.append(
                        "validation workflow workflow_dispatch.inputs contains "
                        "duplicate input keys"
                    )
                if "pr_number" in input_keys:
                    errors.append(
                        "validation workflow retains lifecycle-only "
                        "workflow_dispatch.inputs.pr_number"
                    )
    if include_check_contexts:
        errors.extend(validation_workflow_check_context_errors(text))
        if not trusted_base:
            errors.extend(validation_workflow_job_execution_errors(text))
        errors.extend(validation_workflow_matrix_errors(text))
    return errors


def validation_workflow_base_errors(text: str, base_ref_name: str) -> list[str]:
    """Require any literal branch allowlist to include the live PR base."""
    if not base_ref_name or re.search(r"[\r\n]", base_ref_name):
        return ["pull request lacks a valid current base branch name"]
    lines = text.splitlines()
    on_indexes = [
        index for index, line in enumerate(lines)
        if re.match(
            r'^(?:on|["\']on["\']):(?:[ \t]+#.*)?[ \t]*$', line,
        )
    ]
    if len(on_indexes) != 1:
        return ["validation workflow must contain exactly one top-level on mapping"]
    end = len(lines)
    for index in range(on_indexes[0] + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            end = index
            break
    trigger_lines = lines[on_indexes[0] + 1:end]
    pull_request = _yaml_mapping_section(trigger_lines, "pull_request")
    event_name = "pull_request"
    if pull_request is None:
        pull_request = _yaml_mapping_section(trigger_lines, "pull_request_target")
        event_name = "pull_request_target"
    if pull_request is None:
        return ["validation workflow top-level on.pull_request mapping is missing"]
    if "branches" not in set(_yaml_direct_keys(pull_request[0])):
        return []
    branches = _yaml_literal_branches(pull_request[0])
    if branches is None or base_ref_name not in branches:
        return [
            f"validation workflow {event_name}.branches excludes current base {base_ref_name}"
        ]
    return []


def validation_workflow_job_execution_errors(text: str) -> list[str]:
    """Reject job gates that can skip reopened or merge-group full validation."""
    lines = text.splitlines()
    jobs = [
        index for index, line in enumerate(lines)
        if re.match(
            r'''^(?:jobs|["']jobs["'])[ \t]*:(?:[ \t]+#.*)?[ \t]*$''',
            line,
        )
    ]
    if len(jobs) != 1:
        return []
    end = len(lines)
    for index in range(jobs[0] + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            end = index
            break
    nested = lines[jobs[0] + 1:end]
    entries = _yaml_direct_entries(nested)
    if _yaml_unparsed_direct_mapping_lines(nested):
        return ["validation workflow jobs contains unsupported or escaped job ids"]
    safe_full_event = (
        "github.event_name == 'merge_group' || "
        "(github.event_name == 'pull_request' && "
        "contains(fromJSON('[\"opened\",\"synchronize\",\"reopened\"]'), "
        "github.event.action))"
    )
    safe_with_dispatch = "github.event_name == 'workflow_dispatch' || " + safe_full_event
    safe = {"true", "always()", safe_full_event, safe_with_dispatch}
    errors: list[str] = []
    for position, (index, _indent, job_id, _tail) in enumerate(entries):
        job_end = entries[position + 1][0] if position + 1 < len(entries) else len(nested)
        job_lines = nested[index + 1:job_end]
        if _yaml_unparsed_direct_mapping_lines(job_lines):
            errors.append(
                f"validation job {job_id} contains unsupported or escaped keys"
            )
            continue
        job_entries = _yaml_direct_entries(job_lines)
        gates = [entry for entry in job_entries if entry[2] == "if"]
        if not gates:
            continue
        if len(gates) != 1:
            errors.append(f"validation job {job_id} contains duplicate if keys")
            continue
        gate_index, _gate_indent, _gate_name, gate_tail = gates[0]
        raw_tail = gate_tail.strip()
        if raw_tail.startswith("'"):
            quoted = re.fullmatch(
                r"'([^']*)'(?:[ \t]+#.*)?[ \t]*", raw_tail,
            )
            if quoted is None:
                errors.append(
                    f"validation job {job_id} has an ambiguous quoted if condition"
                )
                continue
            raw = quoted.group(1)
        elif raw_tail.startswith('"'):
            quoted = re.fullmatch(
                r'"([^"\\]*)"(?:[ \t]+#.*)?[ \t]*', raw_tail,
            )
            if quoted is None:
                errors.append(
                    f"validation job {job_id} has an ambiguous quoted if condition"
                )
                continue
            raw = quoted.group(1)
        else:
            raw = re.split(r"[ \t]+#", raw_tail, maxsplit=1)[0].strip()
        if _yaml_block_scalar_header(raw):
            gate_position = next(
                item for item, entry in enumerate(job_entries) if entry[0] == gate_index
            )
            gate_end = (
                job_entries[gate_position + 1][0]
                if gate_position + 1 < len(job_entries) else len(job_lines)
            )
            raw = " ".join(
                line.strip()
                for line in job_lines[gate_index + 1:gate_end]
                if line.strip()
                and len(line) - len(line.lstrip(" ")) > _gate_indent
            )
        raw = raw.strip()
        if raw.startswith("${{") and raw.endswith("}}"):
            raw = raw[3:-2].strip()
        normalized = re.sub(r"\s+", " ", raw)
        if normalized not in safe:
            errors.append(
                f"validation job {job_id} has an if condition that can skip reopened "
                "or merge-group full validation"
            )
    return errors


SCHEDULABLE_MATRIX_MARKER = "# hv-agent-schedulable-matrix:"


def validation_workflow_matrix_errors(text: str) -> list[str]:
    """Require expression-driven strategy matrices to stay schedulable when empty.

    GitHub cannot expand a matrix that resolves to no vectors: the job is
    dropped from the execution graph, its dependents still run, and its result
    is reported as failure — never skipped — to both ``needs`` readers and the
    run conclusion. Because the job-execution contract keeps validation jobs
    unconditional, a matrix taken from a change-detection output must always
    resolve to at least one vector (a placeholder when nothing is in scope,
    with the job's steps guarded on the scope output). The producer-side
    guarantee is not statically checkable, so the workflow attests it with a
    ``# hv-agent-schedulable-matrix: <reason>`` comment directly above the
    matrix key.
    """
    lines = text.splitlines()
    jobs = [
        index for index, line in enumerate(lines)
        if re.match(
            r'''^(?:jobs|["']jobs["'])[ \t]*:(?:[ \t]+#.*)?[ \t]*$''',
            line,
        )
    ]
    if len(jobs) != 1:
        return []
    end = len(lines)
    for index in range(jobs[0] + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            end = index
            break
    nested = lines[jobs[0] + 1:end]
    if _yaml_unparsed_direct_mapping_lines(nested):
        return []
    entries = _yaml_direct_entries(nested)
    errors: list[str] = []
    for position, (index, _indent, job_id, _tail) in enumerate(entries):
        job_end = entries[position + 1][0] if position + 1 < len(entries) else len(nested)
        job_lines = nested[index + 1:job_end]
        if _yaml_unparsed_direct_mapping_lines(job_lines):
            continue
        for strategy_index, strategy_indent, key, strategy_tail in _yaml_direct_entries(job_lines):
            if key != "strategy":
                continue
            if strategy_tail.strip():
                errors.append(
                    f"validation job {job_id} has an ambiguous inline strategy "
                    "mapping; declare strategy as a block mapping"
                )
                continue
            block_end = len(job_lines)
            for candidate in range(strategy_index + 1, len(job_lines)):
                line = job_lines[candidate]
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                if len(line) - len(line.lstrip(" ")) <= strategy_indent:
                    block_end = candidate
                    break
            strategy_lines = job_lines[strategy_index + 1:block_end]
            for matrix_offset, matrix_indent, name, matrix_tail in _yaml_direct_entries(strategy_lines):
                if name != "matrix":
                    continue
                value_end = len(strategy_lines)
                for candidate in range(matrix_offset + 1, len(strategy_lines)):
                    line = strategy_lines[candidate]
                    if not line.strip() or line.lstrip().startswith("#"):
                        continue
                    if len(line) - len(line.lstrip(" ")) <= matrix_indent:
                        value_end = candidate
                        break
                value_lines = strategy_lines[matrix_offset + 1:value_end]
                if "${{" not in matrix_tail \
                        and not any("${{" in line for line in value_lines):
                    continue
                previous = (
                    strategy_lines[matrix_offset - 1]
                    if matrix_offset > 0 else job_lines[strategy_index]
                )
                marker = re.fullmatch(
                    r" *" + re.escape(SCHEDULABLE_MATRIX_MARKER) + r"(.*)",
                    previous,
                )
                if marker is None:
                    errors.append(
                        f"validation job {job_id} drives strategy.matrix from an "
                        "expression without a schedulable-matrix attestation; GitHub "
                        "drops a job whose matrix resolves to no vectors and reports "
                        "failure, never skipped, to dependent jobs and the run "
                        "conclusion, while the lifecycle contract keeps validation "
                        "jobs unconditional; make the producer emit a placeholder "
                        "vector whenever the change scope is empty, guard the job's "
                        "steps on the scope output, then attest the guarantee with "
                        f"'{SCHEDULABLE_MATRIX_MARKER} <reason>' directly above the "
                        "matrix key"
                    )
                elif not marker.group(1).strip():
                    errors.append(
                        f"validation job {job_id} schedulable-matrix attestation "
                        "must record the reason the matrix always resolves to at "
                        "least one vector"
                    )
    return errors


def validation_workflow_check_context_errors(
    text: str, *, require_jobs: bool = True,
) -> list[str]:
    """Reserve the exact lifecycle check context for organization authority."""
    lines = text.splitlines()
    if _yaml_unparsed_direct_mapping_lines(lines):
        return [
            "workflow contains unsupported or escaped top-level keys that may "
            "publish the reserved exact lifecycle check context"
        ]
    jobs = [
        index
        for index, line in enumerate(lines)
        if re.match(
            r'''^(?:jobs|["']jobs["'])[ \t]*:(?:[ \t]+#.*)?[ \t]*$''',
            line,
        )
    ]
    if len(jobs) != 1:
        if not require_jobs and not jobs:
            inline_jobs = [
                line for line in lines
                if re.match(
                    r'''^(?:jobs|["']jobs["'])[ \t]*:[ \t]+[^# \t].*$''',
                    line,
                )
            ]
            if not inline_jobs or all(
                re.fullmatch(
                    r'''(?:jobs|["']jobs["'])[ \t]*:[ \t]+\{\}[ \t]*(?:#.*)?''',
                    line,
                )
                for line in inline_jobs
            ):
                return []
            return [
                "workflow has an ambiguous inline jobs mapping that may publish "
                "the reserved exact lifecycle check context"
            ]
        return ["validation workflow must contain exactly one top-level jobs mapping"]
    end = len(lines)
    for index in range(jobs[0] + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            end = index
            break
    nested = lines[jobs[0] + 1:end]
    if _yaml_unparsed_direct_mapping_lines(nested):
        return [
            "workflow jobs contains unsupported or escaped job ids that may publish "
            "the reserved exact lifecycle check context"
        ]
    entries = _yaml_direct_entries(nested)
    if not entries:
        if not require_jobs:
            return []
        return ["validation workflow jobs mapping has no parseable direct jobs"]
    errors: list[str] = []
    semantic_ids = [job_id for _, _, job_id, _ in entries]
    if len(semantic_ids) != len(set(semantic_ids)):
        errors.append("validation workflow contains duplicate semantic job ids")
    for position, (index, _, job_id, job_tail) in enumerate(entries):
        if job_tail and not job_tail.startswith("#"):
            errors.append(
                f"validation job {job_id} uses an unsupported inline definition"
            )
            continue
        job_end = entries[position + 1][0] if position + 1 < len(entries) else len(nested)
        job_lines = nested[index + 1:job_end]
        if _yaml_unparsed_direct_mapping_lines(job_lines):
            errors.append(
                f"validation job {job_id} contains unsupported or escaped keys that "
                "may publish the reserved exact lifecycle check context"
            )
            continue
        job_entries = _yaml_direct_entries(job_lines)
        names = [entry for entry in job_entries if entry[2] == "name"]
        if len(names) > 1:
            errors.append(f"validation job {job_id} contains duplicate name keys")
            continue
        name = names[0][3] if names else None
        name_indent = names[0][1] if names else None
        scalar_name = name.split("#", 1)[0].strip() if name is not None else None
        name_defaults_to_job_id = scalar_name is None or scalar_name in {
            "", "''", '\"\"', "null", "Null", "NULL", "~",
        }
        if job_id == "lifecycle" and name_defaults_to_job_id:
            errors.append(
                "validation job lifecycle defaults to the reserved exact lifecycle "
                "check context"
            )
            continue
        if name is not None and re.fullmatch(
            r'''(?:lifecycle|["']lifecycle["'])\s*(?:#.*)?''', name,
        ):
            errors.append(
                f"validation job {job_id} publishes reserved exact lifecycle check context"
            )
            continue
        if name is not None:
            unquoted = name.split("#", 1)[0].strip().strip("'\"")
            if unquoted.startswith(("|", ">")):
                if not _yaml_block_scalar_header(unquoted):
                    errors.append(
                        f"validation job {job_id} has an ambiguous block name that "
                        "may resolve to lifecycle"
                    )
                    continue
                name_index = names[0][0]
                name_position = next(
                    position
                    for position, entry in enumerate(job_entries)
                    if entry[0] == name_index
                )
                name_end = (
                    job_entries[name_position + 1][0]
                    if name_position + 1 < len(job_entries)
                    else len(nested[index + 1:job_end])
                )
                content = " ".join(
                    line.strip()
                    for line in nested[index + 1:job_end][name_index + 1:name_end]
                    if line.strip()
                    and name_indent is not None
                    and len(line) - len(line.lstrip(" ")) > name_indent
                )
                fixed_prefix = content.split("${{", 1)[0].strip()
                if not content or (
                    "${{" in content
                    and (not fixed_prefix or "lifecycle".startswith(fixed_prefix))
                ):
                    errors.append(
                        f"validation job {job_id} has a dynamic name that may resolve to lifecycle"
                    )
                    continue
                if "${{" not in content and content.strip("'\"") == "lifecycle":
                    errors.append(
                        f"validation job {job_id} publishes reserved exact lifecycle check context"
                    )
                    continue
            elif (
                "${{" in unquoted
                or "\\" in name
                or unquoted.startswith(("*", "!", "&"))
            ):
                errors.append(
                    f"validation job {job_id} has a dynamic name that may resolve to lifecycle"
                )
                continue
    return errors


def isolate_validation_workflow_triggers(text: str) -> str:
    """Narrow the exact folded lifecycle action list while preserving other YAML."""
    trigger_errors = workflow_trigger_errors(text)
    if trigger_errors:
        raise ValueError("; ".join(trigger_errors))
    workflow_call_inputs = _workflow_call_input_names(text)
    if workflow_call_inputs is None:
        raise ValueError(
            "on.workflow_call inputs are ambiguous; normalize the reusable workflow "
            "contract before lifecycle isolation"
        )
    lines = text.splitlines(keepends=True)
    on_indexes = [
        index for index, line in enumerate(lines)
        if re.match(
            r'^(?:on|["\']on["\']):(?:[ \t]+#.*)?[ \t]*(?:\r?\n)?$',
            line,
        )
    ]
    if len(on_indexes) != 1:
        raise ValueError("workflow must contain exactly one top-level on mapping")
    on_end = len(lines)
    for index in range(on_indexes[0] + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            on_end = index
            break
    trigger_lines = [line.rstrip("\r\n") for line in lines[on_indexes[0] + 1:on_end]]
    if not _legacy_lifecycle_dispatch_only(trigger_lines):
        raise ValueError(
            "on.workflow_dispatch mixes lifecycle pr_number with repository-owned inputs"
        )
    pull_index = next(
        (
            index for index in range(on_indexes[0] + 1, len(lines))
            if re.match(
                r'''^  (?:pull_request|["']pull_request["'])\s*:'''
                r'''\s*(?:#.*)?(?:\r?\n)?$''',
                lines[index],
            )
        ),
        None,
    )
    if pull_index is None:
        raise ValueError("top-level on.pull_request mapping is missing")
    pull_end = len(lines)
    for index in range(pull_index + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indentation = len(line) - len(line.lstrip(" "))
        if indentation <= 2:
            pull_end = index
            break
    types_index = next(
        (
            index for index in range(pull_index + 1, pull_end)
            if re.match(r'''^    (?:types|["']types["'])\s*:''', lines[index])
        ),
        None,
    )
    if types_index is None:
        raise ValueError("on.pull_request.types is missing")
    line = lines[types_index]
    newline = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
    body = line[:-len(newline)] if newline else line
    inline = re.match(r"^(    types:\s*)\[[^\]]*\](\s*(?:#.*)?)$", body)
    ordered = ["opened", "synchronize", "reopened"]
    if inline:
        lines[types_index] = (
            inline.group(1) + "[" + ", ".join(ordered) + "]" + inline.group(2) + newline
        )
    else:
        tail = body.split(":", 1)[1].strip()
        list_end = pull_end
        for index in range(types_index + 1, pull_end):
            candidate = lines[index]
            if not candidate.strip() or candidate.lstrip().startswith("#"):
                continue
            indentation = len(candidate) - len(candidate.lstrip(" "))
            if indentation <= 4:
                list_end = index
                break
        flow_head = _yaml_strip_flow_comment(tail).strip()
        opens_flow = flow_head.startswith("[") or (
            not flow_head
            and next(
                (
                    stripped
                    for index in range(types_index + 1, list_end)
                    for stripped in [
                        _yaml_strip_flow_comment(lines[index].rstrip("\r\n")).strip()
                    ]
                    if stripped
                ),
                "",
            ).startswith("[")
        )
        if opens_flow:
            # A flow sequence broken across lines (prettier's preferred
            # style). Collapse the exact value span to the canonical
            # validation list; trailing comment-only lines survive.
            if "]" in flow_head:
                raise ValueError("on.pull_request.types must be a literal list")
            parts = [flow_head] if flow_head else []
            close_index = None
            for index in range(types_index + 1, list_end):
                stripped = _yaml_strip_flow_comment(lines[index].rstrip("\r\n")).strip()
                if not stripped:
                    continue
                if close_index is not None:
                    raise ValueError("on.pull_request.types must be a literal list")
                parts.append(stripped)
                if "]" in stripped:
                    close_index = index
            if close_index is None or _yaml_flow_list("\n".join(parts)) is None:
                raise ValueError("on.pull_request.types must be a literal list")
            lines[types_index:close_index + 1] = [
                "    types: [" + ", ".join(ordered) + "]" + (newline or "\n")
            ]
        elif tail and not tail.startswith("#"):
            raise ValueError("on.pull_request.types must be a literal list")
        else:
            filtered: list[str] = []
            for candidate in lines[types_index + 1:list_end]:
                match = re.match(r"^(\s*)-\s*([A-Za-z_][A-Za-z0-9_-]*)(\s*(?:#.*)?(?:\r?\n)?)$", candidate)
                if match and match.group(2) in LIFECYCLE_ONLY_PULL_REQUEST_ACTIONS:
                    continue
                filtered.append(candidate)
            lines[types_index + 1:list_end] = filtered
    dispatch_index = next(
        index for index in range(on_indexes[0] + 1, on_end)
        if re.match(
            r'''^  (?:workflow_dispatch|["']workflow_dispatch["'])\s*:'''
            r'''\s*(?:#.*)?(?:\r?\n)?$''',
            lines[index],
        )
    )
    dispatch_end = on_end
    for index in range(dispatch_index + 1, on_end):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indentation = len(line) - len(line.lstrip(" "))
        if indentation <= 2:
            dispatch_end = index
            break
    del lines[dispatch_index:dispatch_end]
    concurrency_indexes = [
        index for index, line in enumerate(lines)
        if re.match(
            r'^(?:concurrency|["\']concurrency["\']):'
            r'(?:[ \t]+#.*)?[ \t]*(?:\r?\n)?$',
            line,
        )
    ]
    if len(concurrency_indexes) > 1:
        raise ValueError("workflow contains multiple top-level concurrency mappings")
    if concurrency_indexes:
        concurrency_start = concurrency_indexes[0]
        concurrency_end = len(lines)
        for index in range(concurrency_start + 1, len(lines)):
            line = lines[index]
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if not line.startswith((" ", "\t")):
                concurrency_end = index
                break
        removable = [
            index for index in range(concurrency_start + 1, concurrency_end)
            if lines[index].strip() == "inputs.pr_number ||"
        ]
        for index in range(concurrency_start + 1, concurrency_end):
            if index in removable or "inputs.pr_number ||" not in lines[index]:
                continue
            if lines[index].count("inputs.pr_number ||") != 1:
                raise ValueError(
                    "top-level concurrency has ambiguous pr_number dispatch references"
                )
            lines[index] = lines[index].replace("inputs.pr_number || ", "", 1)
        for index in reversed(removable):
            del lines[index]
    isolated = "".join(lines)
    outside_lifecycle = re.sub(
        r"(?ms)^  # hv-agent-policy:start\n.*?^  # hv-agent-policy:end\n?",
        "",
        isolated,
    )
    semantic_outside_lifecycle = _yaml_double_quoted_semantic_view(outside_lifecycle)
    expressions = _github_expression_bodies(semantic_outside_lifecycle)
    if any(
        _expression_uses_retired_dispatch_inputs(expression, workflow_call_inputs)
        for expression in expressions
    ):
        raise ValueError(
            "on.workflow_dispatch pr_number is referenced outside the managed lifecycle "
            "job; separate the repository-owned full-CI dispatch before migration"
        )
    errors = validation_workflow_trigger_errors(isolated, include_check_contexts=False)
    if errors:
        raise ValueError("; ".join(errors))
    return isolated


def workflow_references_lifecycle_job(text: str) -> bool:
    """Detect repository jobs that retain an explicit dependency on job id lifecycle."""
    text = _yaml_double_quoted_semantic_view(text)
    direct_reference = bool(
        re.search(r"\bneeds\.lifecycle\b", text, flags=re.IGNORECASE)
        or re.search(
            r'''(?m)^\s*needs:\s*(?:lifecycle|["']lifecycle["'])\s*(?:#.*)?$''',
            text, flags=re.IGNORECASE,
        )
        or re.search(
            r"(?m)^\s*needs:\s*\[[^\]]*\blifecycle\b",
            text, flags=re.IGNORECASE,
        )
    )
    if direct_reference:
        return True
    lines = text.splitlines()
    for index, line in enumerate(lines):
        scalar = re.match(
            r"^(\s*)needs:(?:[ \t]+(.*?))?[ \t]*$", line,
        )
        if scalar is not None and scalar.group(2):
            tail = scalar.group(2)
            if re.search(r"\blifecycle\b", tail, flags=re.IGNORECASE) or re.search(
                r"(?:^|[\s,\[])[!&*]|\\", tail,
            ):
                return True
        match = re.match(r"^(\s*)needs:(?:[ \t]+#.*)?[ \t]*$", line)
        if match is None:
            continue
        parent_indent = len(match.group(1))
        for candidate in lines[index + 1:]:
            stripped = candidate.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(candidate) - len(candidate.lstrip(" "))
            if indent <= parent_indent:
                break
            item = re.match(r"^-\s*(.*?)(?:[ \t]+#.*)?[ \t]*$", stripped)
            if item is not None and (
                re.search(r"\blifecycle\b", item.group(1), flags=re.IGNORECASE)
                or re.search(r"^(?:[!&*])|\\", item.group(1))
            ):
                return True
    return False


def authority_substrate_predecessor_components(
    value: Any, generation: Any, current: dict[str, str], label: str,
) -> tuple[dict[str, str], list[str]]:
    """Validate exact predecessor digests for one signed artifact generation.

    The authority repository executes its own substrate, so the checker binds
    those bytes to the running artifact. V1 pins the immediately preceding
    numeric generation. V2 records the complete selected lock and every
    intervening generation when publication skipped or failed before prepare.
    Both forms bind exact digests to one candidate generation, so the migration
    to the new bytes lands inside the paused canary window as an exact match.
    Any other difference stays drift.
    """
    if not isinstance(value, dict):
        return {}, [f"{label} has unexpected or missing fields"]
    errors: list[str] = []
    schema = value.get("schema")
    if schema == AUTHORITY_SUBSTRATE_PREDECESSOR_SCHEMA:
        if set(value) != AUTHORITY_SUBSTRATE_PREDECESSOR_FIELDS:
            errors.append(f"{label} has unexpected or missing fields")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 2:
            errors.append(f"{label} cannot bind to artifact generation {generation!r}")
        elif value.get("generation") != generation - 1:
            errors.append(f"{label} must pin the exact predecessor generation {generation - 1}")
        commit = value.get("source_commit")
        if not isinstance(commit, str) or not GIT_COMMIT_PATTERN.fullmatch(commit):
            errors.append(f"{label} source_commit must be a lowercase 40-character Git OID")
    elif schema == AUTHORITY_SUBSTRATE_GAP_PREDECESSOR_SCHEMA:
        if set(value) != AUTHORITY_SUBSTRATE_GAP_PREDECESSOR_FIELDS:
            errors.append(f"{label} has unexpected or missing fields")
        valid_generation = (
            not isinstance(generation, bool)
            and isinstance(generation, int)
            and generation >= 2
        )
        if not valid_generation:
            errors.append(f"{label} cannot bind to artifact generation {generation!r}")
        elif value.get("artifact_generation") != generation:
            errors.append(f"{label} must bind to artifact generation {generation}")
        selected = value.get("selected_predecessor")
        selected_generation: Any = None
        if not isinstance(selected, dict):
            errors.append(f"{label} selected_predecessor has unexpected or missing fields")
        else:
            selected_fields = set(selected)
            selected_generation = selected.get("generation")
            expects_rollout = (
                isinstance(selected_generation, int)
                and not isinstance(selected_generation, bool)
                and selected_generation >= ROLLOUT_METADATA_GENERATION
            )
            expected_fields = (
                AUTHORITY_SUBSTRATE_SELECTED_LOCK_ROLLOUT_FIELDS
                if expects_rollout else AUTHORITY_SUBSTRATE_SELECTED_LOCK_FIELDS
            )
            if selected_fields != expected_fields:
                errors.append(f"{label} selected_predecessor has unexpected or missing fields")
            if selected.get("schema") != "hv-agent-policy-lock:v1":
                errors.append(f"{label} selected_predecessor has an unsupported schema")
            artifact = selected.get("artifact")
            if not isinstance(artifact, str) or not re.fullmatch(
                r"ghcr\.io/happyvertical/agent-policy@sha256:[0-9a-f]{64}",
                artifact,
            ):
                errors.append(
                    f"{label} selected_predecessor artifact must be an immutable "
                    "HappyVertical policy digest"
                )
            if (
                isinstance(selected_generation, bool)
                or not isinstance(selected_generation, int)
                or selected_generation < 1
            ):
                errors.append(
                    f"{label} selected_predecessor generation must be a positive integer"
                )
            elif valid_generation and selected_generation >= generation:
                errors.append(
                    f"{label} selected_predecessor generation must be older than "
                    f"artifact generation {generation}"
                )
            revision = selected.get("policy_revision")
            if not isinstance(revision, str) or not revision:
                errors.append(
                    f"{label} selected_predecessor policy_revision must be non-empty"
                )
            commit = selected.get("source_commit")
            if not isinstance(commit, str) or not GIT_COMMIT_PATTERN.fullmatch(commit):
                errors.append(
                    f"{label} selected_predecessor source_commit must be a lowercase "
                    "40-character Git OID"
                )
            tree = selected.get("source_tree_sha256")
            if not isinstance(tree, str) or not SHA256_PATTERN.fullmatch(tree):
                errors.append(
                    f"{label} selected_predecessor source_tree_sha256 must be a "
                    "lowercase SHA-256"
                )
            if expects_rollout:
                rollout = selected.get("rollout")
                rollout_label = f"{label} selected_predecessor rollout"
                if not isinstance(rollout, dict) or set(rollout) != {
                    "kind", "consumer_migration_repository_ids",
                }:
                    errors.append(
                        f"{rollout_label} must declare exactly kind and "
                        "consumer_migration_repository_ids"
                    )
                else:
                    kind = rollout.get("kind")
                    migrations = rollout.get("consumer_migration_repository_ids")
                    if kind not in {"runtime-only", "bootstrap-substrate"}:
                        errors.append(
                            f"{rollout_label} kind must be runtime-only or "
                            "bootstrap-substrate"
                        )
                    elif (
                        not isinstance(migrations, list)
                        or any(
                            not isinstance(repository_id, str)
                            or not REPOSITORY_NODE_ID_PATTERN.fullmatch(repository_id)
                            for repository_id in migrations
                        )
                        or migrations != sorted(set(migrations))
                    ):
                        errors.append(
                            f"{rollout_label} consumer migration set must be "
                            "sorted repository node IDs"
                        )
                    elif kind == "runtime-only" and migrations:
                        errors.append(
                            f"{rollout_label} runtime-only releases cannot "
                            "declare consumer migrations"
                        )
                    elif kind == "bootstrap-substrate" and not migrations:
                        errors.append(
                            f"{rollout_label} bootstrap-substrate releases "
                            "must declare consumer migrations"
                        )
        gap = value.get("gap_generations")
        if (
            valid_generation
            and isinstance(selected_generation, int)
            and not isinstance(selected_generation, bool)
        ):
            expected_gap = list(range(selected_generation + 1, generation))
            if gap != expected_gap:
                errors.append(
                    f"{label} gap_generations must list every intervening generation "
                    f"{expected_gap}"
                )
        elif not isinstance(gap, list):
            errors.append(f"{label} gap_generations must be an array")
    else:
        errors.append(f"{label} has an unsupported schema")
    components = value.get("components")
    if not isinstance(components, dict) or not components:
        errors.append(f"{label} components must pin at least one authority substrate path")
        return {}, errors
    for path, digest in sorted(components.items()):
        if not isinstance(path, str) or path not in current:
            errors.append(f"{label} pins {path!r}, which is not authority substrate")
        elif not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
            errors.append(f"{label} digest for {path} must be a lowercase SHA-256")
        elif digest == current[path]:
            errors.append(f"{label} pins {path}, which this generation does not change")
    if errors:
        return {}, errors
    return dict(components), []


def selected_stable_binding(
    lock: Any, channels: Any, generation: Any,
) -> tuple[Any, bool]:
    """Return the stable lock a V2 gap pin must match, and whether to bind.

    The binding proves a gap bridge names the stable generation the fleet is
    actually running. A promote transition rewrites the stable lock to this
    artifact's own generation in the very commit that installs it, and the lock
    stays there afterwards, so binding to the tree's lock would demand that the
    artifact pin itself and would strand every generation that ships a bridge.
    Bind instead to the stable the promotion leaves for as long as the protected
    channels still record one — promote and finalize transitions are both
    validated in that window — and stop binding only once no older stable
    remains on record. A recorded predecessor that is malformed still binds, so
    it fails closed exactly like the promotion preflight.
    """
    if (
        not isinstance(lock, dict)
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or lock.get("generation") != generation
    ):
        return lock, True
    promotion = channels.get("promotion") if isinstance(channels, dict) else None
    previous = promotion.get("previous_stable") if isinstance(promotion, dict) else None
    if previous is None:
        return lock, False
    return previous, True


def bound_authority_substrate_predecessor_components(
    value: Any,
    generation: Any,
    current: dict[str, str],
    selected_stable: Any,
    label: str,
    bind: bool = True,
) -> tuple[dict[str, str], list[str]]:
    """Resolve predecessor digests after binding V2 to the live stable lock."""
    components, errors = authority_substrate_predecessor_components(
        value, generation, current, label,
    )
    if errors:
        return {}, errors
    if (
        bind
        and value.get("schema") == AUTHORITY_SUBSTRATE_GAP_PREDECESSOR_SCHEMA
        and value.get("selected_predecessor") != selected_stable
    ):
        return {}, [
            f"{label} selected_predecessor must exactly match the selected stable lock"
        ]
    return components, []


def authority_substrate_matches(
    content: bytes, expected: bytes, pinned: str | None,
) -> bool:
    """Accept one installed authority substrate file for the running artifact.

    The running bytes always match. A pinned path also accepts exactly the
    digest its predecessor published, which is what the authority repository
    still has installed when a candidate that changes substrate prepares.
    """
    return content == expected or (
        pinned is not None and hashlib.sha256(content).hexdigest() == pinned
    )


def parse_marked(body: str, marker: str, schema: str) -> dict[str, Any] | None:
    """Return the first valid marked JSON object without tightening legacy v1."""
    if marker not in body:
        return None
    fragment = body.split(marker, 1)[1]
    start = fragment.find("{")
    if start < 0:
        return None
    try:
        value, _ = json.JSONDecoder().raw_decode(fragment[start:])
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) and value.get("schema") == schema else None


def parse_timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def ordered_release_timestamp(payload: dict[str, Any], proposed: str) -> str:
    """Clamp a local release clock to the server-derived claim authority."""
    proposed_at = parse_timestamp(proposed)
    if proposed_at is None:
        raise ValueError("proposed release timestamp must be RFC 3339")
    authority = [
        value for value in (
            parse_timestamp(payload.get("claimed_at")),
            parse_timestamp(payload.get("heartbeat_at")),
        )
        if value is not None
    ]
    effective = max([proposed_at, *authority])
    return effective.isoformat().replace("+00:00", "Z")


def claim_payload_error(payload: dict[str, Any]) -> str | None:
    """Validate the authority-bearing claim fields used by lifecycle checks."""
    for name in ("runtime", "owner", "session"):
        if not isinstance(payload.get(name), str) or not payload[name]:
            return f"{name} must be a non-empty string"
    for name in ("branch", "worktree"):
        if payload.get(name) is not None and not isinstance(payload.get(name), str):
            return f"{name} must be a string or null"
    claimed = parse_timestamp(payload.get("claimed_at"))
    heartbeat = parse_timestamp(payload.get("heartbeat_at"))
    if claimed is None:
        return "claimed_at must be an RFC 3339 timestamp"
    if heartbeat is None:
        return "heartbeat_at must be an RFC 3339 timestamp"
    if heartbeat < claimed:
        return "heartbeat_at precedes claimed_at"
    if payload.get("lease_seconds") != LEASE_SECONDS:
        return f"lease_seconds must equal {LEASE_SECONDS}"
    if "released_at" in payload:
        released = parse_timestamp(payload.get("released_at"))
        if released is None:
            return "released_at must be an RFC 3339 timestamp"
        if released < claimed:
            return "released_at precedes claimed_at"
    reason = payload.get("release_reason")
    if "release_reason" in payload and reason not in RELEASE_REASONS:
        return "release_reason must be a known lifecycle reason"
    if "release_message" in payload and (
        not isinstance(payload.get("release_message"), str)
        or not payload["release_message"].strip()
    ):
        return "release_message must be a non-empty string"
    heads = payload.get("release_pr_heads")
    if "release_pr_heads" in payload:
        if not isinstance(heads, dict) or not heads:
            return "release_pr_heads must be a non-empty object"
        if reason not in PR_BOUND_RELEASE_REASONS:
            return "release_pr_heads requires a review or blocked release_reason"
        for number, oid in heads.items():
            if not isinstance(number, str) or not re.fullmatch(r"[1-9][0-9]*", number):
                return "release_pr_heads keys must be decimal PR numbers"
            if not isinstance(oid, str) or not GIT_OID_PATTERN.fullmatch(oid):
                return "release_pr_heads values must be lowercase Git object IDs"
    evidence = payload.get("release_evidence_sha256")
    if "release_evidence_sha256" in payload:
        if not isinstance(evidence, str) or not re.fullmatch(r"[0-9a-f]{64}", evidence):
            return "release_evidence_sha256 must be a lowercase SHA-256"
        if reason not in PR_BOUND_RELEASE_REASONS or not isinstance(heads, dict):
            return "release_evidence_sha256 requires a review or blocked PR release"
    if not payload.get("released_at") and any(
        name in payload for name in (
            "release_reason", "release_message", "release_pr_heads",
            "release_evidence_sha256",
        )
    ):
        return "release fields require released_at"
    transition = payload.get("generated_transition")
    if "generated_transition" in payload:
        if not isinstance(transition, dict):
            return "generated_transition must be an object"
        fields = {
            "issue_number", "pr_number", "head_branch", "head_sha", "runtime", "session",
        }
        if set(transition) != fields:
            return "generated_transition has unexpected or missing fields"
        for name in ("issue_number", "pr_number"):
            value = transition.get(name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                return f"generated_transition {name} must be a positive integer"
        for name in ("head_branch", "runtime", "session"):
            if not isinstance(transition.get(name), str) or not transition[name]:
                return f"generated_transition {name} must be a non-empty string"
        if not isinstance(transition.get("head_sha"), str) \
                or not re.fullmatch(r"[0-9a-f]{40}", transition["head_sha"]):
            return "generated_transition head_sha must be a lowercase Git SHA"
    return None


def heartbeat_payload_error(payload: dict[str, Any]) -> str | None:
    """Validate one append-only lease renewal linked to a claim cycle."""
    for name in ("claim_comment_id", "session"):
        if not isinstance(payload.get(name), str) or not payload[name]:
            return f"{name} must be a non-empty string"
    if parse_timestamp(payload.get("heartbeat_at")) is None:
        return "heartbeat_at must be an RFC 3339 timestamp"
    return None


def issue_incarnation(issue: dict[str, Any]) -> str:
    """Return the server-owned token for the issue's current open incarnation."""
    value = issue.get("incarnation")
    if isinstance(value, str) and value:
        return value
    issue_id = issue.get("id")
    if isinstance(issue_id, str) and issue_id:
        return issue_id
    return "legacy-initial"


def apply_issue_timeline(
    issue: dict[str, Any], timeline: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Classify comments from one server-ordered close/reopen timeline."""
    initial = str(issue.get("id") or "")
    if not initial:
        raise ValueError("issue lacks a server-owned initial incarnation")
    incarnation: str | None = initial
    latest_incarnation = initial
    open_state = True
    has_reopened = False
    comments: list[dict[str, Any]] = []
    claim_generations: list[dict[str, Any]] = []
    for position, event in enumerate(timeline):
        kind = event.get("event")
        if kind == "closed":
            open_state = False
            incarnation = None
        elif kind == "reopened":
            token = str(event.get("node_id") or "")
            if not token:
                raise ValueError("latest reopen event lacks a server-owned node id")
            open_state = True
            has_reopened = True
            incarnation = token
            latest_incarnation = token
        elif kind == "commented":
            comments.append({
                **event,
                "_timelinePosition": position,
                "_issueIncarnation": incarnation,
            })
        elif kind == "labeled" \
                and (event.get("label") or {}).get("name") == CLAIM_LABEL \
                and incarnation is not None:
            claim_generations.append({
                "incarnation": incarnation,
                "createdAt": event.get("created_at") or event.get("createdAt"),
                "id": event.get("node_id") or event.get("id"),
                "position": position,
                "actorLogin": (event.get("actor") or {}).get("login"),
                "actorNodeId": (event.get("actor") or {}).get("node_id"),
            })
    expected_open = issue.get("state") == "OPEN"
    if open_state != expected_open:
        raise ValueError(
            "issue state disagrees with its complete server timeline; reread GitHub"
        )
    for comment in comments:
        comment["_issueIncarnationCurrent"] = (
            comment.get("_issueIncarnation") == latest_incarnation
            and comment.get("_issueIncarnation") is not None
        )
    issue["incarnation"] = latest_incarnation
    issue["hasReopened"] = has_reopened
    issue["authorityMetadataComplete"] = True
    current_generations = [
        generation for generation in claim_generations
        if generation["incarnation"] == latest_incarnation
    ]
    issue["claimGeneration"] = current_generations[-1] \
        if current_generations else None
    generation_position = (
        int(issue["claimGeneration"]["position"])
        if isinstance(issue.get("claimGeneration"), dict) else -1
    )
    for comment in comments:
        generations = [
            generation for generation in claim_generations
            if generation["incarnation"] == comment.get("_issueIncarnation")
            and int(generation["position"]) < int(comment.get("_timelinePosition", -1))
        ]
        comment_generation = max(
            generations, key=lambda generation: int(generation["position"]),
        ) if generations else None
        comment["_claimGeneration"] = comment_generation
        comment["_claimGenerationCurrent"] = (
            comment.get("_issueIncarnationCurrent") is True
            and generation_position >= 0
            and isinstance(comment_generation, dict)
            and comment_generation.get("id") == issue["claimGeneration"].get("id")
        )
    return comments


def comment_generation_actor_matches(comment: dict[str, Any]) -> bool:
    """Return whether one comment is authored by its server label actor."""
    generation = comment.get("_claimGeneration")
    if not isinstance(generation, dict):
        return False
    author_node_id = str(comment.get("authorNodeId") or "")
    actor_node_id = str(generation.get("actorNodeId") or "")
    return bool(author_node_id and actor_node_id and author_node_id == actor_node_id)


def authority_comment_trusted(comment: dict[str, Any]) -> bool:
    """Trust repository association or the exact server label-generation actor."""
    association = str(comment.get("authorAssociation", "")).upper()
    return association in TRUSTED_AUTHOR_ASSOCIATIONS \
        or comment_generation_actor_matches(comment)


def release_evidence_payload(
    issue: dict[str, Any],
    pair: tuple[dict[str, Any], dict[str, Any]],
) -> dict[str, Any]:
    """Build the exact logical release authorized by immutable commit statuses."""
    comment, claim = pair
    match = re.fullmatch(
        r"https://github\.com/([^/]+/[^/]+)/issues/([1-9][0-9]*)/?",
        str(issue.get("url") or ""),
    )
    if not match:
        raise ValueError("issue URL cannot identify release-evidence repository")
    payload: dict[str, Any] = {
        "schema": "hv-agent-release:v1",
        "repository": match.group(1),
        "issue_number": match.group(2),
        "issue_node_id": issue.get("id"),
        "claim_comment_id": str(comment.get("id") or ""),
        "claim_comment_database_id": str(
            comment_database_id(comment) or ""
        ),
        "claim_generation_id": (
            issue.get("claimGeneration") or {}
        ).get("id"),
        "owner_node_id": comment.get("authorNodeId"),
        "owner_login": claim.get("owner"),
        "runtime": claim.get("runtime"),
        "session": claim.get("session"),
        "branch": claim.get("branch"),
        "issue_incarnation": comment.get("_issueIncarnation"),
        "release_reason": claim.get("release_reason"),
        "release_message": claim.get("release_message"),
    }
    if claim.get("release_pr_heads") is not None:
        payload["release_pr_heads"] = claim.get("release_pr_heads")
    missing = [
        name for name, value in payload.items()
        if value is None or value == ""
    ]
    if missing:
        raise ValueError(
            "release evidence lacks canonical " + ", ".join(sorted(missing))
        )
    return payload


def release_evidence_context(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "hv-agent/release/" + hashlib.sha256(canonical.encode()).hexdigest()


def release_status_evidence_error(
    issue: dict[str, Any],
    pair: tuple[dict[str, Any], dict[str, Any]],
    pr: dict[str, Any],
) -> str | None:
    """Verify an owner-created immutable status for the exact release and head."""
    comment, claim = pair
    if claim.get("release_reason") not in PR_BOUND_RELEASE_REASONS:
        return None
    if not claim_pair_current(pair):
        return "release evidence belongs to an earlier issue incarnation"
    try:
        payload = release_evidence_payload(issue, pair)
    except ValueError as exc:
        return str(exc)
    context = release_evidence_context(payload)
    digest = context.rsplit("/", 1)[-1]
    if claim.get("release_evidence_sha256") != digest:
        return "claim release_evidence_sha256 does not match the exact release payload"
    expected_head = str(pr.get("headRefOid") or "")
    if not expected_head:
        return "linked pull request lacks an exact head revision"
    expected_url = str(comment.get("html_url") or comment.get("htmlUrl") or "")
    generation = issue.get("claimGeneration")
    generated_at = parse_timestamp(
        generation.get("createdAt") if isinstance(generation, dict) else None
    )
    if generated_at is None:
        return "current issue incarnation lacks an agent: implementation label generation"
    if generation.get("actorNodeId") != payload.get("owner_node_id"):
        return "claim owner does not match the immutable claim-generation actor"
    candidates = []
    for status in pr.get("commitStatuses", []):
        creator = status.get("creator") if isinstance(status, dict) else None
        created_value = (
            status.get("createdAt") or status.get("created_at")
            if isinstance(status, dict) else None
        )
        created = parse_timestamp(created_value)
        if not isinstance(status, dict) \
                or status.get("context") != context \
                or status.get("state") != "success" \
                or not isinstance(creator, dict) \
                or creator.get("node_id") != payload.get("owner_node_id") \
                or status.get("target_url") != expected_url \
                or status.get("sha") not in {None, expected_head} \
                or created is None \
                or created <= generated_at:
            continue
        candidates.append(status)
    if not candidates:
        return (
            f"claim comment {comment.get('id')} {MISSING_RELEASE_EVIDENCE_ERROR} "
            f"for {expected_head} after the latest claim generation"
        )
    return None


def claim_pair_current(
    pair: tuple[dict[str, Any], dict[str, Any]],
) -> bool:
    """Return whether a parsed cycle belongs to the current issue incarnation."""
    comment, _payload = pair
    return comment.get("_issueIncarnationCurrent") is not False \
        and comment.get("_claimGenerationCurrent") is not False


def claim_pair_active(
    pair: tuple[dict[str, Any], dict[str, Any]],
    at: dt.datetime | None = None,
) -> bool:
    return claim_pair_current(pair) and claim_active(pair[1], at)


def legacy_claim_owner_shape(payload: dict[str, Any]) -> bool:
    """Match only the two retired pre-login owner conventions.

    Legacy payloads recorded either the runtime name as owner (codex-style) or
    the Hermes manager email; GitHub logins can never contain "@". ASCII
    case-only runtime-owner differences (owner "Codex", runtime "codex") are
    the same retired convention; casefold() is deliberately not used because
    it also equates length-expanding and compatibility folds (ß/ss,
    Kelvin Kodex/kodex), which are not case variants. Any other owner/author
    mismatch has no legitimate origin and stays fail-closed.
    """
    owner = payload.get("owner")
    runtime = payload.get("runtime")
    if owner == runtime:
        return True
    if isinstance(owner, str) and isinstance(runtime, str) \
            and owner.isascii() and runtime.isascii() \
            and owner.lower() == runtime.lower():
        return True
    return runtime == "hermes" and "@" in str(owner)


def owner_repair_payload_error(payload: dict[str, Any]) -> str | None:
    """Validate one append-only legacy Hermes owner repair request."""
    for name in (
        "claim_comment_id", "session", "legacy_owner", "owner", "branch", "worktree",
    ):
        if not isinstance(payload.get(name), str) or not payload[name]:
            return f"{name} must be a non-empty string"
    if parse_timestamp(payload.get("repaired_at")) is None:
        return "repaired_at must be an RFC 3339 timestamp"
    return None


def claim_active(payload: dict[str, Any], at: dt.datetime | None = None) -> bool:
    if payload.get("released_at") or claim_payload_error(payload):
        return False
    heartbeat = parse_timestamp(payload.get("heartbeat_at"))
    if heartbeat is None:
        return False
    current = at or dt.datetime.now(dt.timezone.utc)
    return heartbeat + dt.timedelta(seconds=LEASE_SECONDS) > current


def claim_expired_unreleased(payload: dict[str, Any], at: dt.datetime | None = None) -> bool:
    if payload.get("released_at") or claim_payload_error(payload):
        return False
    return not claim_active(payload, at)


def label_names(value: dict[str, Any]) -> set[str]:
    labels = value.get("labels", [])
    if isinstance(labels, dict):
        labels = labels.get("nodes", [])
    return {
        str(label.get("name"))
        for label in labels
        if isinstance(label, dict) and label.get("name")
    }


def lifecycle_label_errors(
    issue_number: str,
    issue: dict[str, Any],
    pull_requests: list[tuple[str, dict[str, Any]]],
    *,
    claim_label: str,
    blocked_label: str,
    claim_present: bool,
    blocked: bool,
) -> list[str]:
    """Return deterministic final-state errors for lifecycle authority labels."""
    errors: list[str] = []
    issue_labels = label_names(issue)
    if (claim_label in issue_labels) != claim_present:
        errors.append(
            f"issue #{issue_number} must {'have' if claim_present else 'not have'} "
            f"{claim_label!r}"
        )
    if (blocked_label in issue_labels) != blocked:
        errors.append(
            f"issue #{issue_number} must {'have' if blocked else 'not have'} "
            f"{blocked_label!r}"
        )
    for pr_number, pr_state in pull_requests:
        if (blocked_label in label_names(pr_state)) != blocked:
            errors.append(
                f"PR #{pr_number} must {'have' if blocked else 'not have'} "
                f"{blocked_label!r}"
            )
    return errors


def closing_pull_requests(response: Any) -> list[dict[str, Any]]:
    """Flatten and validate paginated closedByPullRequestsReferences."""
    pages = response if isinstance(response, list) else [response]
    if not pages:
        raise ValueError("closing pull-request query returned no pages")
    results: dict[int, dict[str, Any]] = {}
    for index, page in enumerate(pages):
        if not isinstance(page, dict) or page.get("errors"):
            raise ValueError("closing pull-request query returned GraphQL errors")
        try:
            connection = page["data"]["repository"]["issue"][
                "closedByPullRequestsReferences"
            ]
        except (KeyError, TypeError):
            raise ValueError("closing pull-request query returned malformed issue state")
        nodes = connection.get("nodes") if isinstance(connection, dict) else None
        if not isinstance(nodes, list):
            raise ValueError("closing pull-request query returned malformed nodes")
        page_info = connection.get("pageInfo")
        if not isinstance(page_info, dict) or not isinstance(page_info.get("hasNextPage"), bool):
            raise ValueError("closing pull-request query returned malformed pageInfo")
        has_next = page_info["hasNextPage"]
        if has_next and not isinstance(page_info.get("endCursor"), str):
            raise ValueError("closing pull-request query omitted its next-page cursor")
        if (index < len(pages) - 1) != has_next:
            raise ValueError("closing pull-request query returned incomplete pagination")
        for node in nodes:
            if not isinstance(node, dict) or not isinstance(node.get("number"), int) \
                    or node.get("state") not in {"OPEN", "CLOSED", "MERGED"}:
                raise ValueError("closing pull-request query returned a malformed PR node")
            results[node["number"]] = node
    return [results[number] for number in sorted(results)]


def release_pr_heads(pull_requests: list[dict[str, Any]]) -> dict[str, str]:
    """Return the immutable PR-head snapshot required for a review handoff."""
    heads: dict[str, str] = {}
    for pull_request in pull_requests:
        number = pull_request.get("number")
        oid = pull_request.get("headRefOid")
        if not isinstance(number, int) or not isinstance(oid, str) \
                or not GIT_OID_PATTERN.fullmatch(oid):
            raise ValueError(
                "linked open pull request lacks a valid headRefOid; reread GitHub "
                "state before releasing the claim"
            )
        heads[str(number)] = oid
    return {number: heads[number] for number in sorted(heads, key=int)}


def release_evidence_pull_requests(
    recorded_heads: dict[str, str],
    pull_requests: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Recover every exact recorded PR snapshot, including merged PRs."""
    by_number = {
        str(pull_request.get("number")): pull_request
        for pull_request in pull_requests
        if isinstance(pull_request, dict)
    }
    snapshots: list[dict[str, Any]] = []
    for number, expected_oid in sorted(recorded_heads.items(), key=lambda item: int(item[0])):
        pull_request = by_number.get(number)
        if pull_request is None:
            raise ValueError(
                f"canonical release records PR #{number}, but the complete closing-PR "
                "relation no longer contains it; preserve history and reacquire"
            )
        actual_oid = pull_request.get("headRefOid")
        if actual_oid != expected_oid:
            raise ValueError(
                f"canonical release records PR #{number} head {expected_oid}, not "
                f"{actual_oid or 'a readable head'}; preserve history and reacquire"
            )
        snapshots.append(pull_request)
    if not snapshots:
        raise ValueError("canonical review/blocked release has no recorded PR snapshots")
    return snapshots


def linked_pull_request_repository_errors(
    pull_requests: list[dict[str, Any]], repository: str,
) -> list[str]:
    """Reject cross-repository closing references before they authorize release."""
    errors: list[str] = []
    for pull_request in pull_requests:
        value = pull_request.get("repository")
        actual = value.get("nameWithOwner") if isinstance(value, dict) else None
        if actual != repository:
            errors.append(
                f"closing PR #{pull_request.get('number', '?')} belongs to "
                f"{actual or 'an unknown repository'}, not {repository}; use a same-repository "
                "closing reference before releasing implementation"
            )
    return errors


def open_closing_pull_requests(response: Any) -> list[dict[str, Any]]:
    """Return only open PRs from the authoritative closing relation."""
    return [
        node for node in closing_pull_requests(response)
        if node["state"] == "OPEN"
    ]


def issue_number(issue: dict[str, Any]) -> str:
    number = issue.get("number")
    if number is not None:
        return str(number)
    url = str(issue.get("url", ""))
    return url.rstrip("/").rsplit("/", 1)[-1] or "?"


def comment_database_id(comment: dict[str, Any]) -> int | None:
    """Return GitHub's monotonic REST database id without trusting node-id text."""
    value = comment.get("databaseId")
    if value is None and isinstance(comment.get("id"), int):
        value = comment.get("id")
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value):
        return int(value)
    return None


def claim_comment_server_key(
    pair: tuple[dict[str, Any], dict[str, Any]],
) -> tuple[dt.datetime, int]:
    """Order claim comments by GitHub time and monotonic database identity."""
    comment, _payload = pair
    created = parse_timestamp(comment.get("createdAt"))
    if created is None:
        raise ValueError("claim comment lacks a valid GitHub createdAt timestamp")
    return created, comment_database_id(comment) or -1


def open_claim_conflict_releases(
    records: list[tuple[dict[str, Any], dict[str, Any]]],
    at: dt.datetime | None = None,
) -> list[tuple[dict[str, Any], dict[str, Any], str]]:
    """Choose deterministic stale/duplicate losers without migrating authority."""
    releases: list[tuple[dict[str, Any], dict[str, Any], str]] = [
        (comment, payload, "race-lost")
        for comment, payload in records
        if not claim_pair_current((comment, payload))
        and not payload.get("released_at")
    ]
    current_unreleased = [
        pair for pair in records
        if claim_pair_current(pair) and not pair[1].get("released_at")
    ]
    if current_unreleased:
        # The first server-ordered claim wins the generation even after its
        # lease expires. A later duplicate must never inherit authority merely
        # because it has a later expiry; reconciliation expires the original
        # winner and requires a fresh label generation instead.
        winner = min(current_unreleased, key=claim_comment_server_key)
        releases.extend(
            (comment, payload, "duplicate")
            for comment, payload in current_unreleased
            if (comment, payload) != winner
        )
    return releases


def release_claim_activity_error(
    records: list[tuple[dict[str, Any], dict[str, Any]]],
    selected_comment_id: str,
    at: dt.datetime,
) -> str | None:
    """Require the exact release cycle to be the sole live lease at mutation."""
    selected = [
        pair for pair in records
        if str(pair[0].get("id")) == str(selected_comment_id)
    ]
    if len(selected) != 1:
        return (
            "selected claim cycle is absent or duplicated in canonical issue state; "
            "reread the issue and reacquire before release"
        )
    live = [pair for pair in records if claim_pair_active(pair, at)]
    if selected[0] not in live:
        return (
            "selected claim is no longer active; reconcile expired history, reacquire, "
            "verify, and release a new cycle"
        )
    if len(live) != 1:
        return (
            "selected claim is not the sole active claim; run hv-agent reconcile ISSUE --apply to "
            "preserve the earliest winner and release deterministic losers, then use the "
            "winning cycle or reacquire"
        )
    return None


def claim_comment_records(
    issue: dict[str, Any],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], list[str]]:
    """Parse every marker so malformed authority comments fail closed."""
    number = issue_number(issue)
    records: list[tuple[dict[str, Any], dict[str, Any]]] = []
    errors: list[str] = []
    owner_repairs: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    for repair_comment in issue.get("comments", []):
        if not isinstance(repair_comment, dict):
            continue
        body = str(repair_comment.get("body", ""))
        if OWNER_REPAIR_MARKER not in body:
            continue
        if not authority_comment_trusted(repair_comment):
            continue
        repair = parse_marked(
            body, OWNER_REPAIR_MARKER, "hv-agent-claim-owner-repair:v1",
        )
        if repair is None:
            errors.append(
                f"issue #{number} has a malformed hv-agent-claim-owner-repair:v1 "
                "comment; remove that compatibility record before continuing"
            )
            continue
        repair_error = owner_repair_payload_error(repair)
        if repair_error:
            errors.append(
                f"issue #{number} has an invalid hv-agent-claim-owner-repair:v1 "
                f"comment ({repair_error}); remove it before continuing"
            )
            continue
        if repair_comment.get("lastEditedAt") is not None:
            errors.append(
                f"issue #{number} owner repair was edited after creation; ignore it "
                "and recover the cycle manually"
            )
            continue
        repair_author = str(repair_comment.get("authorLogin", ""))
        if not repair_author or repair.get("owner") != repair_author:
            errors.append(
                f"issue #{number} owner repair author does not match its canonical "
                "GitHub owner; remove it before continuing"
            )
            continue
        if parse_timestamp(repair_comment.get("createdAt")) is None:
            errors.append(
                f"issue #{number} owner repair lacks a valid GitHub createdAt "
                "timestamp; reread server state before continuing"
            )
            continue
        owner_repairs.setdefault(str(repair["claim_comment_id"]), []).append(
            (repair_comment, repair)
        )

    claim_ids: set[str] = set()
    matching_generation_claims = {
        str((comment.get("_claimGeneration") or {}).get("id"))
        for comment in issue.get("comments", [])
        if isinstance(comment, dict)
        and CLAIM_MARKER in str(comment.get("body", ""))
        and comment_generation_actor_matches(comment)
        and str((comment.get("_claimGeneration") or {}).get("id"))
    }
    for comment in issue.get("comments", []):
        if not isinstance(comment, dict):
            continue
        body = str(comment.get("body", ""))
        if CLAIM_MARKER not in body:
            continue
        if not authority_comment_trusted(comment):
            continue
        author = str(comment.get("authorLogin", ""))
        if not author:
            errors.append(
                f"issue #{number} claim comment lacks its trusted GitHub author; "
                "reread the server state before proceeding"
            )
            continue
        comment_id = str(comment.get("id") or "")
        if not comment_id:
            errors.append(
                f"issue #{number} claim comment lacks its canonical GitHub id; "
                "reread server state before proceeding"
            )
            continue
        claim_ids.add(comment_id)
        generation = comment.get("_claimGeneration")
        if issue.get("authorityMetadataComplete") \
                and not comment_generation_actor_matches(comment):
            generation_id = str(
                generation.get("id") if isinstance(generation, dict) else ""
            )
            if comment.get("_claimGenerationCurrent") is True \
                    and generation_id not in matching_generation_claims:
                errors.append(current_generation_actor_mismatch_error(issue))
            # A trusted delayed claim can land after a replacement label. Once
            # that generation has its own actor-matching claim or is
            # superseded, the delayed comment is permanently non-authoritative
            # and must not poison every later recovery generation.
            continue
        payload = parse_marked(body, CLAIM_MARKER, "hv-agent-claim:v1")
        if payload is None:
            errors.append(
                f"issue #{number} has a malformed hv-agent-claim:v1 comment; "
                "repair or release that canonical comment in place and keep the PR ready"
            )
            continue
        payload_error = claim_payload_error(payload)
        if payload_error:
            errors.append(
                f"issue #{number} has an invalid hv-agent-claim:v1 comment ({payload_error}); "
                "repair or release it in place and keep the PR ready"
            )
            continue
        created = parse_timestamp(comment.get("createdAt"))
        if created is None:
            errors.append(
                f"issue #{number} claim comment lacks a valid GitHub createdAt timestamp; "
                "reread the server state before proceeding"
            )
            continue
        repairs = owner_repairs.get(comment_id, [])
        if len(repairs) > 1:
            errors.append(
                f"issue #{number} claim comment {comment_id} has duplicate owner repair "
                "records; remove duplicates before continuing"
            )
            continue
        repair_comment = None
        repair = None
        repair_created = None
        if repairs:
            repair_comment, repair = repairs[0]
            repair_created = parse_timestamp(repair_comment.get("createdAt"))
            same_second_out_of_order = repair_created == created and (
                comment_database_id(repair_comment) is None
                or comment_database_id(comment) is None
                or comment_database_id(repair_comment) <= comment_database_id(comment)
            )
            if payload.get("runtime") != "hermes" \
                    or repair.get("owner") != author \
                    or repair.get("legacy_owner") == author \
                    or repair.get("session") != payload.get("session") \
                    or repair.get("branch") != payload.get("branch") \
                    or repair.get("worktree") != payload.get("worktree") \
                    or repair_created is None \
                    or repair_created < created \
                    or same_second_out_of_order \
                    or repair_created >= created + dt.timedelta(seconds=LEASE_SECONDS):
                errors.append(
                    f"issue #{number} claim comment {comment_id} has an owner repair "
                    "that does not match its exact identity or server lease; remove it "
                    "or recover the cycle manually"
                )
                continue
        if payload.get("owner") != author:
            if repair is not None:
                if repair.get("legacy_owner") != payload.get("owner") \
                        or repair.get("owner") != author:
                    errors.append(
                        f"issue #{number} claim comment {comment_id} has an owner repair "
                        "that does not match its exact legacy identity or server lease; "
                        "recover the cycle manually"
                    )
                    continue
            elif not payload.get("released_at"):
                errors.append(
                    f"issue #{number} claim owner {payload.get('owner')} does not match "
                    f"trusted comment author {author}; use the exact append-only legacy "
                    "Hermes owner repair or release that canonical cycle"
                )
                continue
            elif not legacy_claim_owner_shape(payload):
                errors.append(
                    f"issue #{number} released claim owner {payload.get('owner')} does not "
                    f"match trusted comment author {author} or a retired legacy owner "
                    "convention; recover that canonical cycle manually"
                )
                continue
            # A released legacy-shape mismatch is settled pre-login history:
            # those cycles recorded the runtime name or Hermes manager email as
            # owner, and the release settled under this trusted comment author.
            # Canonicalize to the authenticated author (exactly as the Hermes
            # repair does) so one settled record cannot poison every later
            # claim generation.
            payload["owner"] = author
        if not payload.get("released_at"):
            # GitHub's immutable server timestamp is the effective start of a
            # live claim cycle. Payload timestamps remain request material in
            # the canonical comment, but cannot create a future/past lease.
            effective = str(comment.get("createdAt"))
            payload["claimed_at"] = effective
            payload["heartbeat_at"] = effective
            if comment.get("lastEditedAt") is not None:
                errors.append(edited_active_claim_error(number, comment.get("id")))
                continue
        if "_issueIncarnationCurrent" not in comment:
            # Direct pure-function fixtures without a timeline represent an
            # initial incarnation. Production wrappers always supply the
            # server-owned timeline classification.
            comment["_issueIncarnationCurrent"] = not bool(issue.get("hasReopened"))
        records.append((comment, payload))
    for target_id in sorted(set(owner_repairs) - claim_ids):
        errors.append(
            f"issue #{number} owner repair references missing claim comment {target_id}; "
            "remove that compatibility record before continuing"
        )
    # Heartbeats are append-only so they can never overwrite a release that
    # races the renewal. They extend only the exact still-unreleased claim
    # cycle named by claim_comment_id and authored by its canonical owner.
    by_id = {
        str(comment.get("id")): (comment, payload)
        for comment, payload in records
    }
    for heartbeat_comment in issue.get("comments", []):
        if not isinstance(heartbeat_comment, dict):
            continue
        body = str(heartbeat_comment.get("body", ""))
        if HEARTBEAT_MARKER not in body:
            continue
        if not authority_comment_trusted(heartbeat_comment):
            continue
        heartbeat = parse_marked(body, HEARTBEAT_MARKER, "hv-agent-heartbeat:v1")
        if heartbeat is None:
            errors.append(
                f"issue #{number} has a malformed hv-agent-heartbeat:v1 comment; "
                "ignore or remove that renewal record before continuing"
            )
            continue
        heartbeat_error = heartbeat_payload_error(heartbeat)
        if heartbeat_error:
            errors.append(
                f"issue #{number} has an invalid hv-agent-heartbeat:v1 comment "
                f"({heartbeat_error}); ignore or remove that renewal record before continuing"
            )
            continue
        if heartbeat_comment.get("lastEditedAt") is not None:
            errors.append(
                f"issue #{number} heartbeat was edited after creation; ignore or remove "
                "that renewal record before continuing"
            )
            continue
        target = by_id.get(str(heartbeat.get("claim_comment_id")))
        if target is None:
            errors.append(
                f"issue #{number} heartbeat references a missing canonical claim comment; "
                "reread the issue before continuing"
            )
            continue
        claim_comment, claim = target
        if not claim_pair_current(target):
            # A heartbeat created before or after reopen cannot renew a cycle
            # from an older server-owned issue incarnation.
            continue
        author = str(heartbeat_comment.get("authorLogin", ""))
        if not author or author != claim.get("owner"):
            errors.append(
                f"issue #{number} heartbeat author does not match canonical claim owner; "
                "reread the issue before continuing"
            )
            continue
        if heartbeat.get("session") != claim.get("session"):
            errors.append(
                f"issue #{number} heartbeat session does not match its canonical claim; "
                "reread the issue before continuing"
            )
            continue
        created = parse_timestamp(heartbeat_comment.get("createdAt"))
        claimed = parse_timestamp(claim_comment.get("createdAt"))
        if created is None:
            errors.append(
                f"issue #{number} heartbeat comment lacks a valid GitHub createdAt timestamp; "
                "reread the server state before proceeding"
            )
            continue
        if claimed is None or created < claimed:
            errors.append(
                f"issue #{number} heartbeat precedes its canonical claim; "
                "ignore or remove that renewal record before continuing"
            )
            continue
        current = parse_timestamp(claim.get("heartbeat_at"))
        if claim.get("released_at"):
            continue
        if current is None:
            continue
        if created >= current + dt.timedelta(seconds=LEASE_SECONDS):
            # Keep the append-only request as history, but do not poison later
            # reacquisition or let a delayed request revive expired authority.
            continue
        if created > current:
            # GitHub's immutable server timestamp is the effective renewal.
            # The payload timestamp identifies the request but cannot extend
            # authority across client clock skew or a delayed request.
            claim["heartbeat_at"] = str(heartbeat_comment.get("createdAt"))

    by_created_at: dict[dt.datetime, list[dict[str, Any]]] = {}
    for comment, _payload in records:
        created = parse_timestamp(comment.get("createdAt"))
        if created is not None:
            by_created_at.setdefault(created, []).append(comment)
    for created, comments in by_created_at.items():
        if len(comments) < 2:
            continue
        database_ids = [comment_database_id(comment) for comment in comments]
        if any(value is None for value in database_ids) or len(set(database_ids)) != len(database_ids):
            errors.append(
                f"issue #{number} has same-second claim comments without unique GitHub "
                f"database ids at {created.isoformat()}; reread canonical REST state before "
                "claiming, releasing, or merging"
            )
    return records, errors


def edited_active_claim_error(number: int | str, comment_id: str | None) -> str:
    """Return the stable diagnostic for a claim comment edited after creation.

    Shared between the fail-closed parser (which refuses the cycle) and the
    reconcile containment classifier (which may rotate it as `race-lost`), so
    the exact-string match cannot drift.
    """
    return (
        f"issue #{number} active claim {comment_id} was edited after "
        "creation; release or reconcile it and acquire a fresh generation"
    )


def edited_unreleased_claim_recovery(
    issue: dict[str, Any],
    records: list[tuple[dict[str, Any], dict[str, Any]]],
    errors: list[str],
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Identify edited-but-unreleased claim cycles safe for reconcile rotation.

    An OPEN issue whose ONLY parse errors are exactly the edited-active-claim
    error for trusted, fully-valid, unreleased claim comments (owner matches
    the comment author) may have those cycles settled as terminal non-review
    releases (`race-lost`) by authenticated reconcile, unblocking a fresh
    claim generation. Any other defect keeps ordinary fail-closed behavior.

    The parser drops edited-active pairs from `records` (fail-closed), so this
    re-scans the issue's raw comments for the poisoned cycles named by the
    errors instead of relying on `records`.
    """
    if issue.get("state") != "OPEN" or not issue.get("authorityMetadataComplete"):
        return []
    if not errors:
        return []
    expected_error = edited_active_claim_error(
        issue_number(issue), "<comment-id>",
    )
    prefix, suffix = expected_error.split("<comment-id>", 1)
    poisoned: list[tuple[dict[str, Any], dict[str, Any]]] = []
    error_ids: set[str] = set()
    for error in errors:
        if not error.startswith(prefix) or not error.endswith(suffix):
            return []  # an unrelated defect is present: stay fail-closed
        cid = error[len(prefix):-len(suffix)] if suffix else error[len(prefix):]
        if not cid:
            return []
        error_ids.add(cid)
    comments = issue.get("comments", [])
    if not isinstance(comments, list):
        return []
    for comment in comments:
        if not isinstance(comment, dict):
            continue
        if str(comment.get("id") or "") not in error_ids:
            continue
        if not authority_comment_trusted(comment):
            return []
        if comment.get("lastEditedAt") is None:
            return []
        body = str(comment.get("body") or "")
        if CLAIM_MARKER not in body:
            return []
        payload = parse_marked(body, CLAIM_MARKER, "hv-agent-claim:v1")
        if payload is None or claim_payload_error(payload):
            return []
        if payload.get("released_at"):
            return []  # released claims may carry lastEditedAt; not poisoned
        if str(payload.get("owner") or "") != str(comment.get("authorLogin") or ""):
            return []  # ownership mismatch: not safe to settle
        poisoned.append((comment, payload))
    if not poisoned:
        return []
    if len(poisoned) != len(error_ids):
        return []
    return poisoned


def current_generation_actor_mismatch_error(issue: dict[str, Any]) -> str:
    """Return the stable diagnostic for a delayed claim bound to an orphan generation."""
    return (
        f"issue #{issue_number(issue)} current claim author does not match the immutable "
        "agent: implementation label generation actor; authenticated claim or reconcile "
        "must rotate the orphaned generation"
    )


def orphaned_claim_generation_id(
    issue: dict[str, Any],
    records: list[tuple[dict[str, Any], dict[str, Any]]],
    errors: list[str],
) -> str | None:
    """Identify the one mismatch-only generation safe for authenticated rotation.

    Ordinary readers remain fail-closed. Mutation wrappers may use this narrow
    classification to rotate a label generation whose actor crashed before
    posting its own claim, after a delayed trusted comment was bound to it.
    """
    if issue.get("state") != "OPEN" or not issue.get("authorityMetadataComplete"):
        return None
    generation = issue.get("claimGeneration")
    if not isinstance(generation, dict):
        return None
    generation_id = str(generation.get("id") or "")
    if not generation_id or not str(generation.get("actorNodeId") or ""):
        return None
    if any(claim_pair_current(pair) for pair in records):
        return None
    expected_error = current_generation_actor_mismatch_error(issue)
    if not errors or any(error != expected_error for error in errors):
        return None
    mismatches = [
        comment for comment in issue.get("comments", [])
        if isinstance(comment, dict)
        and CLAIM_MARKER in str(comment.get("body", ""))
        and comment.get("_claimGenerationCurrent") is True
        and authority_comment_trusted(comment)
        and not comment_generation_actor_matches(comment)
    ]
    if len(mismatches) != len(errors):
        return None
    if any(
        isinstance(comment, dict)
        and CLAIM_MARKER in str(comment.get("body", ""))
        and comment.get("_claimGenerationCurrent") is True
        and comment_generation_actor_matches(comment)
        for comment in issue.get("comments", [])
    ):
        return None
    return generation_id

def claim_history_classification(
    issue: dict[str, Any],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], list[str], str | None]:
    """Classify one issue's claim history without raising.

    Returns (records, errors, orphaned_id). A malformed history has non-empty
    errors and no recoverable orphaned generation id; the rest is either healthy
    or recoverable through authenticated generation rotation. The parser itself
    stays fail-closed -- this only surfaces what it already rejects so a broad
    reconcile can contain one malformed issue instead of aborting the sweep.
    """
    records, errors = claim_comment_records(issue)
    orphaned_id = orphaned_claim_generation_id(issue, records, errors)
    return records, errors, orphaned_id


def claim_audit_entries(
    issues: Iterable[dict[str, Any]],
) -> list[tuple[str, str, list[str], list[str]]]:
    """Deterministic, never-raising audit of malformed claim histories.

    Returns one (number, state, errors, claim_comment_ids) entry per issue whose
    history is malformed and not recoverable as an orphaned generation, sorted by
    issue number for stable, repeatable output. Mirrors what a broad reconcile
    contains: every malformed history in one pass, in canonical order.
    """
    entries: list[tuple[str, str, list[str], list[str]]] = []
    for issue in issues:
        _records, errors, orphaned_id = claim_history_classification(issue)
        if not errors or orphaned_id is not None:
            continue
        number = issue_number(issue)
        claim_ids = sorted({
            str(comment.get("id") or "")
            for comment in issue.get("comments", [])
            if isinstance(comment, dict)
            and CLAIM_MARKER in str(comment.get("body", ""))
            and str(comment.get("id") or "")
        })
        entries.append((
            number,
            str(issue.get("state") or "UNKNOWN"),
            list(errors),
            claim_ids,
        ))
    entries.sort(
        key=lambda entry: (int(entry[0]) if str(entry[0]).isdigit() else 0, entry[0]),
    )
    return entries


def legacy_owner_repair_candidate(
    issue: dict[str, Any],
    *,
    actor: str,
    legacy_owner: str,
    session: str,
    branch: str,
    worktree: str,
    at: dt.datetime,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Select one live pre-login Hermes cycle and validate an append-only repair."""
    if not all((actor, legacy_owner, session, branch, worktree)):
        raise ValueError("legacy owner repair requires every identity field")
    if actor == legacy_owner:
        raise ValueError("legacy claim owner already matches the authenticated GitHub login")
    candidates: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for comment in issue.get("comments", []):
        if not isinstance(comment, dict):
            continue
        if not claim_pair_current((comment, {})):
            continue
        if not authority_comment_trusted(comment):
            continue
        if str(comment.get("authorLogin", "")) != actor:
            continue
        if not str(comment.get("id") or ""):
            continue
        payload = parse_marked(
            str(comment.get("body", "")), CLAIM_MARKER, "hv-agent-claim:v1",
        )
        if payload is None or claim_payload_error(payload):
            continue
        if payload.get("runtime") != "hermes" \
                or payload.get("owner") != legacy_owner \
                or payload.get("session") != session \
                or payload.get("branch") != branch \
                or payload.get("worktree") != worktree \
                or payload.get("released_at"):
            continue
        candidates.append((comment, payload))
    if len(candidates) != 1:
        raise ValueError(
            "legacy owner repair requires exactly one unreleased trusted Hermes "
            "claim matching actor, owner, session, branch, and worktree"
        )

    selected_comment, selected_payload = candidates[0]
    repair_payload = {
        "schema": "hv-agent-claim-owner-repair:v1",
        "claim_comment_id": str(selected_comment["id"]),
        "session": session,
        "legacy_owner": legacy_owner,
        "owner": actor,
        "branch": branch,
        "worktree": worktree,
        "repaired_at": at.isoformat().replace("+00:00", "Z"),
    }
    repaired_body = (
        OWNER_REPAIR_MARKER + "\n```json\n"
        + json.dumps(repair_payload, sort_keys=True) + "\n```"
    )
    repaired_issue = {
        **issue,
        "comments": [*issue.get("comments", []), {
            "id": "virtual-owner-repair",
            "createdAt": repair_payload["repaired_at"],
            "authorLogin": actor,
            "authorAssociation": "MEMBER",
            "body": repaired_body,
        }],
    }
    records, errors = claim_comment_records(repaired_issue)
    if errors:
        raise ValueError(
            "legacy owner repair would not produce valid canonical history: "
            + "; ".join(errors)
        )
    selected = [
        pair for pair in records
        if str(pair[0].get("id")) == str(selected_comment.get("id"))
    ]
    live = [pair for pair in records if claim_pair_active(pair, at)]
    if len(selected) != 1 or selected[0] not in live or len(live) != 1:
        raise ValueError(
            "legacy owner repair requires the exact selected cycle to be the sole "
            "unexpired active claim"
        )
    return selected_comment, repair_payload


def released_claim_record_error(
    records: list[tuple[dict[str, Any], dict[str, Any]]],
    comment_id: str,
    expected_reason: str,
    expected_message: str | None = None,
    expected_pr_heads: dict[str, str] | None = None,
) -> str | None:
    """Verify one exact canonical claim cycle reached its intended release."""
    matches = [
        payload for comment, payload in records
        if str(comment.get("id", "")) == comment_id
    ]
    if len(matches) != 1:
        return (
            f"claim comment {comment_id} is missing from trusted canonical history"
            if not matches else
            f"claim comment {comment_id} appears more than once in canonical history"
        )
    payload = matches[0]
    if not payload.get("released_at"):
        return f"claim comment {comment_id} is still live because released_at is missing"
    if payload.get("release_reason") != expected_reason:
        return (
            f"claim comment {comment_id} release_reason is "
            f"{payload.get('release_reason')!r}, expected {expected_reason!r}"
        )
    if expected_message is not None and payload.get("release_message") != expected_message:
        return (
            f"claim comment {comment_id} release_message does not match the "
            "canonical handoff text"
        )
    if expected_pr_heads is not None and payload.get("release_pr_heads") != expected_pr_heads:
        return (
            f"claim comment {comment_id} release_pr_heads does not match the "
            "canonical released revision snapshot"
        )
    return None


def _authoritative_latest(
    records: list[tuple[dict[str, Any], dict[str, Any]]],
) -> dict[str, Any] | None:
    if not records:
        return None
    return max(
        records,
        key=claim_comment_server_key,
    )[1]


def _claim_identity_errors(
    number: str,
    claim: dict[str, Any],
    metadata: dict[str, Any],
    pr: dict[str, Any],
    state: str,
) -> list[str]:
    errors: list[str] = []
    expected_session = str(metadata.get("session", ""))
    if claim.get("session") != expected_session:
        errors.append(
            f"issue #{number} {state} claim belongs to foreign session "
            f"{claim.get('session')}; stop, obtain an explicit handoff or release/reclaim, "
            "and keep the PR ready"
        )
    expected_runtime = str(metadata.get("runtime", ""))
    if claim.get("runtime") != expected_runtime:
        errors.append(
            f"issue #{number} {state} claim runtime {claim.get('runtime')} does not match "
            f"PR run runtime {expected_runtime}; release or reacquire the claim and keep "
            "the PR ready"
        )
    head = str(pr.get("headRefName", ""))
    if not isinstance(claim.get("branch"), str) or not claim.get("branch"):
        errors.append(
            f"issue #{number} {state} claim has no branch identity for PR head {head}; "
            "release or reacquire the claim for this branch and keep the PR ready"
        )
    elif claim.get("branch") != head:
        errors.append(
            f"issue #{number} {state} claim branch {claim.get('branch')} does not match "
            f"PR head {head}; release or reacquire the claim for this branch and keep "
            "the PR ready"
        )
    metadata_transition = metadata.get("generated_transition")
    claim_transition = claim.get("generated_transition")
    if metadata_transition is not None and not isinstance(claim_transition, dict):
        errors.append(
            f"issue #{number} generated transition has no immutable producer claim binding; "
            "recreate the generated transition through its producer"
        )
    elif isinstance(claim_transition, dict):
        expected = {
            "issue_number": int(number),
            "pr_number": pr.get("number"),
            "head_branch": pr.get("headRefName"),
            "head_sha": pr.get("headRefOid"),
            "runtime": metadata.get("runtime"),
            "session": metadata.get("session"),
        }
        for field, value in expected.items():
            if claim_transition.get(field) != value:
                errors.append(
                    f"issue #{number} generated transition claim {field} "
                    f"{claim_transition.get(field)!r} does not match PR identity {value!r}; "
                    "recreate the generated transition through its producer"
                )
        if isinstance(metadata_transition, dict):
            expected_metadata = {
                "pr_number": pr.get("number"),
                "head_branch": pr.get("headRefName"),
                "head_sha": pr.get("headRefOid"),
                "runtime": metadata.get("runtime"),
                "session": metadata.get("session"),
            }
            for field, value in expected_metadata.items():
                if metadata_transition.get(field) != value:
                    errors.append(
                        f"agent PR generated_transition {field} "
                        f"{metadata_transition.get(field)!r} does not match PR identity {value!r}; "
                        "recreate the generated transition through its producer"
                    )
    return errors


def validate_issue_claim_state(
    issue: dict[str, Any],
    metadata: dict[str, Any],
    pr: dict[str, Any],
    *,
    at: dt.datetime | None = None,
    require_released: bool = False,
) -> list[str]:
    number = issue_number(issue)
    errors: list[str] = []
    records, parse_errors = claim_comment_records(issue)
    errors.extend(parse_errors)
    current_records = [pair for pair in records if claim_pair_current(pair)]
    superseded_unreleased = [
        pair for pair in records
        if not claim_pair_current(pair) and not pair[1].get("released_at")
    ]
    labels = label_names(issue)

    if superseded_unreleased:
        errors.append(
            f"issue #{number} has {len(superseded_unreleased)} unreleased claim "
            "cycle(s) outside the current issue/label generation; reconcile them as "
            "race-lost before relying on newer authority"
        )

    if issue.get("state") != "OPEN":
        errors.append(
            f"issue #{number} is {str(issue.get('state') or 'unknown').lower()} and cannot "
            f"authorize PR #{pr.get('number') or 'unknown'}; close or unlink the extra PR, "
            "or reopen the implementation issue and complete a new claim/release cycle"
        )

    if BLOCKED_LABEL in labels:
        errors.append(
            f"issue #{number} is blocked; resolve the blocker, reacquire the claim, and "
            "remove status: blocked before merge while keeping the PR ready"
        )

    if not records:
        if not parse_errors:
            errors.append(
                f"issue #{number} has no hv-agent-claim:v1 history; claim the issue before "
                "implementation and keep the PR ready"
            )
        if CLAIM_LABEL in labels:
            errors.append(
                f"issue #{number} has agent: implementation without a valid claim comment; "
                "reconcile or reacquire the claim and do not toggle draft state"
            )
        return errors

    if not current_records:
        same_incarnation = [
            pair for pair in records
            if pair[0].get("_issueIncarnationCurrent") is not False
        ]
        if issue.get("authorityMetadataComplete") and same_incarnation:
            errors.append(
                f"issue #{number} claim history predates the current server-owned "
                "agent: implementation label generation; reconcile stale state, "
                "reacquire to create a fresh generation, then release that cycle"
            )
        else:
            errors.append(
                f"issue #{number} claim history predates the current server-owned issue "
                "incarnation; acquire and release a new cycle after the latest reopen"
            )
        if CLAIM_LABEL in labels:
            if issue.get("authorityMetadataComplete") and same_incarnation:
                errors.append(
                    f"issue #{number} has agent: implementation without a claim from the "
                    "current label generation; reconcile the stale selector and reacquire "
                    "without toggling draft state"
                )
            else:
                errors.append(
                    f"issue #{number} has agent: implementation without a current-incarnation "
                    "claim; reconcile stale history and reacquire without toggling draft state"
                )
        return errors

    expired = [
        payload for _, payload in current_records
        if claim_expired_unreleased(payload, at)
    ]
    if expired:
        errors.append(
            f"issue #{number} has an expired unreleased claim; run "
            "hv-agent reconcile ISSUE --apply, then reacquire and rerun lifecycle without "
            "toggling draft state"
        )

    live = [
        (comment, payload) for comment, payload in current_records
        if claim_active(payload, at)
    ]
    if len(live) > 1:
        sessions = sorted({str(payload.get("session")) for _, payload in live})
        if len(sessions) > 1:
            errors.append(
                f"issue #{number} has overlapping active claims from sessions "
                f"{', '.join(sessions)}; run hv-agent reconcile ISSUE --apply to release "
                "deterministic losers, preserve the earliest server comment, and keep "
                "the PR ready"
            )
        else:
            errors.append(
                f"issue #{number} has duplicate active claim comments for session "
                f"{sessions[0]}; run hv-agent reconcile ISSUE --apply to release deterministic "
                "losers as duplicate, preserve the earliest server comment, and keep the "
                "PR ready"
            )

    if len(live) == 1:
        claim = live[0][1]
        if CLAIM_LABEL not in labels:
            errors.append(
                f"issue #{number} {LIVE_CLAIM_WITHOUT_LABEL_ERROR}; do not "
                "re-add the label onto the old generation—release or hand off that exact "
                "cycle, then acquire a fresh generation while keeping the PR ready"
            )
        errors.extend(_claim_identity_errors(number, claim, metadata, pr, "active"))
        if require_released:
            errors.append(
                f"issue #{number} still has an active implementation claim while its "
                "merge-required lifecycle check is running; finish and push, release the "
                "exact claim cycle, and rerun lifecycle without toggling draft state"
            )
    elif CLAIM_LABEL in labels:
        errors.append(
            f"issue #{number} {LABEL_WITHOUT_LIVE_CLAIM_ERROR}; "
            "reconcile or reacquire the claim and do not toggle draft state"
        )

    if not live:
        latest_pair = max(current_records, key=claim_comment_server_key)
        latest = latest_pair[1]
        if latest is None:
            errors.append(
                f"issue #{number} has no authoritative implementation claim cycle; "
                "reacquire through hv-agent and keep the PR ready"
            )
            return errors
        errors.extend(_claim_identity_errors(number, latest, metadata, pr, "latest released"))
        reason = (latest or {}).get("release_reason")
        if reason not in RELEASE_REASONS:
            errors.append(
                f"issue #{number} latest implementation release reason is missing or unknown; "
                "reacquire and release a new claim cycle for the current revision"
            )
        elif issue.get("authorityMetadataComplete") \
                and reason in PR_BOUND_RELEASE_REASONS \
                and (evidence_error := release_status_evidence_error(
                    issue, latest_pair, pr,
                )):
            errors.append(
                f"issue #{number} {evidence_error}; the editable claim comment alone "
                "cannot authorize review or merge; reacquire implementation, verify the "
                "current revision, and release a new claim cycle for that revision"
            )
        elif reason == "review":
            number_key = str(pr.get("number", ""))
            current_head = pr.get("headRefOid")
            released_heads = latest.get("release_pr_heads")
            if not isinstance(current_head, str) or not GIT_OID_PATTERN.fullmatch(current_head):
                errors.append(
                    f"issue #{number} cannot verify the current PR head; reread GitHub state "
                    "and rerun lifecycle"
                )
            elif not isinstance(released_heads, dict) or not released_heads.get(number_key):
                errors.append(
                    f"issue #{number} review release does not authorize PR #{number_key}; "
                    "reacquire and release a new claim cycle for the current revision"
                )
            elif released_heads[number_key] != current_head:
                errors.append(
                    f"issue #{number} review release authorizes {released_heads[number_key]}, "
                    f"not current PR head {current_head}; reacquire, verify, and release the "
                    "new revision"
                )
        elif reason == "abandoned":
            errors.append(
                f"issue #{number} latest implementation cycle was abandoned but an open PR "
                "is linked; reacquire implementation or close the PR, keeping any "
                "implementation PR ready"
            )
        elif reason in {"blocked", "expired"}:
            errors.append(
                f"issue #{number} latest implementation cycle ended as {reason}; resolve the "
                "blocker and reacquire the claim before merge while keeping the PR ready"
            )
        elif reason in {"duplicate", "race-lost"}:
            errors.append(
                f"issue #{number} latest implementation cycle ended as {reason} and cannot "
                "authorize an older release; settle the claim race, reacquire, and release a "
                "new cycle for the current revision while keeping the PR ready"
            )
    return errors


def _metadata_issue_identity(value: Any) -> tuple[str | None, str | None]:
    if isinstance(value, int):
        return None, str(value)
    if isinstance(value, str) and value:
        match = re.fullmatch(
            r"https://github\.com/([^/]+/[^/]+)/issues/([1-9][0-9]*)/?", value,
        )
        if match:
            return match.group(1), match.group(2)
        if re.fullmatch(r"[1-9][0-9]*", value):
            return None, value
    return None, None


def agent_run_metadata_errors(metadata: dict[str, Any]) -> list[str]:
    """Return strict authoring errors for an ``hv-agent-run:v1`` PR block.

    ``parse_marked`` intentionally remains a small marker/JSON parser because
    it is shared by older comment formats.  PR lifecycle validation owns this
    schema contract so the local ``check-pr`` preflight and protected workflow
    reject the same malformed run metadata.
    """
    errors: list[str] = []
    fields = {
        "schema", "runtime", "session", "issue", "policy_revision", "status", "validation",
    }
    if set(metadata) not in (fields, fields | {"generated_transition"}):
        errors.append("agent PR hv-agent-run:v1 has unexpected or missing fields")
    if metadata.get("schema") != "hv-agent-run:v1":
        errors.append("agent PR hv-agent-run:v1 schema must be hv-agent-run:v1")
    for name in ("runtime", "session", "policy_revision"):
        if not isinstance(metadata.get(name), str) or not metadata[name]:
            errors.append(f"agent PR hv-agent-run:v1 {name} must be a non-empty string")
    issue = metadata.get("issue")
    if not isinstance(issue, int) or isinstance(issue, bool) or issue < 1:
        errors.append("agent PR hv-agent-run:v1 issue must be a positive integer")
    if metadata.get("status") != "complete":
        errors.append("agent PR hv-agent-run:v1 status must be complete")
    validation = metadata.get("validation")
    if not isinstance(validation, list) or not validation or any(
            not isinstance(check, str) or not check for check in validation):
        errors.append(
            "agent PR hv-agent-run:v1 validation must be a non-empty array of non-empty strings"
        )
    transition = metadata.get("generated_transition")
    if "generated_transition" in metadata:
        if not isinstance(transition, dict):
            errors.append("agent PR generated_transition must be an object")
        else:
            fields = {"pr_number", "head_branch", "head_sha", "runtime", "session"}
            if set(transition) != fields:
                errors.append("agent PR generated_transition has unexpected or missing fields")
            for name in ("pr_number",):
                value = transition.get(name)
                if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                    errors.append(
                        f"agent PR generated_transition {name} must be a positive integer"
                    )
            for name in ("head_branch", "runtime", "session"):
                if not isinstance(transition.get(name), str) or not transition[name]:
                    errors.append(
                        f"agent PR generated_transition {name} must be a non-empty string"
                    )
            if not isinstance(transition.get("head_sha"), str) \
                    or not re.fullmatch(r"[0-9a-f]{40}", transition["head_sha"]):
                errors.append(
                    "agent PR generated_transition head_sha must be a lowercase Git SHA"
                )
    return errors


def closing_issue_reference_errors(pr: dict[str, Any], repository: str) -> list[str]:
    """Require every closing issue reference to remain in the PR repository."""
    errors: list[str] = []
    for issue in pr.get("closingIssuesReferences", []):
        value = issue.get("repository") if isinstance(issue, dict) else None
        actual = None
        if isinstance(value, dict):
            actual = value.get("nameWithOwner")
            if actual is None and value.get("name") and isinstance(value.get("owner"), dict):
                actual = f"{value['owner'].get('login')}/{value['name']}"
        if actual != repository:
            errors.append(
                f"closing issue #{issue_number(issue)} belongs to "
                f"{actual or 'an unknown repository'}, not {repository}; move the canonical "
                "implementation issue or use a same-repository closing reference"
            )
    return errors


# GitHub scans commit messages landing on the default branch for closing
# keywords, separately from the PR body's linked-issues parse, and neither scan
# is sentence-aware. `close #12` closes #12 whether or not the words in front of
# it are "this does not". The keyword set is exactly GitHub's; note that
# `closing`/`fixing`/`resolving` are absent, which is why the behaviour reads as
# arbitrary and cannot be left to an author to remember.
CLOSING_KEYWORD_REFERENCE = re.compile(
    r"\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b[\s:]+"
    r"(?:(?P<repository>[A-Za-z0-9._-]+/[A-Za-z0-9._-]+)?#|GH-)"
    r"(?P<number>[1-9][0-9]*)\b",
    re.IGNORECASE,
)
# A PR body is rendered as Markdown, and GitHub does not autolink — so does not
# close — a reference inside a code span or fenced block. Block quotes are
# deliberately still scanned: GitHub does resolve references there, so quoting
# someone else's closing line really can close that issue.
#
# A commit message is not Markdown. Its closing scan runs over the raw text, so
# backticks there protect nothing and stripping them here would be a false
# negative on the one source that actually caused the incident.
_FENCED_CODE = re.compile(r"^\s*(`{3,}|~{3,}).*?(?:^\s*\1\s*$|\Z)", re.M | re.S)
_INLINE_CODE = re.compile(r"`[^`\n]*`")


def closing_keyword_references(
    text: str, repository: str, *, markdown: bool = True,
) -> set[str]:
    """Return issue references a GitHub closing-keyword scan would act on."""
    if not isinstance(text, str) or not text:
        return set()
    scanned = _INLINE_CODE.sub(" ", _FENCED_CODE.sub("\n", text)) if markdown else text
    references: set[str] = set()
    for match in CLOSING_KEYWORD_REFERENCE.finditer(scanned):
        owner = match.group("repository")
        number = match.group("number")
        references.add(
            f"#{number}" if owner in (None, repository) else f"{owner}#{number}"
        )
    return references


def undeclared_closing_reference_errors(
    pr: dict[str, Any],
    commits: list[dict[str, Any]],
    repository: str,
    *,
    check_commit_references: bool = True,
) -> list[str]:
    """Reject closing-keyword references the PR does not declare it closes.

    The PR body's declared set is `closingIssuesReferences`, which GitHub
    computes from the body alone. A commit message that lands on the default
    branch gets its own closing scan that never appears there, so an issue can
    close on merge without the PR ever declaring it — and a sentence written to
    *disclaim* a closure is indistinguishable from one that intends it.

    Known limitation, stated rather than papered over: this reads the PR body
    and the branch's commit messages. It cannot read a squash message composed
    in the merge dialog, because that text does not exist until merge. It would
    still have caught the incident that prompted the guard, whose message came
    from the branch.
    """
    declared = {f"#{issue_number(issue)}" for issue in pr.get("closingIssuesReferences", [])}
    sources: list[tuple[str, str, bool]] = [
        ("the PR body", str(pr.get("body") or ""), True),
    ]
    if check_commit_references:
        for commit in commits:
            if not isinstance(commit, dict):
                continue
            oid = str(commit.get("sha") or commit.get("oid") or "")
            message = commit.get("message")
            if message is None and isinstance(commit.get("commit"), dict):
                message = commit["commit"].get("message")
            sources.append((f"commit {oid[:7] or 'unknown'}", str(message or ""), False))

    errors: list[str] = []
    for origin, text, markdown in sources:
        extras = sorted(
            closing_keyword_references(text, repository, markdown=markdown) - declared,
            key=lambda reference: (reference.count("#") > 1, reference),
        )
        for reference in extras:
            errors.append(
                f"{origin} places a closing keyword directly before {reference}, which "
                f"GitHub closes on merge, but the PR does not declare it closes "
                f"{reference}. If that is intended, declare it in the PR body; if it is "
                "not — a negation reads the same to GitHub's parser — use a form with no "
                f"keyword in front of the reference, such as `Refs {reference}`, "
                f"`Parent: {reference}`, or `{reference} stays open`"
            )
    return errors


_CHECK_RUN_DETAILS_URL = re.compile(
    r"https://github\.com/(?P<repository>[^/]+/[^/]+)/actions/runs/(?P<run>[1-9][0-9]*)"
    r"(?:/job/[1-9][0-9]*)?"
)


def _workflow_run_identity(run: dict[str, Any]) -> tuple[str, int] | None:
    """Return the (repository, workflow run id) backing one check run, or None.

    Rerunning a workflow run keeps its id and issues a fresh check run under a
    new job id, so this identity is what links a failure to the rerun that
    replaced it.
    """
    match = _CHECK_RUN_DETAILS_URL.fullmatch(str(run.get("details_url") or ""))
    if match is None:
        return None
    return match.group("repository"), int(match.group("run"))


def _succeeded(run: dict[str, Any]) -> bool:
    return run.get("status") == "completed" and run.get("conclusion") == "success"


# `cancelled` and `timed_out` hold a required context exactly as `failure` does.
# `neutral`, `skipped`, and `action_required` do not, and rerunning them would
# only churn.
BLOCKING_CHECK_RUN_CONCLUSIONS = {"failure", "timed_out", "cancelled"}


def _check_run_ordering(run: dict[str, Any]) -> tuple[str, int]:
    started = run.get("started_at") or run.get("completed_at") or ""
    identifier = run.get("id")
    return str(started), identifier if isinstance(identifier, int) else 0


def _check_runs_by_context(
    check_runs: list[dict[str, Any]],
    contexts: Collection[str],
) -> dict[str, list[dict[str, Any]]]:
    """Group check runs of the named contexts, oldest first within each name."""
    by_name: dict[str, list[dict[str, Any]]] = {}
    for run in check_runs:
        if not isinstance(run, dict):
            continue
        name = run.get("name")
        if isinstance(name, str) and name in contexts:
            by_name.setdefault(name, []).append(run)
    return {
        name: sorted(runs, key=_check_run_ordering)
        for name, runs in by_name.items()
    }


# A required context resolves to its newest run, but a superseded failure from
# an earlier run of the same context can still hold `mergeStateStatus` at
# BLOCKED. `gh pr checks` deduplicates by name and hides it, so the PR looks
# green in the one view an agent is likely to consult while merge stays blocked
# for an unexplained reason.
def superseded_failed_check_runs(
    check_runs: list[dict[str, Any]],
    required_contexts: set[str],
) -> list[dict[str, Any]]:
    """Return superseded failures of a required context that still need a rerun.

    Rerunning a workflow run appends a new check run instead of updating the
    failed record, so the original failure stays on the commit forever. A guard
    that only asked whether the newest run of the context is green therefore
    re-reported the same historical failure on every call, long after the rerun
    it asked for had already cleared the block (#293) — and a guard on the ship
    path that always reports something is a guard agents learn to skip.

    The rerun is identifiable: it carries the failed run's own workflow run id.
    So a failure needs action only while no later check run of that same
    workflow run has succeeded. A success from a *different* workflow run of the
    context is the superseding run itself — it is what makes the failure stale
    without clearing it, which is the case worth reporting.
    """
    by_name = _check_runs_by_context(check_runs, required_contexts)
    stale: list[dict[str, Any]] = []
    for name in sorted(by_name):
        runs = by_name[name]
        newest = runs[-1]
        if not _succeeded(newest):
            # The newest run is the authoritative one. If it is failing or still
            # running, that is a real result and rerunning an older run would
            # only hide it.
            continue
        for position, run in enumerate(runs[:-1]):
            if run.get("status") != "completed":
                continue
            if run.get("conclusion") not in BLOCKING_CHECK_RUN_CONCLUSIONS:
                continue
            identity = _workflow_run_identity(run)
            if identity is not None and any(
                _succeeded(later) and _workflow_run_identity(later) == identity
                for later in runs[position + 1:]
            ):
                # This exact workflow run was already rerun and the rerun
                # passed. The failed record persists because GitHub never
                # rewrites it, but nothing is left to do.
                continue
            # An unparseable details_url leaves the rerun unknowable, and
            # cmd_rerun_superseded already reports that case for a human. Report
            # rather than assume it was handled.
            stale.append(run)
    return stale


# The kernel orders a cycle finish → push → open the PR → release, because the
# release records owner-attributed evidence against the exact PR head and so
# cannot precede that head existing. Every one of those pushes fires the
# lifecycle check, which then evaluates a claim the release has not settled yet
# and fails closed — correctly, on the state it can see, but on state that is
# already obsolete by the time the annotation lands. That made a first-run red
# `lifecycle` the norm on agent PRs and a manual rerun the standing remedy,
# which is exactly how a check stops being read (#380).
#
# The release itself is the moment the data becomes authoritative, so it is the
# release that re-evaluates. Rerunning the check never launders anything: the
# rerun re-derives its verdict from current canonical state, so a genuine
# violation simply fails again.
def lifecycle_recheck_targets(
    check_runs: list[dict[str, Any]],
    contexts: Collection[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split lifecycle check runs on a released head into (stale, pending).

    `stale` is the newest run of a context when it is a completed blocking
    conclusion: that verdict predates the settled release and needs one rerun.
    `pending` is every run of a context that has not completed, because its
    verdict is still being formed against pre-release state and the caller must
    wait for it before deciding.

    A context whose newest run already succeeded is settled. An older failure
    under a green newest run is the separate superseded-failure case that
    `superseded_failed_check_runs` owns; re-reporting it here would duplicate a
    remedy the ship path already applies.
    """
    by_name = _check_runs_by_context(check_runs, contexts)
    stale: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    for name in sorted(by_name):
        runs = by_name[name]
        incomplete = [run for run in runs if run.get("status") != "completed"]
        if incomplete:
            pending.extend(incomplete)
            continue
        newest = runs[-1]
        if newest.get("conclusion") in BLOCKING_CHECK_RUN_CONCLUSIONS:
            stale.append(newest)
    return stale, pending


def release_settlement_pending(
    issue: dict[str, Any],
    metadata: dict[str, Any],
    pr: dict[str, Any],
    errors: list[str],
    *,
    at: dt.datetime | None = None,
) -> str | None:
    """Explain a rejection that is an unsettled release rather than a violation.

    `hv-agent release` is a sequence of GitHub writes — the immutable evidence
    status, then `released_at` and its digest on the claim comment, then the
    derived label and Project state — and the lifecycle check evaluates whatever
    snapshot it happens to read. Each intermediate snapshot is genuinely
    unauthorized and stays rejected here; what differs is the remedy. "The
    release for this exact head has not finished" wants the release to finish,
    not the reacquire-and-verify cycle every one of those messages prescribes.

    This is advisory only: it never removes an error. It explains only the
    rejections a release actually passes through, and only for a single current
    claim that already matches this PR's session, runtime, and branch while
    unreleased or released against this PR's exact current head. A foreign
    session, an expired claim, a release bound to a superseded head, or a
    rejection an unfinished release cannot cause — a draft PR, a blocked label,
    bad run metadata — is a real violation and returns None.
    """
    if issue.get("state") != "OPEN" or BLOCKED_LABEL in label_names(issue):
        return None
    number = issue_number(issue)
    prefix = f"issue #{number} "
    if not any(
        error.startswith(prefix) and fragment in error
        for error in errors
        for fragment in RELEASE_SETTLEMENT_ERRORS
    ):
        return None
    records, parse_errors = claim_comment_records(issue)
    if parse_errors:
        return None
    current = [pair for pair in records if claim_pair_current(pair)]
    if len(current) != 1 or any(
        not claim_pair_current(pair) and not pair[1].get("released_at")
        for pair in records
    ):
        # An unreleased cycle outside the current generation is drift that
        # reconciliation owns, not a write still in flight.
        return None
    _comment, claim = current[0]
    if _claim_identity_errors(number, claim, metadata, pr, "active"):
        return None
    if not claim.get("released_at"):
        if not claim_active(claim, at):
            return None
        return (
            f"issue #{number} still holds this session's live claim for this PR head; "
            "the release runs after the head exists, so this result predates it — "
            "no reacquisition is needed, complete `hv-agent release` and rerun this check"
        )
    if claim.get("release_reason") not in PR_BOUND_RELEASE_REASONS:
        return None
    heads = claim.get("release_pr_heads")
    head = str(pr.get("headRefOid") or "")
    if not isinstance(heads, dict) or not head \
            or heads.get(str(pr.get("number", ""))) != head:
        return None
    return (
        f"issue #{number} is released against this exact PR head; the remaining "
        "derived state — evidence status, implementation label, Project status — "
        "settles after that write, so this result predates it — no reacquisition is "
        "needed, let `hv-agent release` finish and rerun this check"
    )


# GitHub renders at most 10 annotations per step.
MAX_WORKFLOW_ANNOTATIONS = 10


def lifecycle_annotations(
    errors: list[str],
    notes: list[str],
    *,
    github_actions: bool,
) -> list[str]:
    """Render workflow annotations for a rejected revision, most useful first.

    Without them the only annotation an agent PR carries is `Process completed
    with exit code 1`, which reads identically for a foreign-session violation
    and for a release that has not finished settling. That
    indistinguishability is what taught everyone to rerun `lifecycle` on sight
    and, on happyvertical/smrt#2215, hid a real violation behind the expected
    one (#380).
    """
    if not github_actions or not errors:
        return []
    lines = [
        f"::notice title=lifecycle release settling::{_annotation_text(note)}"
        for note in notes[:MAX_WORKFLOW_ANNOTATIONS]
    ]
    remaining = MAX_WORKFLOW_ANNOTATIONS - len(lines)
    lines.extend(
        f"::error title=lifecycle rejected this revision::{_annotation_text(error)}"
        for error in errors[:remaining]
    )
    return lines


def _annotation_text(message: str) -> str:
    """Escape a message for a workflow command's single-line payload."""
    return (
        message.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


def check_run_workflow_run_id(run: dict[str, Any], repository: str) -> int | None:
    """Extract the workflow run id backing one check run, or None."""
    identity = check_run_workflow_run_identity(run)
    if identity is None or identity[0] != repository:
        return None
    return identity[1]


def check_run_workflow_run_identity(run: dict[str, Any]) -> tuple[str, int] | None:
    """Return the repository and workflow-run id named by a check's details URL.

    A ruleset-required workflow can be hosted in the central authority
    repository while publishing its check on a consumer PR. Callers use this
    identity to target GitHub's run-rerun REST endpoint at the repository that
    owns the execution, rather than assuming the consumer owns it.
    """
    return _workflow_run_identity(run)


def validate_agent_pr(
    pr: dict[str, Any],
    metadata: dict[str, Any],
    linked_issues: list[dict[str, Any]],
    policy_revision: str,
    *,
    at: dt.datetime | None = None,
    merge_group: bool = False,
    require_released: bool = False,
    repository: str | None = None,
) -> list[str]:
    """Validate one agent PR snapshot for every PR and dispatch event.

    Queue-protected repositories supply ``merge_group``.  A private
    Team-plan repository instead supplies ``require_released`` from its local
    compatibility workflow, which makes its strict local status check require
    the same exact-head review release without pretending that GitHub created
    a merge-group commit.
    """
    errors: list[str] = []
    errors.extend(agent_run_metadata_errors(metadata))
    if BLOCKED_LABEL in label_names(pr):
        errors.append(
            "PR has status: blocked; resolve the blocker, reacquire implementation, and "
            "remove the label before merge while keeping the PR ready"
        )
    if pr.get("isDraft"):
        errors.append(
            "agent-authored PR is draft; mark it ready for review and keep it ready during "
            "claimed implementation or review fixes"
        )
    if metadata.get("policy_revision") != policy_revision:
        errors.append(
            f"agent PR policy revision {metadata.get('policy_revision')} does not match "
            f"runtime revision {policy_revision}; refresh generated policy metadata"
        )
    if not linked_issues:
        errors.append("agent-authored PR has no closing issue reference")
        return errors

    linked_numbers = {issue_number(issue) for issue in linked_issues}
    metadata_repository, metadata_number = _metadata_issue_identity(metadata.get("issue"))
    if metadata_number is None:
        errors.append("agent PR hv-agent-run:v1 issue must identify a closing issue")
    elif metadata_number not in linked_numbers:
        errors.append(
            f"agent PR hv-agent-run:v1 issue #{metadata_number} is not a closing issue "
            f"({', '.join(sorted(linked_numbers))})"
        )
    if repository and metadata_repository not in {None, repository}:
        errors.append(
            f"agent PR hv-agent-run:v1 issue belongs to {metadata_repository}, not "
            f"{repository}; use the same-repository canonical issue"
        )

    for issue in linked_issues:
        errors.extend(validate_issue_claim_state(
            issue,
            metadata,
            pr,
            at=at,
            require_released=merge_group or require_released,
        ))
    return errors
