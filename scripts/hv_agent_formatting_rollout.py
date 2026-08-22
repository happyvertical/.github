#!/usr/bin/env python3
"""Deterministic consumer rendering for agent-formatting:v1 integrations."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import hv_agent_formatting as formatting
import hv_agent_lifecycle as lifecycle


CONTRACT_PATH = Path(".agents/formatting.json")
WORKFLOW_PATH = Path(".github/workflows/formatting.yml")
HOOK_PATH = Path(".agents/hooks/pre-commit-format")
LEFTHOOK_EXTENSION_PATH = Path(".agents/lefthook-formatting.yml")
RUNTIME_PATHS = (
    Path("scripts/hv-agent-format"),
    Path("scripts/hv_agent_formatting.py"),
    Path("schemas/agent-formatting.schema.json"),
)
WORKFLOW_MARKER = b"hv-agent-formatting-workflow:v1"
HOOK_MARKER = b"hv-agent-formatting-hook:v1"
LEFTHOOK_MARKER = b"hv-agent-formatting-lefthook:v1"
RUNTIME_MARKER = b"hv-agent-formatting-runtime:v1"
MODULE_MARKER = b"hv-agent-formatting-module:v1"
SCHEMA_MARKER = b"hv-agent-formatting-schema:v1"
PROVISION_START = b"hv-agent-formatting-provision:start"
PROVISION_END = b"hv-agent-formatting-provision:end"
EXTEND_START_MARKER = b"hv-agent-formatting-extend:start"
EXTEND_END_MARKER = b"hv-agent-formatting-extend:end"
EXTEND_START = "# hv-agent-formatting-extend:start"
EXTEND_END = "# hv-agent-formatting-extend:end"
FORMAT_CHECK_CONTEXTS = {"formatting", "Verify repository formatting"}
FILE_MARKERS = {
    WORKFLOW_PATH: WORKFLOW_MARKER,
    HOOK_PATH: HOOK_MARKER,
    LEFTHOOK_EXTENSION_PATH: LEFTHOOK_MARKER,
    Path("scripts/hv-agent-format"): RUNTIME_MARKER,
    Path("scripts/hv_agent_formatting.py"): MODULE_MARKER,
    Path("schemas/agent-formatting.schema.json"): SCHEMA_MARKER,
}
ACTIVE_MARKER_OWNERS = {
    **{marker: path for path, marker in FILE_MARKERS.items()},
    PROVISION_START: WORKFLOW_PATH,
    PROVISION_END: WORKFLOW_PATH,
    EXTEND_START_MARKER: Path("lefthook.yml"),
    EXTEND_END_MARKER: Path("lefthook.yml"),
}
CONTROL_PLANE_MARKER_OWNERS = {
    WORKFLOW_MARKER: Path("templates/github/formatting.yml"),
    PROVISION_START: Path("templates/github/formatting.yml"),
    PROVISION_END: Path("templates/github/formatting.yml"),
    HOOK_MARKER: Path("templates/hooks/pre-commit-format"),
    LEFTHOOK_MARKER: Path("templates/hooks/lefthook-formatting.yml"),
    RUNTIME_MARKER: Path("scripts/hv-agent-format"),
    MODULE_MARKER: Path("scripts/hv_agent_formatting.py"),
    SCHEMA_MARKER: Path("schemas/agent-formatting.schema.json"),
}


class RolloutError(RuntimeError):
    pass


@dataclass(frozen=True)
class RenderedFile:
    content: bytes
    executable: bool = False


@dataclass(frozen=True)
class MappingEntry:
    line: int
    indent: int
    key: str
    remainder: str


def _yaml_document_marker(line: str) -> str | None:
    match = re.fullmatch(r"(---|\.\.\.)(?:[ \t]+#.*)?[ \t]*", line)
    return match.group(1) if match else None


def _forge_repository(manifest: dict[str, Any]) -> str:
    """
    Formatting hooks, workflows, and CI checks live with the code, so their
    identity follows the forge. A pre-split manifest has no `forge` block and
    lets `tracker.repository` serve both roles, which the shared resolver
    already handles.
    """
    try:
        return lifecycle.forge_repository(manifest)
    except ValueError as exc:
        raise RolloutError(str(exc)) from exc


def _load(repo: Path) -> tuple[dict[str, Any], dict[str, Any]] | None:
    current = repo
    for part in CONTRACT_PATH.parts[:-1]:
        current /= part
        if current.is_symlink():
            raise RolloutError(f"formatting contract parent must not be a symlink: {current}")
        if current.exists() and not current.is_dir():
            raise RolloutError(f"formatting contract parent is not a directory: {current}")
    location = repo / CONTRACT_PATH
    if location.is_symlink():
        raise RolloutError(f"formatting contract must not be a symlink: {location}")
    if not location.is_file():
        if not location.exists():
            return None
        raise RolloutError(f"formatting contract is not a regular file: {location}")
    try:
        contract, _relative = formatting.load_contract(repo)
    except formatting.FormattingError as exc:
        raise RolloutError(str(exc)) from exc
    integrations = contract.get("integrations")
    if integrations is None:
        return None
    if not isinstance(integrations, dict):
        raise RolloutError("formatting integrations must be an object")
    try:
        formatting.validate_contract(repo)
    except formatting.FormattingError as exc:
        raise RolloutError(str(exc)) from exc
    return contract, integrations


def _safe_destination(repo: Path, relative: Path) -> Path:
    if relative.is_absolute() or relative == Path(".") or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        raise RolloutError(f"unsafe generated formatting path: {relative}")
    destination = repo / relative
    current = repo
    for part in relative.parts[:-1]:
        current /= part
        if current.is_symlink():
            raise RolloutError(f"generated formatting parent must not be a symlink: {current}")
        if current.exists() and not current.is_dir():
            raise RolloutError(f"generated formatting parent is not a directory: {current}")
    if destination.is_symlink() or destination.exists() and not destination.is_file():
        raise RolloutError(f"generated formatting destination is not a regular file: {destination}")
    return destination


def _repository_files(repo: Path) -> set[Path]:
    completed = subprocess.run(
        [
            formatting.GIT,
            "-C",
            os.fspath(repo),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        check=False,
        capture_output=True,
        env=formatting.internal_git_environment(),
    )
    if completed.returncode:
        message = completed.stderr.decode(errors="replace").strip()
        raise RolloutError(f"unable to enumerate repository files: {message}")
    result: set[Path] = set()
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        relative = Path(os.fsdecode(raw))
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise RolloutError(f"Git returned an unsafe repository path: {relative}")
        result.add(relative)
    return result


def _marker_placement_errors(
    repo: Path,
    active: bool,
    source_repository: bool,
) -> list[str]:
    owners = ACTIVE_MARKER_OWNERS if active else (
        CONTROL_PLANE_MARKER_OWNERS
        if source_repository
        else {}
    )
    candidates = _repository_files(repo)
    candidates.update(path for path in set(owners.values()) if (repo / path).exists())
    errors: list[str] = []
    for relative in sorted(candidates):
        if not active and source_repository \
                and relative == Path("scripts/hv_agent_formatting_rollout.py"):
            continue
        path = repo / relative
        if path.is_symlink():
            if relative in set(ACTIVE_MARKER_OWNERS.values()):
                errors.append(f"{path}: generated formatting path must not be a symlink")
            continue
        if not path.is_file():
            continue
        try:
            content = path.read_bytes()
        except OSError as exc:
            errors.append(str(exc))
            continue
        for marker in set(ACTIVE_MARKER_OWNERS) | set(CONTROL_PLANE_MARKER_OWNERS):
            count = content.count(marker)
            if not count:
                continue
            expected = owners.get(marker)
            if expected != relative:
                state = "duplicate or misplaced" if active else "orphaned"
                errors.append(
                    f"{path}: {state} generated formatting marker "
                    f"{marker.decode()}; expected {repo / expected if expected else 'no marker'}"
                )
            elif count != 1:
                errors.append(
                    f"{path}: generated formatting marker {marker.decode()} must occur exactly once"
                )
    return errors


def _atomic_write(destination: Path, rendered: RenderedFile) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.hv-agent-",
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o755 if rendered.executable else 0o644)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(rendered.content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _required_check_errors(manifest: dict[str, Any]) -> list[str]:
    github = manifest.get("github", {})
    checks = github.get("required_status_checks", []) if isinstance(github, dict) else []
    if not isinstance(checks, list):
        return ["github.required_status_checks must be an array"]
    conflicts = sorted(FORMAT_CHECK_CONTEXTS.intersection(str(check) for check in checks))
    if conflicts:
        return [
            "report-mode formatting must not be required; remove from "
            f"github.required_status_checks: {', '.join(conflicts)}"
        ]
    return []


def _mapping_entry(line: str, line_number: int) -> MappingEntry | None:
    indentation = len(line) - len(line.lstrip(" "))
    if "\t" in line[:len(line) - len(line.lstrip())]:
        raise RolloutError(f"lefthook line {line_number}: tab indentation is unsupported")
    stripped = line[indentation:]
    if (
        not stripped
        or stripped.startswith(("#", "- "))
        or _yaml_document_marker(stripped) is not None
    ):
        return None
    quote: str | None = None
    escaped = False
    separator = -1
    for index, character in enumerate(stripped):
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if quote == "'":
            if character == quote:
                if index + 1 < len(stripped) and stripped[index + 1] == quote:
                    continue
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
        elif character == ":":
            separator = index
            break
    if separator < 0:
        if indentation == 0 and stripped.startswith(("{", "?")):
            raise RolloutError(
                f"lefthook line {line_number}: flow or explicit top-level mappings are unsupported"
            )
        return None
    token = stripped[:separator].strip()
    try:
        if token.startswith('"'):
            key = json.loads(token)
            if not isinstance(key, str):
                raise ValueError("mapping key is not a string")
        elif token.startswith("'"):
            if len(token) < 2 or not token.endswith("'"):
                raise ValueError("unterminated single-quoted mapping key")
            key = token[1:-1].replace("''", "'")
        elif re.fullmatch(r"[A-Za-z0-9_.-]+|<<", token):
            key = token
        else:
            raise ValueError("unsupported mapping key syntax")
    except (json.JSONDecodeError, ValueError) as exc:
        if indentation == 0 or any(
            needle in token for needle in ("pre-commit", "commands", "extends")
        ):
            raise RolloutError(
                f"lefthook line {line_number}: ambiguous mapping key {token!r}"
            ) from exc
        return None
    return MappingEntry(line_number - 1, indentation, key, stripped[separator + 1:].strip())


def _mapping_entries(lines: list[str]) -> list[MappingEntry]:
    _yaml_document_end_line(lines)
    entries = [
        entry for number, line in enumerate(lines, 1)
        if (entry := _mapping_entry(line, number)) is not None
    ]
    remote = next(
        (entry for entry in entries if entry.indent == 0 and entry.key == "remotes"),
        None,
    )
    if remote:
        raise RolloutError(
            f"lefthook line {remote.line + 1}: remote configuration sources are unsupported; "
            "use audited local extends files"
        )
    merge = next((entry for entry in entries if entry.key == "<<"), None)
    if merge:
        raise RolloutError(
            f"lefthook line {merge.line + 1}: YAML merge keys are unsupported for safe migration"
        )
    return entries


def _yaml_document_end_line(lines: list[str]) -> int | None:
    significant = [
        index for index, line in enumerate(lines)
        if line.strip() and not line.lstrip().startswith("#")
    ]
    markers = {
        index: _yaml_document_marker(lines[index].lstrip(" ")) for index in significant
    }
    starts = [index for index, marker in markers.items() if marker == "---"]
    ends = [index for index, marker in markers.items() if marker == "..."]
    indented_markers = [
        index for index, marker in markers.items()
        if marker is not None and lines[index] != lines[index].lstrip(" ")
    ]
    if indented_markers:
        raise RolloutError(
            f"lefthook line {indented_markers[0] + 1}: indented YAML document markers are unsupported"
        )
    document_content = [index for index in significant if markers[index] is None]
    if document_content and min(
        len(lines[index]) - len(lines[index].lstrip(" "))
        for index in document_content
    ) > 0:
        raise RolloutError(
            "lefthook document root indentation is unsupported; "
            "place top-level mappings at column zero"
        )
    if len(starts) > 1 or (starts and starts[0] != significant[0]):
        raise RolloutError("lefthook config must contain at most one leading YAML document start")
    if len(ends) > 1 or (ends and ends[0] != significant[-1]):
        raise RolloutError("lefthook config must contain at most one trailing YAML document end")
    if starts and ends and starts[0] >= ends[0]:
        raise RolloutError("lefthook YAML document markers are out of order")
    return ends[0] if ends else None


def _block_value(entry: MappingEntry, name: str) -> None:
    if entry.remainder and not entry.remainder.startswith("#"):
        raise RolloutError(
            f"lefthook line {entry.line + 1}: {name} must use a literal block mapping/list"
        )


def _block_end(lines: list[str], start: int, maximum: int, indent: int) -> int:
    for index in range(start + 1, maximum):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        current = len(line) - len(line.lstrip(" "))
        if current <= indent:
            return index
    return maximum


def _mapping_children(
    lines: list[str],
    entries: list[MappingEntry],
    parent: MappingEntry,
    maximum: int,
    name: str,
) -> tuple[list[MappingEntry], int]:
    end = _block_end(lines, parent.line, maximum, parent.indent)
    content = [
        index for index in range(parent.line + 1, end)
        if lines[index].strip() and not lines[index].lstrip().startswith("#")
    ]
    if not content:
        return [], end
    child_indent = min(len(lines[index]) - len(lines[index].lstrip(" ")) for index in content)
    if child_indent <= parent.indent:
        raise RolloutError(f"lefthook line {parent.line + 1}: invalid {name} indentation")
    by_line = {entry.line: entry for entry in entries}
    children: list[MappingEntry] = []
    for index in content:
        indentation = len(lines[index]) - len(lines[index].lstrip(" "))
        if indentation != child_indent:
            continue
        entry = by_line.get(index)
        if entry is None:
            raise RolloutError(
                f"lefthook line {index + 1}: {name} must use a literal block mapping"
            )
        children.append(entry)
    return children, end


def _lefthook_command_ids(text: str) -> set[str]:
    lines = text.splitlines()
    entries = _mapping_entries(lines)
    pre = [entry for entry in entries if entry.indent == 0 and entry.key == "pre-commit"]
    if not pre:
        return set()
    if len(pre) != 1:
        raise RolloutError("lefthook config must contain exactly one top-level pre-commit mapping")
    _block_value(pre[0], "pre-commit")
    pre_children, pre_end = _mapping_children(
        lines, entries, pre[0], len(lines), "pre-commit"
    )
    commands = [
        entry for entry in pre_children if entry.key == "commands"
    ]
    if not commands:
        return set()
    if len(commands) != 1:
        raise RolloutError("lefthook pre-commit must contain exactly one commands mapping")
    _block_value(commands[0], "pre-commit commands")
    command_children, _ = _mapping_children(
        lines, entries, commands[0], pre_end, "pre-commit commands"
    )
    return {entry.key for entry in command_children}


def _extends_entry(lines: list[str]) -> MappingEntry | None:
    entries = _mapping_entries(lines)
    extends = [entry for entry in entries if entry.indent == 0 and entry.key == "extends"]
    if len(extends) > 1:
        raise RolloutError("lefthook config must contain at most one top-level extends mapping")
    if not extends:
        return None
    _block_value(extends[0], "extends")
    end = _block_end(lines, extends[0].line, len(lines), 0)
    for index in range(extends[0].line + 1, end):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not re.fullmatch(r"  -\s+\S.*", line):
            raise RolloutError(
                f"lefthook line {index + 1}: extends must be one literal top-level block list"
            )
    return extends[0]


def _yaml_path_scalar(value: str, line_number: int) -> Path:
    value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
    try:
        if value.startswith('"'):
            decoded = json.loads(value)
        elif value.startswith("'"):
            if len(value) < 2 or not value.endswith("'"):
                raise ValueError("unterminated single-quoted path")
            decoded = value[1:-1].replace("''", "'")
        else:
            decoded = value
    except (json.JSONDecodeError, ValueError) as exc:
        raise RolloutError(
            f"lefthook line {line_number}: invalid extends path {value!r}"
        ) from exc
    if not isinstance(decoded, str) or not decoded:
        raise RolloutError(f"lefthook line {line_number}: extends path must be a string")
    parts = decoded.split("/")
    if (
        decoded.startswith("/")
        or decoded.endswith("/")
        or "\\" in decoded
        or any(part in {"", ".", ".."} for part in parts)
        or any(character in decoded for character in "*?[]{}")
    ):
        raise RolloutError(
            f"lefthook line {line_number}: extends must use normalized literal repo paths"
        )
    return Path(decoded)


def _extends_paths(text: str) -> list[Path]:
    lines = text.splitlines()
    extends = _extends_entry(lines)
    if extends is None:
        return []
    end = _block_end(lines, extends.line, len(lines), 0)
    result: list[Path] = []
    for index in range(extends.line + 1, end):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"  -\s+(\S.*)", line)
        assert match is not None
        result.append(_yaml_path_scalar(match.group(1), index + 1))
    return result


def _effective_lefthook_command_ids(
    repo: Path,
    config_path: Path,
    config_text: str,
) -> set[str]:
    pending: list[tuple[Path, str | None]] = [(config_path, config_text)]
    local = Path("lefthook-local.yml")
    if (repo / local).exists():
        pending.append((local, None))
    visited: set[Path] = set()
    commands: set[str] = set()
    while pending:
        relative, supplied = pending.pop()
        if relative in visited:
            continue
        if len(visited) >= 32:
            raise RolloutError("lefthook extends graph exceeds 32 local files")
        visited.add(relative)
        path = _safe_destination(repo, relative)
        if supplied is None:
            try:
                text = path.read_text(encoding="utf-8")
            except OSError as exc:
                raise RolloutError(f"unable to read lefthook extension {path}: {exc}") from exc
        else:
            text = supplied
        if relative != LEFTHOOK_EXTENSION_PATH:
            commands.update(_lefthook_command_ids(text))
        for child in _extends_paths(text):
            if child == LEFTHOOK_EXTENSION_PATH:
                continue
            pending.append((child, None))
    return commands


def _managed_extend_block(text: str) -> str:
    top_lines = [
        EXTEND_START,
        "extends:",
        f"  - {LEFTHOOK_EXTENSION_PATH.as_posix()}",
        EXTEND_END,
    ]
    nested_lines = [
        f"  {EXTEND_START}",
        f"  - {LEFTHOOK_EXTENSION_PATH.as_posix()}",
        f"  {EXTEND_END}",
    ]
    lines = text.splitlines()
    document_end = _yaml_document_end_line(lines)
    extends = _extends_entry(lines)
    start_count = text.count(EXTEND_START_MARKER.decode())
    end_count = text.count(EXTEND_END_MARKER.decode())
    if start_count or end_count:
        if start_count != 1 or end_count != 1:
            raise RolloutError("lefthook formatting extend markers must occur exactly once")
        start_line = next(
            (index for index, line in enumerate(lines) if EXTEND_START in line),
            None,
        )
        end_line = next(
            (index for index, line in enumerate(lines) if EXTEND_END in line),
            None,
        )
        if start_line is None or end_line is None or end_line < start_line:
            raise RolloutError("lefthook formatting extend block differs from canonical")
        managed_lines = lines[start_line:end_line + 1]
        if managed_lines == top_lines:
            if extends is None:
                raise RolloutError("managed lefthook formatting extend is missing its extends list")
            return text
        if managed_lines == nested_lines:
            if extends is None or extends.line >= start_line:
                raise RolloutError(
                    "managed lefthook formatting extend must be inside one top-level extends list"
                )
            for line in lines[extends.line + 1:start_line]:
                if line.strip() and not line.lstrip().startswith("#") \
                        and not line.startswith((" ", "\t")):
                    raise RolloutError(
                        "managed lefthook formatting extend must be inside the top-level extends list"
                    )
            return text
        raise RolloutError("lefthook formatting extend block differs from canonical")
    if LEFTHOOK_EXTENSION_PATH.as_posix() in text:
        raise RolloutError("lefthook formatting extension is present without managed markers")
    newline_match = re.search(r"\r\n|\n|\r", text)
    newline = newline_match.group(0) if newline_match else "\n"
    if extends is None:
        top = newline.join(top_lines) + newline
        raw_lines = text.splitlines(keepends=True)
        insertion = (
            sum(len(line) for line in raw_lines[:document_end])
            if document_end is not None else len(text)
        )
        prefix = text[:insertion]
        suffix = text[insertion:]
        if not prefix or re.search(r"(?:(?:\r\n)|\n|\r){2}$", prefix):
            separator = ""
        elif prefix.endswith(("\r\n", "\n", "\r")):
            separator = newline
        else:
            separator = newline * 2
        return prefix + separator + top + suffix
    raw_lines = text.splitlines(keepends=True)
    raw_extends = raw_lines[extends.line]
    line_ending = re.search(r"(?:\r\n|\n|\r)$", raw_extends)
    offset = sum(len(line) for line in raw_lines[:extends.line + 1])
    if line_ending:
        newline = line_ending.group(0)
        nested = newline.join(nested_lines) + newline
    else:
        nested = newline + newline.join(nested_lines)
    return text[:offset] + nested + text[offset:]


def _shell_join_argv(argv: list[str]) -> str:
    return " ".join("'" + argument.replace("'", "'\"'\"'") + "'" for argument in argv)


def _render_provision(commands: list[dict[str, Any]]) -> str:
    lines = [
        "      # hv-agent-formatting-provision:start",
        "      - name: Provision formatting dependencies",
        "        shell: bash",
        "        run: |",
        "          set -euo pipefail",
    ]
    if commands:
        lines.extend(f"          {_shell_join_argv(command['argv'])}" for command in commands)
    else:
        lines.append("          true")
    lines.append("      # hv-agent-formatting-provision:end")
    return "\n".join(lines) + "\n"


def _render_workflow(template_root: Path, ci: dict[str, Any]) -> bytes:
    template = template_root / "templates/github/formatting.yml"
    text = template.read_text(encoding="utf-8")
    branch = '    branches: ["main"]\n'
    runner = '    runs-on: "ubuntu-latest"\n'
    if text.count(branch) != 1 or text.count(runner) != 1:
        raise RolloutError("canonical formatting workflow render anchors are invalid")
    text = text.replace(branch, f"    branches: [{json.dumps(ci['default_branch'])}]\n", 1)
    text = text.replace(runner, f"    runs-on: {json.dumps(ci['runner'])}\n", 1)
    pattern = re.compile(
        r"(?ms)^      # hv-agent-formatting-provision:start\n.*?"
        r"^      # hv-agent-formatting-provision:end\n"
    )
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        raise RolloutError("canonical formatting provision block is invalid")
    rendered = _render_provision(ci["provision"])
    return (text[:matches[0].start()] + rendered + text[matches[0].end():]).encode()


def _validate_prospective_paths(
    repo: Path,
    contract: dict[str, Any],
    outputs: dict[Path, RenderedFile],
) -> None:
    index = formatting.current_index(repo)
    prospective_paths = set(index)
    prospective_paths.update(relative.as_posix().encode("utf-8") for relative in outputs)
    errors = formatting.semantic_errors(contract, prospective_paths)
    if errors:
        raise RolloutError(
            "generated formatting paths make the contract invalid:\n" + "\n".join(errors)
        )
    try:
        formatting.classify(contract, prospective_paths, index)
    except formatting.FormattingError as exc:
        raise RolloutError(
            "generated formatting paths are not classified by the contract:\n" + str(exc)
        ) from exc


def render_plan(
    repo: Path,
    template_root: Path,
    manifest: dict[str, Any],
    *,
    source_repository: bool = False,
) -> dict[Path, RenderedFile]:
    loaded = _load(repo)
    marker_errors = _marker_placement_errors(
        repo,
        loaded is not None,
        source_repository or repo.resolve() == template_root.resolve(),
    )
    if marker_errors:
        raise RolloutError("\n".join(marker_errors))
    if loaded is None:
        return {}
    contract, integrations = loaded
    repository = _forge_repository(manifest)
    if contract.get("repository") != repository:
        raise RolloutError(
            "formatting contract repository does not match the project forge repository"
        )
    check_errors = _required_check_errors(manifest)
    if check_errors:
        raise RolloutError("; ".join(check_errors))
    hook = integrations["staged_hook"]
    ci = integrations["ci"]
    config_path = Path(hook["config_path"])
    config = _safe_destination(repo, config_path)
    if config.is_file():
        try:
            config_text = config.read_bytes().decode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise RolloutError(f"unable to read lefthook config {config}: {exc}") from exc
    else:
        config_text = ""
    command_ids = _effective_lefthook_command_ids(repo, config_path, config_text)
    conflicts = sorted(set(hook["legacy_commands"]).intersection(command_ids))
    if conflicts:
        raise RolloutError(
            "declared legacy lefthook formatting commands remain; remove them in the "
            f"consumer change before migration: {', '.join(conflicts)}"
        )
    if "hv-agent-format" in command_ids:
        raise RolloutError(
            "repository-owned lefthook command hv-agent-format conflicts with the managed extension"
        )
    rendered_config = _managed_extend_block(config_text).encode()
    outputs: dict[Path, RenderedFile] = {
        config_path: RenderedFile(rendered_config),
        WORKFLOW_PATH: RenderedFile(_render_workflow(template_root, ci)),
        HOOK_PATH: RenderedFile(
            (template_root / "templates/hooks/pre-commit-format").read_bytes(), True,
        ),
        LEFTHOOK_EXTENSION_PATH: RenderedFile(
            (template_root / "templates/hooks/lefthook-formatting.yml").read_bytes(),
        ),
    }
    for relative in RUNTIME_PATHS:
        outputs[relative] = RenderedFile(
            (template_root / relative).read_bytes(),
            relative == Path("scripts/hv-agent-format"),
        )
    _validate_prospective_paths(repo, contract, outputs)
    for relative in outputs:
        destination = _safe_destination(repo, relative)
        if relative == config_path:
            continue
        marker = FILE_MARKERS.get(relative)
        if marker is None or outputs[relative].content.count(marker) != 1:
            raise RolloutError(
                f"canonical formatting output {relative} lacks one ownership marker"
            )
        if destination.is_file():
            current = destination.read_bytes()
            if current != outputs[relative].content and marker not in current:
                raise RolloutError(
                    f"{destination}: unmarked repository-owned file conflicts with generated "
                    "formatting output; move or remove it deliberately before migration"
                )
    return outputs


def audit(
    repo: Path,
    template_root: Path,
    manifest: dict[str, Any],
    *,
    source_repository: bool = False,
) -> list[str]:
    try:
        plan = render_plan(
            repo, template_root, manifest, source_repository=source_repository,
        )
    except (OSError, UnicodeError, formatting.FormattingError, RolloutError) as exc:
        return [f"{repo}: formatting rollout invalid: {exc}"]
    if not plan:
        return []
    errors: list[str] = []
    correction = "run scripts/hv-agent migrate-repo . --profile happyvertical --apply"
    for relative, rendered in plan.items():
        path = repo / relative
        try:
            if path.read_bytes() != rendered.content:
                errors.append(f"{path}: missing or stale generated formatting output; {correction}")
                continue
            metadata = path.stat()
            if metadata.st_nlink != 1:
                errors.append(
                    f"{path}: generated formatting output must not be hard-linked; {correction}"
                )
                continue
            execute_bits = metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            expected_bits = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH \
                if rendered.executable else 0
            if execute_bits != expected_bits:
                expected = "executable" if rendered.executable else "non-executable"
                errors.append(f"{path}: generated formatting output must be {expected}; {correction}")
        except OSError as exc:
            errors.append(f"{exc}; {correction}")
    return errors


def apply(
    repo: Path,
    template_root: Path,
    manifest: dict[str, Any],
    mutate: bool,
    *,
    source_repository: bool = False,
) -> dict[Path, RenderedFile]:
    plan = render_plan(
        repo, template_root, manifest, source_repository=source_repository,
    )
    for relative, rendered in plan.items():
        destination = _safe_destination(repo, relative)
        current = destination.read_bytes() if destination.is_file() else None
        current_execute_bits = destination.stat().st_mode & (
            stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        ) if destination.is_file() else 0
        current_link_count = destination.stat().st_nlink if destination.is_file() else 0
        expected_execute_bits = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH \
            if rendered.executable else 0
        if current == rendered.content and current_execute_bits == expected_execute_bits \
                and current_link_count == 1:
            continue
        print(f"{'write' if mutate else 'would write'} {destination}")
        if not mutate:
            continue
        _atomic_write(destination, rendered)
    return plan


def render_tree(
    repo: Path,
    output: Path,
    template_root: Path,
    manifest: dict[str, Any],
    mutate: bool,
) -> dict[Path, RenderedFile]:
    plan = render_plan(repo, template_root, manifest)
    for relative, rendered in plan.items():
        destination = _safe_destination(output, relative)
        print(f"{'write' if mutate else 'would render'} formatting: {destination}")
        if not mutate:
            continue
        _atomic_write(destination, rendered)
    return plan
