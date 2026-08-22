#!/usr/bin/env python3
# hv-agent-formatting-module:v1
"""Transactional formatting runtime for the HappyVertical formatting contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


SCHEMA_ID = "https://happyvertical.com/schemas/agent-formatting/v1"
CONTRACT_PATH = Path(".agents/formatting.json")
GIT = shutil.which("git") or "git"
ALLOWED_GIT_SUBCOMMANDS = {
    "blame",
    "cat-file",
    "check-attr",
    "check-ignore",
    "check-mailmap",
    "check-ref-format",
    "describe",
    "diff",
    "diff-files",
    "diff-index",
    "diff-tree",
    "for-each-ref",
    "grep",
    "log",
    "ls-files",
    "ls-tree",
    "merge-base",
    "name-rev",
    "rev-list",
    "rev-parse",
    "show",
    "show-branch",
    "show-ref",
    "status",
    "verify-commit",
    "verify-tag",
}
TEST_ENVIRONMENT_VARIABLES = {
    "HV_TEST_ASSERT_SANITIZED",
    "HV_TEST_CHMOD",
    "HV_TEST_DELETE",
    "HV_TEST_FAIL",
    "HV_TEST_GIT",
    "HV_TEST_GIT_ARGV",
    "HV_TEST_HIDDEN_PATH_TOUCH",
    "HV_TEST_INDEX_MUTATE",
    "HV_TEST_LOG",
    "HV_TEST_REAL_GIT",
    "HV_TEST_STATEFUL_CACHE",
    "HV_TEST_STATEFUL_DEPENDENCY_CACHE",
    "HV_TEST_TOUCH",
    "HV_TEST_VERIFY_TOUCH",
}


class FormattingError(RuntimeError):
    """A contract or transaction failure safe to display to a caller."""


@dataclass(frozen=True)
class IndexEntry:
    mode: bytes
    oid: bytes
    path: bytes

    @property
    def present_regular_file(self) -> bool:
        return self.mode in {b"100644", b"100755"}


@dataclass
class IsolatedRepository:
    root: Path
    index: dict[bytes, IndexEntry]
    revision: str | None
    baseline: dict[bytes, tuple[str, int, bytes]]
    guard_bin: Path
    ignored_roots: set[bytes]
    dependency_snapshot: Path


def run(
    argv: Sequence[str | bytes],
    *,
    cwd: Path,
    input_bytes: bytes | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        list(argv),
        cwd=cwd,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    if check and completed.returncode:
        command = os.fsdecode(argv[0]) if argv else "command"
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise FormattingError(
            f"{command} failed with exit {completed.returncode}"
            + (f": {detail}" if detail else "")
        )
    return completed


def internal_git_environment() -> dict[str, str]:
    return {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("GIT_")
    }


def git(repo: Path, *args: str | bytes, input_bytes: bytes | None = None) -> bytes:
    return run(
        [GIT, *args],
        cwd=repo,
        input_bytes=input_bytes,
        env=internal_git_environment(),
    ).stdout


def repository_root(value: str | Path) -> Path:
    candidate = Path(value).resolve()
    result = run(
        [GIT, "rev-parse", "--show-toplevel"],
        cwd=candidate,
        env=internal_git_environment(),
    )
    return Path(os.fsdecode(result.stdout.rstrip(b"\n"))).resolve()


def resolve_schema(schema: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    reference = schema.get("$ref")
    if not reference:
        return schema
    prefix = "#/$defs/"
    if not isinstance(reference, str) or not reference.startswith(prefix):
        raise FormattingError(f"unsupported schema reference: {reference!r}")
    return root["$defs"][reference.removeprefix(prefix)]


def schema_errors(
    value: Any,
    schema: dict[str, Any],
    root: dict[str, Any],
    path: str = "$",
) -> list[str]:
    schema = resolve_schema(schema, root)
    errors: list[str] = []
    expected = schema.get("type")
    type_matches = {
        "array": isinstance(value, list),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "object": isinstance(value, dict),
        "string": isinstance(value, str),
    }
    if expected and not type_matches.get(str(expected), False):
        return [f"{path}: expected {expected}"]
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected constant {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value is outside enum")
    if isinstance(value, str):
        if len(value) < int(schema.get("minLength", 0)):
            errors.append(f"{path}: string is too short")
        if len(value) > int(schema.get("maxLength", len(value))):
            errors.append(f"{path}: string is too long")
        pattern = schema.get("pattern")
        if pattern and re.fullmatch(str(pattern), value) is None:
            errors.append(f"{path}: string does not match pattern")
    if isinstance(value, int) and not isinstance(value, bool):
        if value < int(schema.get("minimum", value)):
            errors.append(f"{path}: value is below minimum")
    if isinstance(value, list):
        if len(value) < int(schema.get("minItems", 0)):
            errors.append(f"{path}: array has too few items")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True) for item in value]
            if len(encoded) != len(set(encoded)):
                errors.append(f"{path}: array items are not unique")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                errors.extend(schema_errors(item, item_schema, root, f"{path}[{index}]"))
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                errors.append(f"{path}: missing required property {name}")
        for name, item in value.items():
            child = properties.get(name)
            if child is not None:
                errors.extend(schema_errors(item, child, root, f"{path}.{name}"))
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected property {name}")
    forbidden = schema.get("not")
    if isinstance(forbidden, dict) and not schema_errors(value, forbidden, root, path):
        errors.append(f"{path}: matched forbidden schema")
    choices = schema.get("oneOf")
    if isinstance(choices, list):
        matches = sum(not schema_errors(value, choice, root, path) for choice in choices)
        if matches != 1:
            errors.append(f"{path}: expected exactly one oneOf match, got {matches}")
    return errors


def segment_matches(pattern: bytes, candidate: bytes) -> bool:
    memo: dict[tuple[int, int], bool] = {}

    def visit(pattern_index: int, candidate_index: int) -> bool:
        key = (pattern_index, candidate_index)
        if key in memo:
            return memo[key]
        if pattern_index == len(pattern):
            result = candidate_index == len(candidate)
        elif pattern[pattern_index] == ord("*"):
            result = visit(pattern_index + 1, candidate_index) or (
                candidate_index < len(candidate) and visit(pattern_index, candidate_index + 1)
            )
        elif pattern[pattern_index] == ord("?"):
            result = candidate_index < len(candidate) and visit(
                pattern_index + 1, candidate_index + 1
            )
        else:
            result = (
                candidate_index < len(candidate)
                and pattern[pattern_index] == candidate[candidate_index]
                and visit(pattern_index + 1, candidate_index + 1)
            )
        memo[key] = result
        return result

    return visit(0, 0)


def glob_matches(pattern: str | bytes, candidate: str | bytes) -> bool:
    pattern_bytes = pattern.encode("utf-8") if isinstance(pattern, str) else pattern
    candidate_bytes = candidate.encode("utf-8") if isinstance(candidate, str) else candidate
    pattern_segments = pattern_bytes.split(b"/")
    candidate_segments = candidate_bytes.split(b"/")
    memo: dict[tuple[int, int], bool] = {}

    def visit(pattern_index: int, candidate_index: int) -> bool:
        key = (pattern_index, candidate_index)
        if key in memo:
            return memo[key]
        if pattern_index == len(pattern_segments):
            result = candidate_index == len(candidate_segments)
        elif pattern_segments[pattern_index] == b"**":
            result = visit(pattern_index + 1, candidate_index) or (
                candidate_index < len(candidate_segments)
                and visit(pattern_index, candidate_index + 1)
            )
        else:
            result = (
                candidate_index < len(candidate_segments)
                and segment_matches(pattern_segments[pattern_index], candidate_segments[candidate_index])
                and visit(pattern_index + 1, candidate_index + 1)
            )
        memo[key] = result
        return result

    return visit(0, 0)


def display_path(path: bytes) -> str:
    return json.dumps(os.fsdecode(path), ensure_ascii=True)


def display_paths(paths: Iterable[bytes]) -> str:
    return "[" + ", ".join(display_path(path) for path in sorted(paths)) + "]"


def contract_repo_path(repo: Path, contract_path: Path | None = None) -> bytes:
    path = contract_path or CONTRACT_PATH
    if path.is_absolute():
        try:
            path = path.relative_to(repo)
        except ValueError as exc:
            raise FormattingError("formatting contract must be inside the repository") from exc
    if path == Path(".") or any(part in {"", ".", ".."} for part in path.parts):
        raise FormattingError("formatting contract must be a normalized repository file path")
    return path.as_posix().encode("utf-8")


def parse_contract(data: bytes, location: str) -> dict[str, Any]:
    schema_path = Path(__file__).resolve().parents[1] / "schemas/agent-formatting.schema.json"
    try:
        contract = json.loads(data.decode("utf-8"))
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FormattingError(f"unable to load formatting contract from {location}: {exc}") from exc
    errors = schema_errors(contract, schema, schema)
    if errors:
        raise FormattingError("invalid formatting contract:\n" + "\n".join(errors))
    return contract


def load_contract(repo: Path, contract_path: Path | None = None) -> tuple[dict[str, Any], bytes]:
    relative = contract_repo_path(repo, contract_path)
    path = os.path.join(os.fsencode(repo), relative)
    try:
        data = Path(os.fsdecode(path)).read_bytes()
    except OSError as exc:
        raise FormattingError(f"unable to load formatting contract: {exc}") from exc
    return parse_contract(data, display_path(relative)), relative


def load_snapshot_contract(
    repo: Path,
    index: dict[bytes, IndexEntry],
    contract_path: Path | None = None,
) -> tuple[dict[str, Any], bytes]:
    relative = contract_repo_path(repo, contract_path)
    entry = index.get(relative)
    if entry is None or not entry.present_regular_file:
        raise FormattingError(
            f"formatting contract is not a regular file in the evaluated snapshot: {display_path(relative)}"
        )
    data = git(repo, "cat-file", "blob", entry.oid)
    return parse_contract(data, f"snapshot {display_path(relative)}"), relative


def parse_index(data: bytes) -> dict[bytes, IndexEntry]:
    result: dict[bytes, IndexEntry] = {}
    for record in data.split(b"\0"):
        if not record:
            continue
        metadata, path = record.split(b"\t", 1)
        mode, oid, stage = metadata.split(b" ", 2)
        if stage != b"0":
            raise FormattingError(f"unmerged index entry: {display_path(path)}")
        if oid and not oid.strip(b"0"):
            raise FormattingError(f"intent-to-add entry is unsupported: {display_path(path)}")
        result[path] = IndexEntry(mode=mode, oid=oid, path=path)
    return result


def current_index(repo: Path) -> dict[bytes, IndexEntry]:
    return parse_index(git(repo, "ls-files", "--stage", "-z"))


def tree_index(repo: Path, revision: str) -> dict[bytes, IndexEntry]:
    result: dict[bytes, IndexEntry] = {}
    data = git(repo, "ls-tree", "-r", "-z", revision)
    for record in data.split(b"\0"):
        if not record:
            continue
        metadata, path = record.split(b"\t", 1)
        mode, _kind, oid = metadata.split(b" ", 2)
        result[path] = IndexEntry(mode=mode, oid=oid, path=path)
    return result


def head_index(repo: Path) -> dict[bytes, IndexEntry]:
    completed = run(
        [GIT, "rev-parse", "--verify", "HEAD^{commit}"],
        cwd=repo,
        env=internal_git_environment(),
        check=False,
    )
    if completed.returncode:
        return {}
    return tree_index(repo, os.fsdecode(completed.stdout.strip()))


def semantic_errors(contract: dict[str, Any], index_paths: set[bytes]) -> list[str]:
    errors: list[str] = []

    def unique(entries: list[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for entry in entries:
            identifier = entry["id"]
            if identifier in result:
                errors.append(f"duplicate {label} id: {identifier}")
            result[identifier] = entry
        return result

    formatters = unique(contract["formatters"], "formatter")
    owners = unique(contract["owners"], "owner")
    postprocessors = unique(contract["postprocessors"], "postprocessor")
    exclusions = unique(contract["exclusions"], "exclusion")
    del owners
    for owner in contract["owners"]:
        if owner["formatter"] not in formatters:
            errors.append(
                f"owner {owner['id']} references missing formatter {owner['formatter']}"
            )
    checksum_seen = False
    for postprocessor in contract["postprocessors"]:
        checksum_seen = checksum_seen or postprocessor["kind"] == "checksum"
        if checksum_seen and postprocessor["kind"] == "generate":
            errors.append("generate postprocessor appears after checksum postprocessor")
        for output in postprocessor["outputs"]:
            exclusion = exclusions.get(output)
            if exclusion is None:
                errors.append(f"postprocessor {postprocessor['id']} references missing output {output}")
                continue
            expected_kind = "generated" if postprocessor["kind"] == "generate" else "checksummed"
            if exclusion["reason_class"] != expected_kind:
                errors.append(
                    f"postprocessor {postprocessor['id']} output {output} is not {expected_kind}"
                )
            if exclusion.get("producer") != postprocessor["id"]:
                errors.append(f"output {output} does not point back to {postprocessor['id']}")
    for exclusion in contract["exclusions"]:
        producer = exclusion.get("producer")
        if producer:
            postprocessor = postprocessors.get(producer)
            if postprocessor is None:
                errors.append(f"exclusion {exclusion['id']} references missing producer {producer}")
            elif exclusion["id"] not in postprocessor["outputs"]:
                errors.append(f"producer {producer} does not declare output {exclusion['id']}")
    tracked_text_paths: set[str] = set()
    for path in index_paths:
        try:
            tracked_text_paths.add(path.decode("utf-8"))
        except UnicodeDecodeError:
            pass
    for category, inputs in contract["inputs"].items():
        for item in inputs:
            if item["path"] != "." and item["path"] not in tracked_text_paths:
                errors.append(f"{category} input is not tracked: {item['path']}")
    for root in contract.get("execution", {}).get("dependency_roots", []):
        root_bytes = root.encode("utf-8")
        reserved_roots = {b".git"}
        if root == "." or root.endswith("/") or any(
            root_bytes == reserved or root_bytes.startswith(reserved + b"/")
            for reserved in reserved_roots
        ):
            errors.append(f"invalid dependency root: {root}")
        if any(path == root_bytes or path.startswith(root_bytes + b"/") for path in index_paths):
            errors.append(f"dependency root must be untracked: {root}")
    return errors


def classify(
    contract: dict[str, Any],
    paths: Iterable[bytes],
    present_index: dict[bytes, IndexEntry],
) -> tuple[dict[str, list[bytes]], dict[bytes, str]]:
    groups: dict[str, list[bytes]] = {}
    excluded: dict[bytes, str] = {}
    errors: list[str] = []
    for path in sorted(set(paths)):
        exclusions = [
            item
            for item in contract["exclusions"]
            if any(glob_matches(pattern, path) for pattern in item["paths"])
        ]
        if len(exclusions) > 1:
            errors.append(f"duplicate exclusions for {display_path(path)}")
            continue
        if exclusions:
            excluded[path] = exclusions[0]["id"]
            continue
        owners = [
            item
            for item in contract["owners"]
            if any(glob_matches(pattern, path) for pattern in item["paths"])
        ]
        if not owners:
            errors.append(f"unknown-path: {display_path(path)}")
            continue
        if len(owners) > 1:
            errors.append(f"overlapping-ownership: {display_path(path)}")
            continue
        entry = present_index.get(path)
        if entry is not None:
            if not entry.present_regular_file:
                errors.append(
                    f"non-regular owned path requires an explicit exclusion: {display_path(path)}"
                )
                continue
            try:
                path.decode("utf-8")
            except UnicodeDecodeError:
                errors.append(
                    f"non-UTF-8 owned path requires an explicit exclusion: {display_path(path)}"
                )
                continue
            groups.setdefault(owners[0]["formatter"], []).append(path)
    if errors:
        raise FormattingError("classification failed:\n" + "\n".join(errors))
    return groups, excluded


def repository_file_state(
    root: Path,
    ignored_roots: set[bytes] | None = None,
) -> dict[bytes, tuple[str, int, bytes]]:
    result: dict[bytes, tuple[str, int, bytes]] = {}
    root_bytes = os.fsencode(root)
    ignored = set(ignored_roots or set()) | {b".git"}

    def visit(directory: bytes, prefix: bytes = b"") -> None:
        with os.scandir(directory) as entries:
            for entry in entries:
                name = entry.name if isinstance(entry.name, bytes) else os.fsencode(entry.name)
                relative = prefix + name
                if relative in ignored:
                    continue
                entry_stat = entry.stat(follow_symlinks=False)
                mode = stat.S_IMODE(entry_stat.st_mode)
                if entry.is_symlink():
                    target = os.readlink(entry.path)
                    target_bytes = target if isinstance(target, bytes) else os.fsencode(target)
                    result[relative] = ("symlink", mode, target_bytes)
                elif entry.is_dir(follow_symlinks=False):
                    visit(entry.path, relative + b"/")
                elif entry.is_file(follow_symlinks=False):
                    result[relative] = ("file", mode, Path(os.fsdecode(entry.path)).read_bytes())
                else:
                    result[relative] = ("special", mode, b"")

    visit(root_bytes)
    return result


def changed_paths(
    before: dict[bytes, tuple[str, int, bytes]],
    after: dict[bytes, tuple[str, int, bytes]],
) -> set[bytes]:
    return {path for path in before.keys() | after.keys() if before.get(path) != after.get(path)}


def write_index(repo: Path, index: dict[bytes, IndexEntry]) -> None:
    payload = b"".join(
        entry.mode + b" " + entry.oid + b"\t" + path + b"\0"
        for path, entry in sorted(index.items())
    )
    git(repo, "update-index", "-z", "--index-info", input_bytes=payload)


def materialize(repo: Path, source: Path, index: dict[bytes, IndexEntry]) -> None:
    for path, entry in sorted(index.items()):
        destination = os.path.join(os.fsencode(repo), path)
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        if entry.mode == b"160000":
            os.makedirs(destination, exist_ok=True)
            continue
        content = git(source, "cat-file", "blob", entry.oid)
        if entry.mode == b"120000":
            os.symlink(content, destination)
            continue
        with open(destination, "wb") as handle:
            handle.write(content)
        os.chmod(destination, 0o755 if entry.mode == b"100755" else 0o644)


def install_git_guard(root: Path) -> Path:
    guard = root / "guard-bin"
    guard.mkdir()
    script = guard / "git"
    allowed = "|".join(sorted(ALLOWED_GIT_SUBCOMMANDS))
    script.write_text(
        "#!/bin/sh\n"
        "probe_git_command() {\n"
        "  while [ \"$#\" -gt 0 ]; do\n"
        "    case \"$1\" in\n"
        "      -c|--config-env|--config-env=*) echo \"hv-agent-format: Git config overrides are disabled in isolated formatting\" >&2; return 97 ;;\n"
        "      -C|--git-dir|--work-tree|--namespace|--super-prefix) shift 2 ;;\n"
        "      --git-dir=*|--work-tree=*|--namespace=*|--super-prefix=*) shift ;;\n"
        "      --) shift; printf '%s' \"${1:-}\"; return ;;\n"
        "      -*) shift ;;\n"
        "      *) printf '%s' \"$1\"; return ;;\n"
        "    esac\n"
        "  done\n"
        "}\n"
        "command_name=$(probe_git_command \"$@\") || exit $?\n"
        "case \"$command_name\" in\n"
        f"  {allowed}) ;;\n"
        "  *) echo \"hv-agent-format: git ${command_name:-<none>} is disabled in isolated formatting\" >&2; exit 97 ;;\n"
        "esac\n"
        f"exec {json.dumps(GIT)} \"$@\"\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return guard


def copy_dependency_roots(
    source: Path,
    destination: Path,
    contract: dict[str, Any],
) -> set[bytes]:
    roots = {
        item.encode("utf-8")
        for item in contract.get("execution", {}).get("dependency_roots", [])
    }
    for relative in sorted(roots):
        source_path = os.path.join(os.fsencode(source), relative)
        destination_path = os.path.join(os.fsencode(destination), relative)
        current = source.resolve()
        for part in Path(os.fsdecode(relative)).parts:
            current = current / part
            if current.is_symlink():
                raise FormattingError(
                    f"dependency root has a symlinked path component: {display_path(relative)}"
                )
        try:
            source_stat = os.lstat(source_path)
        except OSError as exc:
            raise FormattingError(
                f"declared formatter dependency root is unavailable: {display_path(relative)}"
            ) from exc
        if not stat.S_ISDIR(source_stat.st_mode) or stat.S_ISLNK(source_stat.st_mode):
            raise FormattingError(
                f"formatter dependency root must be a real directory: {display_path(relative)}"
            )
        repository = source.resolve()
        resolved_root = Path(os.fsdecode(source_path)).resolve()
        if not path_is_within(resolved_root, repository) or resolved_root == repository:
            raise FormattingError(
                f"formatter dependency root escapes the repository: {display_path(relative)}"
            )
        for directory, directory_names, file_names in os.walk(source_path):
            for name in [*directory_names, *file_names]:
                candidate = os.path.join(directory, name)
                if not os.path.islink(candidate):
                    continue
                target = os.readlink(candidate)
                if os.path.isabs(target):
                    raise FormattingError(
                        f"dependency root contains an absolute symlink: {display_path(relative)}"
                    )
                resolved = (Path(os.fsdecode(candidate)).parent / os.fsdecode(target)).resolve()
                if not path_is_within(resolved, repository):
                    raise FormattingError(
                        f"dependency root symlink escapes the repository: {display_path(relative)}"
                    )
        os.makedirs(os.path.dirname(destination_path), exist_ok=True)
        shutil.copytree(source_path, destination_path, symlinks=True)
    return roots


def snapshot_dependency_roots(
    repository: Path,
    roots: set[bytes],
    destination: Path,
) -> None:
    destination.mkdir()
    for relative in sorted(roots):
        source_path = os.path.join(os.fsencode(repository), relative)
        destination_path = os.path.join(os.fsencode(destination), relative)
        os.makedirs(os.path.dirname(destination_path), exist_ok=True)
        shutil.copytree(source_path, destination_path, symlinks=True)


def isolated_repository(
    source: Path,
    index: dict[bytes, IndexEntry],
    revision: str | None,
    destination: Path,
    contract: dict[str, Any],
) -> IsolatedRepository:
    destination.mkdir()
    git(destination, "init", "--quiet")
    objects = Path(os.fsdecode(git(source, "rev-parse", "--git-path", "objects").strip()))
    if not objects.is_absolute():
        objects = source / objects
    alternates = destination / ".git/objects/info/alternates"
    alternates.parent.mkdir(parents=True, exist_ok=True)
    alternates.write_text(str(objects.resolve()) + "\n", encoding="utf-8")
    git(destination, "config", "core.hooksPath", os.devnull)
    git(destination, "config", "user.name", "hv-agent-format")
    git(destination, "config", "user.email", "formatting@invalid")
    if revision is not None:
        git(destination, "update-ref", "refs/heads/snapshot", revision)
        git(destination, "symbolic-ref", "HEAD", "refs/heads/snapshot")
    write_index(destination, index)
    materialize(destination, source, index)
    ignored_roots = copy_dependency_roots(source, destination, contract)
    dependency_snapshot = destination.parent / "dependency-snapshot"
    snapshot_dependency_roots(destination, ignored_roots, dependency_snapshot)
    baseline = repository_file_state(destination, ignored_roots)
    return IsolatedRepository(
        root=destination,
        index=index,
        revision=revision,
        baseline=baseline,
        guard_bin=install_git_guard(destination.parent),
        ignored_roots=ignored_roots,
        dependency_snapshot=dependency_snapshot,
    )


def command_environment(isolated: IsolatedRepository, mode: str) -> dict[str, str]:
    environment = {
        name: os.environ[name]
        for name in TEST_ENVIRONMENT_VARIABLES
        if name in os.environ
    }
    runtime_root = isolated.root.parent
    home = runtime_root / "home"
    temporary = runtime_root / "tmp"
    home.mkdir(exist_ok=True)
    temporary.mkdir(exist_ok=True)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CEILING_DIRECTORIES": str(isolated.root.parent),
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": str(home),
            "HV_FORMAT_MODE": mode,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NO_COLOR": "1",
            "PATH": str(isolated.guard_bin)
            + os.pathsep
            + os.environ.get("PATH", os.defpath),
            "PWD": str(isolated.root),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
            "TEMP": str(temporary),
            "TERM": "dumb",
            "TMP": str(temporary),
            "TMPDIR": str(temporary),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_CONFIG_HOME": str(home / ".config"),
        }
    )
    return environment


def reset_command_state(isolated: IsolatedRepository) -> None:
    for name in ("home", "tmp"):
        path = isolated.root.parent / name
        if not os.path.lexists(path):
            continue
        if path.is_symlink() or not path.is_dir():
            path.unlink()
        else:
            shutil.rmtree(path)
    for relative in sorted(isolated.ignored_roots):
        destination = Path(os.fsdecode(os.path.join(os.fsencode(isolated.root), relative)))
        if os.path.lexists(destination):
            if destination.is_symlink() or not destination.is_dir():
                destination.unlink()
            else:
                shutil.rmtree(destination)
        source = os.path.join(os.fsencode(isolated.dependency_snapshot), relative)
        os.makedirs(os.path.dirname(os.fsencode(destination)), exist_ok=True)
        shutil.copytree(source, os.fsencode(destination), symlinks=True)


def command_invocations(
    command: dict[str, Any], paths: list[bytes], *, run_without_paths: bool = False
) -> list[list[bytes]]:
    base = [item.encode("utf-8") for item in command["argv"]]
    mode = command["path_mode"]
    arguments = [b"./" + path for path in sorted(paths)]
    if mode == "batch":
        return [base + arguments] if arguments or run_without_paths else []
    if mode == "each-file":
        return [base + [argument] for argument in arguments]
    parents = sorted({path.rpartition(b"/")[0] for path in paths})
    parent_arguments = [b"./" + parent if parent else b"./" for parent in parents]
    return [base + parent_arguments] if parent_arguments else []


def repository_git_control_state(isolated: IsolatedRepository) -> tuple[bytes, bytes, bytes, bytes]:
    git_dir_value = os.fsdecode(git(isolated.root, "rev-parse", "--git-dir").strip())
    git_dir = Path(git_dir_value)
    if not git_dir.is_absolute():
        git_dir = isolated.root / git_dir
    index_path = git_dir / "index"
    config_path = git_dir / "config"
    return (
        index_path.read_bytes(),
        config_path.read_bytes(),
        git(isolated.root, "for-each-ref", "--format=%(refname) %(objectname)"),
        git(isolated.root, "remote"),
    )


def run_contract_command(
    isolated: IsolatedRepository,
    command: dict[str, Any],
    paths: list[bytes],
    mode: str,
    *,
    run_without_paths: bool = False,
) -> None:
    environment = command_environment(isolated, mode)
    for invocation in command_invocations(
        command, paths, run_without_paths=run_without_paths
    ):
        git_state = repository_git_control_state(isolated)
        completed = run(invocation, cwd=isolated.root, env=environment, check=False)
        if completed.returncode:
            detail = (completed.stderr or completed.stdout).decode("utf-8", "replace").strip()
            raise FormattingError(
                f"formatter command failed with exit {completed.returncode}"
                + (f": {detail}" if detail else "")
            )
        if repository_git_control_state(isolated) != git_state:
            raise FormattingError("configured command mutated isolated Git control state")


def paths_for_exclusion(
    exclusion: dict[str, Any], index_paths: Iterable[bytes]
) -> set[bytes]:
    return {
        path
        for path in index_paths
        if any(glob_matches(pattern, path) for pattern in exclusion["paths"])
    }


def verify_repository_identity(isolated: IsolatedRepository) -> None:
    refs = git(isolated.root, "for-each-ref", "--format=%(refname) %(objectname)")
    if isolated.revision is None:
        head = run(
            [GIT, "rev-parse", "--verify", "HEAD^{commit}"],
            cwd=isolated.root,
            env=internal_git_environment(),
            check=False,
        )
        valid = head.returncode != 0 and not refs
    else:
        head = os.fsdecode(git(isolated.root, "rev-parse", "HEAD").strip())
        expected = f"refs/heads/snapshot {isolated.revision}\n".encode()
        valid = head == isolated.revision and refs == expected
    if not valid:
        raise FormattingError("formatter attempted to commit or mutate isolated Git refs")
    if git(isolated.root, "remote").strip():
        raise FormattingError("formatter added a remote to the isolated repository")


def transaction_once(
    isolated: IsolatedRepository,
    contract: dict[str, Any],
    groups: dict[str, list[bytes]],
    *,
    staged_paths: set[bytes] | None,
    full_scope: bool,
    mode: str,
) -> None:
    formatters = {item["id"]: item for item in contract["formatters"]}
    for formatter_id in sorted(groups):
        before = repository_file_state(isolated.root, isolated.ignored_roots)
        run_contract_command(
            isolated,
            formatters[formatter_id]["apply"],
            groups[formatter_id],
            mode,
        )
        after = repository_file_state(isolated.root, isolated.ignored_roots)
        changed = changed_paths(before, after)
        allowed = set(groups[formatter_id])
        outside = changed - allowed
        if outside:
            if staged_paths is not None and full_scope:
                raise FormattingError(
                    "full-apply-required: full-scope formatting changed paths outside the original staged set: "
                    + display_paths(outside)
                )
            raise FormattingError(
                f"formatter {formatter_id} changed undeclared paths: {display_paths(outside)}"
            )
        for path in allowed:
            prior = before.get(path)
            current = after.get(path)
            if (
                prior is None
                or current is None
                or prior[0] != "file"
                or current[0] != "file"
                or prior[1] != current[1]
            ):
                raise FormattingError(
                    f"formatter {formatter_id} changed file type or mode: {display_path(path)}"
                )

    exclusions = {item["id"]: item for item in contract["exclusions"]}
    trigger_paths = set(staged_paths or isolated.index)
    for postprocessor in contract["postprocessors"]:
        selected = full_scope or any(
            glob_matches(pattern, path)
            for pattern in postprocessor["inputs"]
            for path in trigger_paths
        )
        if not selected:
            continue
        before = repository_file_state(isolated.root, isolated.ignored_roots)
        allowed: set[bytes] = set()
        for output in postprocessor["outputs"]:
            allowed.update(paths_for_exclusion(exclusions[output], isolated.index))
        for path in sorted(allowed):
            prior = before.get(path)
            if prior is None or prior[0] != "file":
                raise FormattingError(
                    f"postprocessor {postprocessor['id']} output must be a regular tracked file: "
                    f"{display_path(path)}"
                )
        command = {"argv": postprocessor["argv"], "path_mode": "batch"}
        run_contract_command(
            isolated, command, [], mode, run_without_paths=True
        )
        after = repository_file_state(isolated.root, isolated.ignored_roots)
        changed = changed_paths(before, after)
        for path in sorted(allowed):
            prior = before[path]
            current = after.get(path)
            if current is None or current[0] != "file" or current[1] != prior[1]:
                raise FormattingError(
                    f"postprocessor {postprocessor['id']} changed output type or mode: "
                    f"{display_path(path)}"
                )
        outside = changed - allowed
        if outside:
            raise FormattingError(
                f"postprocessor {postprocessor['id']} changed undeclared paths: {display_paths(outside)}"
            )
        if staged_paths is not None and changed - staged_paths:
            raise FormattingError(
                "full-apply-required: postprocessor output is outside the original staged set: "
                + display_paths(changed - staged_paths)
            )
        trigger_paths.update(changed)

    for formatter_id in sorted(groups):
        verification = formatters[formatter_id]["verify"]
        if verification["mode"] == "native-check":
            before = repository_file_state(isolated.root, isolated.ignored_roots)
            run_contract_command(
                isolated,
                verification["command"],
                groups[formatter_id],
                mode,
            )
            changed = changed_paths(
                before,
                repository_file_state(isolated.root, isolated.ignored_roots),
            )
            if changed:
                raise FormattingError(
                    f"verification command for {formatter_id} mutated paths: {display_paths(changed)}"
                )
    verify_repository_identity(isolated)


def run_transaction(
    isolated: IsolatedRepository,
    contract: dict[str, Any],
    groups: dict[str, list[bytes]],
    *,
    staged_paths: set[bytes] | None,
    full_scope: bool,
    mode: str,
) -> dict[bytes, tuple[str, int, bytes]]:
    reset_command_state(isolated)
    transaction_once(
        isolated,
        contract,
        groups,
        staged_paths=staged_paths,
        full_scope=full_scope,
        mode=mode,
    )
    first = repository_file_state(isolated.root, isolated.ignored_roots)
    reset_command_state(isolated)
    transaction_once(
        isolated,
        contract,
        groups,
        staged_paths=staged_paths,
        full_scope=full_scope,
        mode=mode,
    )
    second = repository_file_state(isolated.root, isolated.ignored_roots)
    if first != second:
        raise FormattingError(
            "formatting transaction is not idempotent; second application changed: "
            + display_paths(changed_paths(first, second))
        )
    return second


def contract_input_paths(contract: dict[str, Any]) -> set[bytes]:
    return {
        item["path"].encode("utf-8")
        for values in contract["inputs"].values()
        for item in values
    }


def repository_index_path(source: Path) -> Path:
    value = os.fsdecode(git(source, "rev-parse", "--git-path", "index").strip())
    path = Path(value)
    return path if path.is_absolute() else source / path


def build_candidate_index(
    isolated: IsolatedRepository,
    changed: set[bytes],
    source: Path,
    original_index: bytes,
    candidate: Path,
) -> None:
    candidate.write_bytes(original_index)
    entries: list[IndexEntry] = []
    state = repository_file_state(isolated.root, isolated.ignored_roots)
    for path in sorted(changed):
        entry = isolated.index.get(path)
        current = state.get(path)
        if entry is None or current is None or not entry.present_regular_file or current[0] != "file":
            raise FormattingError(f"formatter changed path type: {display_path(path)}")
        if stat.S_IMODE(current[1]) != (0o755 if entry.mode == b"100755" else 0o644):
            raise FormattingError(f"formatter changed file mode: {display_path(path)}")
        oid = git(source, "hash-object", "-w", "--stdin", input_bytes=current[2]).strip()
        entries.append(IndexEntry(entry.mode, oid, path))
    payload = b"".join(
        entry.mode + b" " + entry.oid + b"\t" + entry.path + b"\0"
        for entry in entries
    )
    environment = internal_git_environment()
    environment["GIT_INDEX_FILE"] = str(candidate)
    run(
        [GIT, "update-index", "-z", "--index-info"],
        cwd=source,
        input_bytes=payload,
        env=environment,
    )


def atomic_install_index(
    source: Path,
    expected: bytes,
    candidate: Path,
) -> None:
    index_path = repository_index_path(source)
    lock_path = Path(str(index_path) + ".lock")
    descriptor: int | None = None
    owned_lock = False
    try:
        descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        owned_lock = True
        if index_path.read_bytes() != expected:
            raise FormattingError("live index changed during isolated staged formatting")
        os.fchmod(descriptor, stat.S_IMODE(index_path.stat().st_mode))
        payload = candidate.read_bytes()
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(lock_path, index_path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if owned_lock and lock_path.exists():
            lock_path.unlink()


def validate_contract(repo: Path, contract_path: Path | None = None) -> None:
    contract, _relative = load_contract(repo, contract_path)
    index = current_index(repo)
    errors = semantic_errors(contract, set(index))
    if errors:
        raise FormattingError("invalid formatting contract:\n" + "\n".join(errors))
    classify(contract, index, index)


def index_from_snapshot(repo: Path, payload: bytes, snapshot: Path) -> dict[bytes, IndexEntry]:
    snapshot.write_bytes(payload)
    environment = internal_git_environment()
    environment["GIT_INDEX_FILE"] = str(snapshot)
    listed = run(
        [GIT, "ls-files", "--stage", "-z"],
        cwd=repo,
        env=environment,
    ).stdout
    return parse_index(listed)


def staged(repo: Path, contract_path: Path | None = None) -> int:
    original_index = repository_index_path(repo).read_bytes()
    resolved_head = run(
        [GIT, "rev-parse", "--verify", "HEAD^{commit}"],
        cwd=repo,
        env=internal_git_environment(),
        check=False,
    )
    revision = os.fsdecode(resolved_head.stdout.strip()) if resolved_head.returncode == 0 else None
    with tempfile.TemporaryDirectory(prefix="hv-agent-format-staged-") as directory:
        temporary = Path(directory)
        index = index_from_snapshot(repo, original_index, temporary / "source-index")
        contract, contract_relative = load_snapshot_contract(repo, index, contract_path)
        errors = semantic_errors(contract, set(index))
        if errors:
            raise FormattingError("invalid formatting contract:\n" + "\n".join(errors))
        head = tree_index(repo, revision) if revision is not None else {}
        staged_paths = {
            path
            for path in set(head) | set(index)
            if head.get(path) != index.get(path)
        }
        if not staged_paths:
            print("no staged paths")
            return 0
        classify(contract, index, index)
        inputs = contract_input_paths(contract) | {contract_relative}
        full_scope = b"." in inputs or bool(staged_paths & inputs)
        scope = (set(index) | staged_paths) if full_scope else staged_paths
        groups, _excluded = classify(contract, scope, index)
        isolated = isolated_repository(
            repo, index, revision, temporary / "repo", contract
        )
        final = run_transaction(
            isolated,
            contract,
            groups,
            staged_paths=staged_paths,
            full_scope=full_scope,
            mode="staged",
        )
        changed = changed_paths(isolated.baseline, final)
        outside = changed - staged_paths
        if outside:
            raise FormattingError(
                "full-apply-required: isolated transaction changed paths outside the original staged set: "
                + display_paths(outside)
            )
        if changed:
            candidate = temporary / "candidate-index"
            build_candidate_index(isolated, changed, repo, original_index, candidate)
            atomic_install_index(repo, original_index, candidate)
    print(f"formatted staged paths: {display_paths(staged_paths)}")
    return 0


def exact_revision(repo: Path, revision: str) -> str:
    completed = run(
        [GIT, "rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}"],
        cwd=repo,
        env=internal_git_environment(),
    )
    return os.fsdecode(completed.stdout.strip())


def full_transaction(
    repo: Path,
    contract: dict[str, Any],
    revision: str,
    destination: Path,
    mode: str,
) -> tuple[IsolatedRepository, set[bytes], bytes]:
    index = tree_index(repo, revision)
    errors = semantic_errors(contract, set(index))
    if errors:
        raise FormattingError("invalid formatting contract:\n" + "\n".join(errors))
    groups, _excluded = classify(contract, index, index)
    isolated = isolated_repository(repo, index, revision, destination, contract)
    final = run_transaction(
        isolated,
        contract,
        groups,
        staged_paths=None,
        full_scope=True,
        mode=mode,
    )
    changed = changed_paths(isolated.baseline, final)
    tracked = set(index)
    outside = changed - tracked
    if outside:
        raise FormattingError(f"transaction created untracked paths: {display_paths(outside)}")
    patch = git(isolated.root, "diff", "--binary", "--no-ext-diff", "HEAD", "--")
    return isolated, changed, patch


def full_apply(repo: Path, contract_path: Path | None = None) -> int:
    if git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all"):
        raise FormattingError("full-apply requires a completely clean repository")
    revision = exact_revision(repo, "HEAD")
    index = tree_index(repo, revision)
    contract, _relative = load_snapshot_contract(repo, index, contract_path)
    with tempfile.TemporaryDirectory(prefix="hv-agent-format-apply-") as directory:
        _isolated, changed, patch = full_transaction(
            repo, contract, revision, Path(directory) / "repo", "full-apply"
        )
        if exact_revision(repo, "HEAD") != revision or git(
            repo, "status", "--porcelain=v1", "-z", "--untracked-files=all"
        ):
            raise FormattingError("repository changed during isolated full application")
        if patch:
            run(
                [GIT, "apply", "--check", "--binary", "-"],
                cwd=repo,
                input_bytes=patch,
                env=internal_git_environment(),
            )
            run(
                [GIT, "apply", "--binary", "-"],
                cwd=repo,
                input_bytes=patch,
                env=internal_git_environment(),
            )
    print(f"full formatting applied: {display_paths(changed)}")
    return 0


def path_is_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
        return True
    except ValueError:
        return False


def write_patch_artifact(repo: Path, requested: Path, payload: bytes) -> None:
    absolute = requested if requested.is_absolute() else Path.cwd() / requested
    parent = absolute.parent.resolve()
    destination = parent / absolute.name
    protected = {repo.resolve()}
    for selector in ("--git-dir", "--git-common-dir"):
        value = os.fsdecode(git(repo, "rev-parse", selector).strip())
        path = Path(value)
        protected.add((path if path.is_absolute() else repo / path).resolve())
    if any(path_is_within(destination, root) for root in protected):
        raise FormattingError(
            "patch output must be outside the invoking worktree and Git directories"
        )
    parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(destination):
        raise FormattingError(f"patch output already exists: {destination}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def full_verify(
    repo: Path,
    contract_path: Path | None = None,
    *,
    revision: str = "HEAD",
    patch_path: Path | None = None,
    report: bool = False,
) -> int:
    resolved = exact_revision(repo, revision)
    index = tree_index(repo, resolved)
    contract, _relative = load_snapshot_contract(repo, index, contract_path)
    with tempfile.TemporaryDirectory(prefix="hv-agent-format-verify-") as directory:
        _isolated, changed, patch = full_transaction(
            repo, contract, resolved, Path(directory) / "repo", "full-verify"
        )
        if patch_path is not None:
            write_patch_artifact(repo, patch_path, patch)
    if changed:
        print(f"formatting drift at {resolved}: {display_paths(changed)}", file=sys.stderr)
        return 0 if report else 1
    print(f"formatting verified at {resolved}")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="hv-agent-format")
    result.add_argument("--repo", default=".")
    result.add_argument("--contract", type=Path)
    subparsers = result.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate")
    subparsers.add_parser("staged")
    subparsers.add_parser("full-apply")
    verify = subparsers.add_parser("full-verify")
    verify.add_argument("--revision", default="HEAD")
    verify.add_argument("--patch", type=Path)
    verify.add_argument(
        "--report",
        action="store_true",
        help="report ordinary formatting drift without failing; contract and runtime errors still fail",
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        repo = repository_root(args.repo)
        contract = args.contract
        if args.command == "validate":
            validate_contract(repo, contract)
            print("formatting contract valid")
            return 0
        if args.command == "staged":
            return staged(repo, contract)
        if args.command == "full-apply":
            return full_apply(repo, contract)
        return full_verify(
            repo,
            contract,
            revision=args.revision,
            patch_path=args.patch,
            report=args.report,
        )
    except (FormattingError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
