#!/usr/bin/env python3
"""Shared GitHub transport for HappyVertical lifecycle runtimes.

REST is the default transport. GraphQL is used only for GitHub surfaces that
have no REST equivalent with the authority semantics required by the lifecycle:
Projects v2, closing-issue relations, merge-queue state, and exact authority
comment edit timestamps.
"""

from __future__ import annotations

import datetime as dt
import base64
import json
import re
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import quote

import hv_agent_lifecycle as lifecycle


JsonRunner = Callable[[list[str]], Any]
ErrorType = type[Exception]

MAX_PROJECT_FIELD_PAGES = 10
MAX_TARGETED_PROJECT_ITEM_PAGES = 20
MAX_BACKGROUND_PROJECT_PAGES = 100
MAX_PROJECT_SYNC_ITEMS = 100
PROJECT_SYNC_STATUSES = frozenset({"New", "Backlog", "Planning", "Ready"})
LIFECYCLE_OWNED_PROJECT_STATUSES = frozenset({"In Progress", "Review", "Done"})
AGENT_POLICY_WORKFLOW_PATTERN = re.compile(
    r"\.github/workflows/[A-Za-z0-9._-]+\.ya?ml"
)
DEDICATED_LIFECYCLE_WORKFLOW = ".github/workflows/agent-policy.yml"

PROJECT_METADATA_ORGANIZATION_QUERY = """\
query($owner:String!,$number:Int!,$endCursor:String){
  organization(login:$owner){
    projectV2(number:$number){
      id title
      fields(first:100,after:$endCursor){
        nodes{... on ProjectV2SingleSelectField{id name options{id name}}}
        pageInfo{hasNextPage endCursor}
      }
    }
  }
  rateLimit{cost remaining resetAt}
}"""

PROJECT_METADATA_USER_QUERY = """\
query($owner:String!,$number:Int!,$endCursor:String){
  user(login:$owner){
    projectV2(number:$number){
      id title
      fields(first:100,after:$endCursor){
        nodes{... on ProjectV2SingleSelectField{id name options{id name}}}
        pageInfo{hasNextPage endCursor}
      }
    }
  }
  rateLimit{cost remaining resetAt}
}"""

PROJECT_METADATA_AND_PROJECT_ITEMS_ORGANIZATION_QUERY = """\
query($owner:String!,$number:Int!,$itemQuery:String!){
  organization(login:$owner){
    projectV2(number:$number){
      id title
      fields(first:100){
        nodes{... on ProjectV2SingleSelectField{id name options{id name}}}
        pageInfo{hasNextPage endCursor}
      }
      items(first:100,query:$itemQuery){
        nodes{
          id isArchived project{id}
          content{... on Issue{id}}
          fieldValueByName(name:"Status"){
            ... on ProjectV2ItemFieldSingleSelectValue{name optionId}
          }
        }
        pageInfo{hasNextPage endCursor}
      }
    }
  }
  rateLimit{cost remaining resetAt}
}"""

PROJECT_METADATA_AND_PROJECT_ITEMS_USER_QUERY = """\
query($owner:String!,$number:Int!,$itemQuery:String!){
  user(login:$owner){
    projectV2(number:$number){
      id title
      fields(first:100){
        nodes{... on ProjectV2SingleSelectField{id name options{id name}}}
        pageInfo{hasNextPage endCursor}
      }
      items(first:100,query:$itemQuery){
        nodes{
          id isArchived project{id}
          content{... on Issue{id}}
          fieldValueByName(name:"Status"){
            ... on ProjectV2ItemFieldSingleSelectValue{name optionId}
          }
        }
        pageInfo{hasNextPage endCursor}
      }
    }
  }
  rateLimit{cost remaining resetAt}
}"""

PROJECT_ITEMS_QUERY = """\
query($project:ID!,$itemQuery:String!,$endCursor:String){
  node(id:$project){
    ... on ProjectV2{
      items(first:100,after:$endCursor,query:$itemQuery){
        nodes{
          id isArchived
          project{id}
          content{... on Issue{id}}
          fieldValueByName(name:"Status"){
            ... on ProjectV2ItemFieldSingleSelectValue{name optionId}
          }
        }
        pageInfo{hasNextPage endCursor}
      }
    }
  }
  rateLimit{cost remaining resetAt}
}"""

PROJECT_ITEM_QUERY = """\
query($item:ID!){
  node(id:$item){
    ... on ProjectV2Item{
      id isArchived project{id}
      content{... on Issue{id}}
      fieldValueByName(name:"Status"){
        ... on ProjectV2ItemFieldSingleSelectValue{name optionId}
      }
    }
  }
  rateLimit{cost remaining resetAt}
}"""

ADD_PROJECT_ITEM_MUTATION = """\
mutation($project:ID!,$content:ID!){
  addProjectV2ItemById(input:{projectId:$project,contentId:$content}){
    item{
      id isArchived project{id}
      content{... on Issue{id}}
      fieldValueByName(name:"Status"){
        ... on ProjectV2ItemFieldSingleSelectValue{name optionId}
      }
    }
  }
}"""

UPDATE_PROJECT_STATUS_MUTATION = """\
mutation($project:ID!,$item:ID!,$field:ID!,$option:String!){
  updateProjectV2ItemFieldValue(input:{
    projectId:$project,
    itemId:$item,
    fieldId:$field,
    value:{singleSelectOptionId:$option}
  }){
    projectV2Item{
      id isArchived project{id}
      content{... on Issue{id}}
      fieldValueByName(name:"Status"){
        ... on ProjectV2ItemFieldSingleSelectValue{name optionId}
      }
    }
  }
}"""

BACKGROUND_PROJECT_ITEMS_QUERY = """\
query($id:ID!,$endCursor:String){
  node(id:$id){
    ... on ProjectV2{
      items(first:100,after:$endCursor){
        nodes{
          id isArchived
          fieldValueByName(name:"Status"){
            ... on ProjectV2ItemFieldSingleSelectValue{name optionId}
          }
          content{
            ... on Issue{id number url state repository{nameWithOwner}}
          }
        }
        pageInfo{hasNextPage endCursor}
      }
    }
  }
  rateLimit{cost remaining resetAt}
}"""

MARK_PULL_REQUEST_READY_MUTATION = """\
mutation($id:ID!){
  markPullRequestReadyForReview(input:{pullRequestId:$id}){
    pullRequest{id isDraft}
  }
}"""

PULL_REQUEST_LIFECYCLE_QUERY = """\
query($owner:String!,$name:String!,$number:Int!,$endCursor:String){
  repository(owner:$owner,name:$name){
    pullRequest(number:$number){
      closingIssuesReferences(first:100,after:$endCursor){
        nodes{number url state repository{nameWithOwner}}
        pageInfo{hasNextPage endCursor}
      }
    }
  }
  rateLimit{cost remaining resetAt}
}"""

AUTHORITY_COMMENTS_QUERY = """\
query($ids:[ID!]!){
  nodes(ids:$ids){
    ... on IssueComment{
      id databaseId body createdAt lastEditedAt
      author{login ... on Node{id}}
    }
  }
  rateLimit{cost remaining resetAt}
}"""


@dataclass(frozen=True)
class GraphQLBudget:
    requests: int
    points: int


LIFECYCLE_GRAPHQL_BUDGETS = {
    "claim": GraphQLBudget(requests=9, points=40),
    "heartbeat": GraphQLBudget(requests=9, points=10),
    # Release settles exact-head evidence after the claim mutation, its
    # Project state, and the exact stale lifecycle recheck. The bounded normal
    # path is eleven requests; keeping it at ten records the release but
    # strands the automatic lifecycle recheck after the producer has done its
    # durable work (#479).
    "release": GraphQLBudget(requests=11, points=30),
    "reconcile-targeted": GraphQLBudget(requests=9, points=40),
    "check-pr": GraphQLBudget(requests=9, points=20),
    # Broad reconciliation is deliberately outside the interactive budget and
    # must run with a dedicated GitHub App installation token.
    "reconcile-background": GraphQLBudget(requests=500, points=4_000),
}

# Noncritical Project v2 coordination must leave enough primary GraphQL quota
# for one complete interactive claim -> heartbeat -> release cycle. This is a
# fresh refusal floor, not an atomic reservation: only a separately
# credentialed GitHub App has an isolated bucket.
INTERACTIVE_LIFECYCLE_RESERVE_POINTS = sum(
    LIFECYCLE_GRAPHQL_BUDGETS[name].points
    for name in ("claim", "heartbeat", "release")
)
PROJECT_SYNC_BASE_POINTS = 1  # one first-page Project metadata read
PROJECT_SYNC_POINTS_PER_ITEM = 6  # plan/read/add/read/update/verify
# A supported one-page query has one connection and a measured cost of one.
# Reserve nine additional points so an unexpected cost as high as ten is
# detected after its first response without borrowing from lifecycle capacity.
PROJECT_SYNC_COST_DRIFT_GUARD = 9


@dataclass(frozen=True)
class ProjectStatusRequest:
    issue_url: str
    status: str


@dataclass(frozen=True)
class ProjectStatusPlan:
    request: ProjectStatusRequest
    item: dict[str, Any] | None
    add_required: bool
    status_update_possible: bool

    @property
    def mutation_upper_bound(self) -> int:
        return int(self.add_required) + int(self.status_update_possible)

    @property
    def apply_point_upper_bound(self) -> int:
        # Reread, optional add, pre-update reread, optional update, readback.
        return 5 if self.add_required else 4


def _reset_time(epoch: Any) -> str:
    if isinstance(epoch, bool) or not isinstance(epoch, (int, float)):
        return "unknown"
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


class GraphQLMeter:
    """Preflight, cap, and account for every explicit GraphQL operation."""

    def __init__(
        self,
        run_json: JsonRunner,
        error_type: ErrorType,
        printer: Callable[[str], None] = print,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._run_json = run_json
        self._error_type = error_type
        self._print = printer
        self._sleep = sleeper
        self._monotonic = monotonic
        self.command: str | None = None
        self.budget: GraphQLBudget | None = None
        self.requests = 0
        self.points = 0
        self.remaining: int | None = None
        self.reset_at = "unknown"
        self.reserve_points = 0
        self.noncritical = False

    def provisional_negative_edit_cache_until(self) -> float:
        """Require one server reread after a full REST timestamp interval."""
        return self._monotonic() + 1.05

    def wait_for_authority_recheck(self, stable_at: Any) -> None:
        if isinstance(stable_at, bool) or not isinstance(stable_at, (int, float)):
            return
        delay = stable_at - self._monotonic()
        if 0 < delay <= 2:
            self._sleep(delay)

    def preflight(self, command: str) -> None:
        self._preflight_budget(command, LIFECYCLE_GRAPHQL_BUDGETS[command])

    def preflight_project_sync(self, item_count: int) -> None:
        if isinstance(item_count, bool) or not 1 <= item_count <= MAX_PROJECT_SYNC_ITEMS:
            raise self._error_type(
                f"project-sync requires 1-{MAX_PROJECT_SYNC_ITEMS} unique items"
            )
        requests = PROJECT_SYNC_BASE_POINTS + (
            item_count * PROJECT_SYNC_POINTS_PER_ITEM
        )
        points = requests + PROJECT_SYNC_COST_DRIFT_GUARD
        self._preflight_budget(
            "project-sync",
            GraphQLBudget(requests=requests, points=points),
            reserve_points=INTERACTIVE_LIFECYCLE_RESERVE_POINTS,
            noncritical=True,
        )

    def _rate_limit(self) -> tuple[int, str]:
        response = self._run_json(["gh", "api", "rate_limit"])
        resource = (
            response.get("resources", {}).get("graphql")
            if isinstance(response, dict)
            else None
        )
        if not isinstance(resource, dict):
            raise self._error_type("GitHub rate-limit preflight returned invalid state")
        remaining = resource.get("remaining")
        if isinstance(remaining, bool) or not isinstance(remaining, int):
            raise self._error_type("GitHub GraphQL remaining quota is unavailable")
        return remaining, _reset_time(resource.get("reset"))

    def _preflight_budget(
        self,
        command: str,
        budget: GraphQLBudget,
        *,
        reserve_points: int = 0,
        noncritical: bool = False,
    ) -> None:
        remaining, reset_at = self._rate_limit()
        self.command = command
        self.budget = budget
        self.requests = 0
        self.points = 0
        self.remaining = remaining
        self.reset_at = reset_at
        self.reserve_points = reserve_points
        self.noncritical = noncritical
        required = budget.points + reserve_points
        self._print(
            "graphql preflight: "
            f"command={command} request_budget={budget.requests} "
            f"point_budget={budget.points} estimated_cost={budget.points} "
            f"lifecycle_reserve={reserve_points} required={required} "
            f"remaining={remaining} "
            f"reset={self.reset_at}"
        )
        if remaining < required:
            qualifier = "deferred noncritical Project v2 coordination" \
                if noncritical else f"insufficient GitHub GraphQL quota for {command}"
            raise self._error_type(
                f"{qualifier}: planned_points={budget.points}, "
                f"lifecycle_reserve={reserve_points}, requires {required} points, "
                f"remaining {remaining}, "
                f"reset {self.reset_at}; retry at or after {self.reset_at}"
            )

    def require_noncritical_capacity(self, planned_points: int) -> None:
        if not self.noncritical or self.command != "project-sync":
            raise self._error_type(
                "noncritical GraphQL reserve guard used outside project-sync"
            )
        if isinstance(planned_points, bool) or planned_points < 1:
            raise self._error_type("project-sync reserve guard requires planned points")
        remaining, reset_at = self._rate_limit()
        self.remaining = remaining
        self.reset_at = reset_at
        required = self.reserve_points + planned_points
        self._print(
            "graphql reserve: command=project-sync "
            f"planned_points={planned_points} "
            f"lifecycle_reserve={self.reserve_points} required={required} "
            f"remaining={remaining} reset={reset_at}"
        )
        if remaining < required:
            raise self._error_type(
                "deferred noncritical Project v2 coordination before operation: "
                f"planned_points={planned_points}, "
                f"lifecycle_reserve={self.reserve_points}, requires {required} points, "
                f"remaining {remaining}, reset {reset_at}; rerun the unchanged "
                f"project-sync plan at or after {reset_at}"
            )

    def request(
        self,
        query: str,
        *,
        strings: dict[str, str] | None = None,
        integers: dict[str, int] | None = None,
        string_lists: dict[str, list[str]] | None = None,
    ) -> dict[str, Any]:
        arguments = ["gh", "api", "graphql", "-f", f"query={query}"]
        for name, value in (strings or {}).items():
            arguments.extend(["-f", f"{name}={value}"])
        for name, value in (integers or {}).items():
            arguments.extend(["-F", f"{name}={value}"])
        for name, values in (string_lists or {}).items():
            for value in values:
                arguments.extend(["-f", f"{name}[]={value}"])
        query_operation = query.lstrip().startswith("query")
        # Noncritical project-sync reads stop and resume from GitHub state on
        # any transport ambiguity so retries cannot spend the fixed reserve.
        attempts = 3 if query_operation and not self.noncritical else 1
        for attempt in range(attempts):
            if self.budget is not None and self.requests >= self.budget.requests:
                raise self._error_type(
                    f"GraphQL request regression for {self.command}: "
                    f"budget {self.budget.requests} would be exceeded"
                )
            self.requests += 1
            try:
                response = self._run_json(arguments)
            except self._error_type as exc:
                if attempt + 1 < attempts and transient_failure(str(exc)):
                    self._sleep(0.25 * (2 ** attempt))
                    continue
                self._refresh_remaining_after_failure()
                raise
            if not isinstance(response, dict):
                raise self._error_type("GitHub GraphQL operation returned invalid state")
            if query_operation:
                self._record_rate(response, attempts=attempt + 1)
            else:
                self._record_mutation_cost()
            if response.get("errors"):
                raise self._error_type("GitHub GraphQL operation returned errors")
            return response
        raise self._error_type("GitHub GraphQL query retry loop did not settle")

    def _record_rate(self, response: dict[str, Any], *, attempts: int = 1) -> None:
        rate = response.get("data", {}).get("rateLimit")
        cost = rate.get("cost") if isinstance(rate, dict) else None
        remaining = rate.get("remaining") if isinstance(rate, dict) else None
        reset_at = rate.get("resetAt") if isinstance(rate, dict) else None
        if isinstance(cost, bool) or not isinstance(cost, int) \
                or isinstance(remaining, bool) or not isinstance(remaining, int) \
                or not isinstance(reset_at, str):
            raise self._error_type(
                "GitHub GraphQL operation omitted rateLimit cost/remaining/resetAt"
            )
        # Query cost is deterministic for an identical operation and variables.
        # Conservatively charge transport retries at the successful attempt's
        # measured cost without attributing other sessions' shared-bucket use.
        self.points += cost * attempts
        self.remaining = remaining
        self.reset_at = reset_at
        if self.noncritical and cost != 1:
            raise self._error_type(
                "project-sync targeted query cost changed: "
                f"expected 1 point, measured {cost}; stopped after the first "
                "regression while retaining the lifecycle reserve. Inspect the "
                "query shape and rerun only after updating its measured budget"
            )
        if self.budget is not None and self.points > self.budget.points:
            raise self._error_type(
                f"GraphQL point regression for {self.command}: used {self.points}, "
                f"budget {self.budget.points}; retry only after inspecting the "
                "idempotent canonical state"
            )
        if self.noncritical and remaining < self.reserve_points:
            raise self._error_type(
                "deferred noncritical Project v2 coordination after a measured read: "
                f"lifecycle_reserve={self.reserve_points}, remaining {remaining}, "
                f"reset {reset_at}; rerun the unchanged project-sync plan at or "
                f"after {reset_at}"
            )

    def _record_mutation_cost(self) -> None:
        # GitHub exposes rateLimit only on the Query root. These lifecycle
        # mutations return no connections, so GitHub's cost formula assigns
        # the minimum deterministic cost of one point.
        self.points += 1
        if self.budget is not None and self.points > self.budget.points:
            raise self._error_type(
                f"GraphQL point regression for {self.command}: used {self.points}, "
                f"budget {self.budget.points}; retry only after inspecting the "
                "idempotent canonical state"
            )

    def _refresh_remaining_after_failure(self) -> None:
        try:
            response = self._run_json(["gh", "api", "rate_limit"])
        except self._error_type:
            return
        resource = (
            response.get("resources", {}).get("graphql")
            if isinstance(response, dict) else None
        )
        remaining = resource.get("remaining") if isinstance(resource, dict) else None
        if isinstance(remaining, bool) or not isinstance(remaining, int):
            return
        self.remaining = remaining
        self.reset_at = _reset_time(resource.get("reset"))

    def summary(self) -> str | None:
        if self.command is None:
            return None
        return (
            "graphql accounting: "
            f"command={self.command} requests={self.requests} cost={self.points} "
            f"remaining={self.remaining if self.remaining is not None else 'unknown'} "
            f"reset={self.reset_at}"
        )


def issue_reference(value: str) -> tuple[str, str]:
    match = re.fullmatch(
        r"https://github\.com/([^/]+/[^/]+)/issues/([1-9][0-9]*)/?", value
    )
    if not match:
        raise ValueError(f"invalid GitHub issue URL: {value}")
    return match.group(1), match.group(2)


def project_status_requests(values: list[Any]) -> list[ProjectStatusRequest]:
    if not 1 <= len(values) <= MAX_PROJECT_SYNC_ITEMS:
        raise ValueError(
            f"project-sync requires 1-{MAX_PROJECT_SYNC_ITEMS} unique items"
        )
    requests: list[ProjectStatusRequest] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, (list, tuple)) or len(value) != 2:
            raise ValueError("each project-sync --item requires ISSUE_URL and STATUS")
        raw_issue_url = str(value[0]).rstrip("/")
        status = str(value[1])
        repository, number = issue_reference(raw_issue_url)
        issue_url = f"https://github.com/{repository.lower()}/issues/{number}"
        if status not in PROJECT_SYNC_STATUSES:
            allowed = ", ".join(sorted(PROJECT_SYNC_STATUSES))
            raise ValueError(
                f"project-sync status {status!r} is not a pre-implementation "
                f"status; choose one of: {allowed}"
            )
        if issue_url in seen:
            raise ValueError(f"duplicate project-sync issue: {issue_url}")
        seen.add(issue_url)
        requests.append(ProjectStatusRequest(issue_url=issue_url, status=status))
    return requests


def rest_issue_timeline_state(
    run_json: JsonRunner,
    error_type: ErrorType,
    repository: str,
    number: str,
    raw: dict[str, Any],
) -> dict[str, Any]:
    """Classify canonical issue and claim generations from its REST timeline."""
    issue = {
        "id": raw.get("node_id"),
        "databaseId": raw.get("id"),
        "number": raw.get("number"),
        "url": raw.get("html_url"),
        "labels": raw.get("labels", []),
        "state": str(raw.get("state") or "").upper(),
        # Server-owned closure identity: cleared on reopen and set anew on
        # every close, so it distinguishes closure incarnations (#385).
        "closedAt": raw.get("closed_at"),
    }
    pages = run_json([
        "gh", "api", f"repos/{repository}/issues/{number}/timeline?per_page=100",
        "-H", "Accept: application/vnd.github+json",
        "--paginate", "--slurp",
    ])
    if not isinstance(pages, list):
        raise error_type(f"issue #{number} timeline returned an invalid response")
    timeline = [event for page in pages for event in page] \
        if pages and isinstance(pages[0], list) else pages
    if not all(isinstance(event, dict) for event in timeline):
        raise error_type(f"issue #{number} timeline returned an invalid page")
    try:
        comments = lifecycle.apply_issue_timeline(issue, timeline)
    except ValueError as exc:
        raise error_type(f"issue #{number} {exc}") from exc
    issue["comments"] = []
    for comment in comments:
        created = comment.get("created_at") or comment.get("createdAt")
        updated = comment.get("updated_at") or comment.get("updatedAt")
        issue["comments"].append({
            **comment,
            "id": comment.get("node_id") or comment.get("id"),
            "databaseId": comment.get("databaseId") or comment.get("id"),
            "createdAt": created,
            "lastEditedAt": updated if updated and updated != created else None,
            "authorLogin": comment.get("authorLogin")
            or (comment.get("author") or {}).get("login")
            or (comment.get("user") or {}).get("login"),
            "authorNodeId": comment.get("authorNodeId")
            or (comment.get("author") or {}).get("node_id")
            or (comment.get("user") or {}).get("node_id"),
            "authorAssociation": comment.get("authorAssociation")
            or comment.get("author_association"),
        })
    return issue


def issue_state(
    run_json: JsonRunner,
    error_type: ErrorType,
    repository: str,
    number: str,
    graphql: GraphQLMeter,
    authority_cache: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Read canonical issue authority entirely from REST."""
    raw = run_json(["gh", "api", f"repos/{repository}/issues/{number}"])
    if not isinstance(raw, dict) or not raw.get("node_id") \
            or raw.get("pull_request") is not None:
        raise error_type(f"issue #{number} REST state is invalid")
    issue = rest_issue_timeline_state(
        run_json, error_type, repository, number, raw,
    )
    _verify_authority_comments(issue["comments"], graphql, authority_cache, error_type)
    return issue


def same_author_login(rest_login: Any, graphql_login: Any) -> bool:
    """Match GitHub's REST and GraphQL spellings for one authenticated App.

    REST appends ``[bot]`` to an App account's login while GraphQL returns the
    App slug.  The node-id comparison below still binds the two views to the
    same server-owned actor; this only normalizes that documented display
    difference.
    """
    rest = str(rest_login or "")
    graphql = str(graphql_login or "")
    return rest == graphql or (
        rest.endswith("[bot]") and rest.removesuffix("[bot]") == graphql
    )


def _verify_authority_comments(
    comments: list[dict[str, Any]],
    graphql: GraphQLMeter,
    cache: dict[str, dict[str, Any]],
    error_type: ErrorType,
) -> None:
    unreleased_claims = {
        str(comment.get("id") or "")
        for comment in comments
        if (payload := lifecycle.parse_marked(
            str(comment.get("body") or ""),
            lifecycle.CLAIM_MARKER,
            "hv-agent-claim:v1",
        )) is not None and not payload.get("released_at")
    }

    def requires_edit_verification(comment: dict[str, Any]) -> bool:
        node_id = str(comment.get("id") or "")
        body = str(comment.get("body") or "")
        claim = lifecycle.parse_marked(
            body, lifecycle.CLAIM_MARKER, "hv-agent-claim:v1",
        )
        if claim is not None:
            return node_id in unreleased_claims
        for marker, schema in (
            (lifecycle.HEARTBEAT_MARKER, "hv-agent-heartbeat:v1"),
            (lifecycle.OWNER_REPAIR_MARKER, "hv-agent-claim-owner-repair:v1"),
        ):
            payload = lifecycle.parse_marked(body, marker, schema)
            if payload is not None:
                return str(payload.get("claim_comment_id") or "") in unreleased_claims
        return False

    pending: list[tuple[dict[str, Any], tuple[Any, ...], bool]] = []
    for comment in comments:
        if not requires_edit_verification(comment):
            continue
        node_id = str(comment.get("id") or "")
        fingerprint = (
            comment.get("body"), comment.get("createdAt"),
            comment.get("lastEditedAt"), comment.get("databaseId"),
            comment.get("authorLogin"), comment.get("authorNodeId"),
            comment.get("authorAssociation"),
        )
        cached = cache.get(node_id)
        if cached is not None and cached.get("fingerprint") == fingerprint:
            stable_at = cached.get("negative_stable_at")
            if stable_at is None:
                comment.update(cached["verified"])
                continue
            graphql.wait_for_authority_recheck(stable_at)
            pending.append((comment, fingerprint, True))
            continue
        pending.append((comment, fingerprint, False))
    for offset in range(0, len(pending), 100):
        chunk = pending[offset:offset + 100]
        response = graphql.request(
            AUTHORITY_COMMENTS_QUERY,
            string_lists={
                "ids": [str(comment["id"]) for comment, _, _recheck in chunk],
            },
        )
        nodes = response.get("data", {}).get("nodes")
        if not isinstance(nodes, list) or len(nodes) != len(chunk):
            raise error_type("authority comment GraphQL verification is incomplete")
        by_id = {
            str(node.get("id")): node
            for node in nodes
            if isinstance(node, dict) and node.get("id")
        }
        for comment, fingerprint, negative_recheck in chunk:
            node_id = str(comment.get("id") or "")
            node = by_id.get(node_id)
            author = node.get("author") if isinstance(node, dict) else None
            if not isinstance(node, dict) \
                    or str(node.get("databaseId") or "") != str(comment.get("databaseId") or "") \
                    or node.get("body") != comment.get("body") \
                    or node.get("createdAt") != comment.get("createdAt") \
                    or not isinstance(author, dict) \
                    or str(author.get("id") or "") != str(comment.get("authorNodeId") or "") \
                    or not same_author_login(
                        comment.get("authorLogin"), author.get("login"),
                    ):
                raise error_type(
                    f"authority comment {node_id or 'unknown'} changed between REST and "
                    "GraphQL verification; reread GitHub"
                )
            verified = {"lastEditedAt": node.get("lastEditedAt")}
            comment.update(verified)
            stable_at = None
            if verified["lastEditedAt"] is None and not negative_recheck:
                stable_at = graphql.provisional_negative_edit_cache_until()
            cache[node_id] = {
                "fingerprint": fingerprint,
                "verified": verified,
                "negative_stable_at": stable_at,
            }


def pull_request_state(
    run_json: JsonRunner,
    error_type: ErrorType,
    repository: str,
    number: str,
) -> dict[str, Any]:
    """Read PR labels, ready state, body, branch, and head through REST."""
    raw = run_json(["gh", "api", f"repos/{repository}/pulls/{number}"])
    if not isinstance(raw, dict) or not raw.get("node_id"):
        raise error_type(f"PR #{number} REST state is invalid")
    return {
        **raw,
        "id": raw.get("node_id"),
        "number": raw.get("number"),
        "isDraft": bool(raw.get("draft")),
        "state": str(raw.get("state") or "").upper(),
        "body": raw.get("body") or "",
        "headRefName": (raw.get("head") or {}).get("ref"),
        "headRefOid": (raw.get("head") or {}).get("sha"),
        "baseRefName": (raw.get("base") or {}).get("ref"),
        "baseRefOid": (raw.get("base") or {}).get("sha"),
        "baseRepositoryDefaultBranch": (
            ((raw.get("base") or {}).get("repo") or {}).get("default_branch")
        ),
        "labels": raw.get("labels", []),
    }


def pull_request_commits(
    run_json: JsonRunner,
    error_type: ErrorType,
    repository: str,
    number: str,
) -> list[dict[str, Any]]:
    """Read every commit message on a PR branch through REST.

    GitHub caps this endpoint at 250 commits. A branch longer than that is well
    outside the reviewable shape this policy expects, and the closing-keyword
    guard degrades to scanning the first page rather than failing the check.
    """
    pages = run_json([
        "gh", "api", f"repos/{repository}/pulls/{number}/commits?per_page=100",
        "--paginate", "--slurp",
    ])
    if not isinstance(pages, list):
        raise error_type(f"PR #{number} commits returned an invalid response")
    commits = [commit for page in pages for commit in page] \
        if pages and isinstance(pages[0], list) else pages
    if not all(isinstance(commit, dict) for commit in commits):
        raise error_type(f"PR #{number} commits returned an invalid page")
    return [
        {
            "sha": str(commit.get("sha") or ""),
            "message": str((commit.get("commit") or {}).get("message") or ""),
        }
        for commit in commits
    ]


def _revision_text(
    run_json: JsonRunner, repository: str, path: str, oid: str,
) -> str | None:
    """Read one UTF-8 file at an exact revision; None when unreadable."""
    response = run_json([
        "gh", "api",
        f"repos/{repository}/contents/{path}?ref={quote(oid, safe='')}",
    ])
    if not isinstance(response, dict) or response.get("encoding") != "base64" \
            or not isinstance(response.get("content"), str):
        return None
    try:
        encoded = "".join(response["content"].split())
        return base64.b64decode(encoded, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def _migration_bootstrap_selector(
    run_json: JsonRunner,
    repository: str,
    pull_request: dict[str, Any],
    base_runtime: dict[str, Any],
    canonical_lifecycle: Callable[[dict[str, Any]], bytes] | None,
) -> str | None:
    """Return the head validation selector for a canonical migration PR.

    A repository whose protected base predates the split lifecycle layout can
    never satisfy the base validation contract from inside its own migration
    pull request: the PR repairs the validation workflow, but the base audit
    keeps rejecting the base revision it is about to replace. Accept exactly
    the bootstrap shape the migrator produces — the base manifest has no
    runtime.agent_validation_workflow selector yet, while the head revision
    declares a valid selector, the head validation workflow satisfies the
    full validation contract, and the head's dedicated lifecycle workflow is
    byte-identical to the canonical render for the head manifest. Anything
    less, including any read or render failure, fails closed to the original
    base-audit error.
    """
    if canonical_lifecycle is None:
        return None
    if base_runtime.get("agent_validation_workflow") is not None:
        return None
    head_oid = str(pull_request.get("headRefOid") or "")
    base_ref_name = str(pull_request.get("baseRefName") or "")
    if not lifecycle.GIT_OID_PATTERN.fullmatch(head_oid) or not base_ref_name:
        return None
    try:
        manifest_text = _revision_text(
            run_json, repository, ".agents/project.yaml", head_oid,
        )
        if manifest_text is None:
            return None
        manifest = json.loads(manifest_text)
        if not isinstance(manifest, dict):
            return None
        runtime = manifest.get("runtime")
        if not isinstance(runtime, dict):
            return None
        selector = runtime.get("agent_validation_workflow")
        if not isinstance(selector, str) \
                or not AGENT_POLICY_WORKFLOW_PATTERN.fullmatch(selector) \
                or selector == DEDICATED_LIFECYCLE_WORKFLOW:
            return None
        validation_text = _revision_text(run_json, repository, selector, head_oid)
        if validation_text is None:
            return None
        if lifecycle.validation_workflow_trigger_errors(validation_text) \
                or lifecycle.validation_workflow_base_errors(
                    validation_text, base_ref_name,
                ):
            return None
        lifecycle_text = _revision_text(
            run_json, repository, DEDICATED_LIFECYCLE_WORKFLOW, head_oid,
        )
        if lifecycle_text is None:
            return None
        if lifecycle_text.encode("utf-8") != canonical_lifecycle(manifest):
            return None
        return selector
    except Exception:
        return None


def validation_workflow_evidence(
    run_json: JsonRunner,
    error_type: ErrorType,
    repository: str,
    pull_request: dict[str, Any],
    *,
    require_selector: bool = False,
    canonical_lifecycle: Callable[[dict[str, Any]], bytes] | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    """Read the protected-base validation contract and PR timeline through REST."""
    number = pull_request.get("number")
    base_oid = str(pull_request.get("baseRefOid") or "")
    head_oid = str(pull_request.get("headRefOid") or "")
    if isinstance(number, bool) or not isinstance(number, int) or number < 1 \
            or not lifecycle.GIT_OID_PATTERN.fullmatch(base_oid) \
            or not lifecycle.GIT_OID_PATTERN.fullmatch(head_oid):
        raise error_type(
            "pull request lacks a valid number and current head/base revision pair; "
            "reread GitHub"
        )
    raw = run_json([
        "gh", "api",
        f"repos/{repository}/contents/.agents/project.yaml?ref={quote(base_oid, safe='')}",
    ])
    if not isinstance(raw, dict) or raw.get("encoding") != "base64" \
            or not isinstance(raw.get("content"), str):
        raise error_type(
            f"base revision {base_oid} lacks readable .agents/project.yaml policy"
        )
    try:
        encoded = "".join(raw["content"].split())
        manifest = json.loads(base64.b64decode(encoded, validate=True))
    except (ValueError, json.JSONDecodeError) as exc:
        raise error_type(
            f"base revision {base_oid} has invalid .agents/project.yaml policy: {exc}"
        ) from exc
    if not isinstance(manifest, dict):
        raise error_type(f"base revision {base_oid} project policy is not an object")
    runtime = manifest.get("runtime")
    if runtime is not None and not isinstance(runtime, dict):
        raise error_type(f"base revision {base_oid} has invalid runtime policy")
    runtime = runtime or {}
    selector = runtime.get("agent_validation_workflow")
    if selector is None:
        # The compatibility migration PR necessarily runs against a base that
        # still names the folded workflow. Do not use this fallback once the
        # explicit validation selector exists on the protected base.
        selector = runtime.get("agent_policy_workflow")
    if selector is None:
        github_policy = manifest.get("github") or {}
        checks = github_policy.get("required_status_checks", []) \
            if isinstance(github_policy, dict) else []
        if not checks and not require_selector:
            return "", []
    if not isinstance(selector, str) or not AGENT_POLICY_WORKFLOW_PATTERN.fullmatch(selector) \
            or selector == DEDICATED_LIFECYCLE_WORKFLOW:
        raise error_type(
            f"base revision {base_oid} has no valid non-lifecycle code-validation workflow"
        )
    workflow_response = run_json([
        "gh", "api",
        f"repos/{repository}/contents/{selector}?ref={quote(base_oid, safe='')}",
    ])
    if not isinstance(workflow_response, dict) \
            or workflow_response.get("encoding") != "base64" \
            or not isinstance(workflow_response.get("content"), str):
        raise error_type(
            f"base revision {base_oid} lacks readable {selector} validation policy"
        )
    try:
        workflow_encoded = "".join(workflow_response["content"].split())
        workflow_text = base64.b64decode(workflow_encoded, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise error_type(
            f"base revision {base_oid} has invalid {selector} validation policy"
        ) from exc
    contract_errors = lifecycle.validation_workflow_trigger_errors(workflow_text)
    contract_errors.extend(
        lifecycle.validation_workflow_base_errors(
            workflow_text, str(pull_request.get("baseRefName") or ""),
        )
    )
    if contract_errors:
        bootstrap_selector = _migration_bootstrap_selector(
            run_json, repository, pull_request, runtime, canonical_lifecycle,
        )
        if bootstrap_selector is None:
            message = (
                f"base revision {base_oid} {selector} cannot guarantee full validation: "
                + "; ".join(contract_errors)
            )
            if runtime.get("agent_validation_workflow") is None:
                # Only a base that predates the split layout is eligible for
                # the migration bootstrap; on a migrated base the failure is
                # a validation-workflow regression, not a migration problem.
                message += (
                    "; a migration pull request bootstraps only when its head is "
                    "migrator-canonical (run scripts/hv-agent migrate-repo . "
                    "--profile happyvertical --apply and push the regenerated layout)"
                )
            raise error_type(message)
        print(
            f"WARNING base revision {base_oid} {selector} predates the split "
            f"lifecycle layout; accepting migrator-canonical head {head_oid} "
            "as the one-time migration bootstrap",
            file=sys.stderr,
        )
        selector = bootstrap_selector
    pages = run_json([
        "gh", "api", f"repos/{repository}/issues/{number}/timeline?per_page=100",
        "-H", "Accept: application/vnd.github+json",
        "--paginate", "--slurp",
    ])
    if not isinstance(pages, list):
        raise error_type("pull request timeline returned invalid REST state")
    timeline = [event for page in pages for event in page] \
        if pages and isinstance(pages[0], list) else pages
    if not all(isinstance(event, dict) for event in timeline):
        raise error_type("pull request timeline returned an invalid REST page")
    return selector, timeline


def project_coordinates(project_url: str) -> tuple[str, str, int] | None:
    match = re.fullmatch(
        r"https://github\.com/(orgs|users)/([^/]+)/projects/([1-9][0-9]*)",
        project_url.rstrip("/"),
    )
    if not match:
        return None
    owner_kind = "organization" if match.group(1) == "orgs" else "user"
    return owner_kind, match.group(2), int(match.group(3))


class ProjectV2Client:
    """Issue-targeted Project v2 access with process-local metadata caching."""

    def __init__(
        self,
        run_json: JsonRunner,
        graphql: GraphQLMeter,
        error_type: ErrorType,
    ) -> None:
        self._run_json = run_json
        self._graphql = graphql
        self._error_type = error_type
        self._metadata: dict[str, dict[str, Any]] = {}
        self._issues: dict[str, dict[str, Any]] = {}
        self._issue_nodes: dict[str, str] = {}
        self._items: dict[tuple[str, str], dict[str, Any] | None] = {}
        self._item_cursors: dict[tuple[str, str], str] = {}

    @staticmethod
    def _metadata_value(
        project_url: str,
        owner_kind: str,
        owner: str,
        number: int,
        project: dict[str, Any],
        status_field: dict[str, Any],
    ) -> dict[str, Any]:
        options = {
            str(option.get("name")): str(option.get("id"))
            for option in status_field.get("options", [])
            if isinstance(option, dict) and option.get("name") and option.get("id")
        }
        return {
            "url": project_url,
            "owner_kind": owner_kind,
            "owner": owner,
            "number": str(number),
            "project_id": str(project["id"]),
            "title": str(project.get("title") or ""),
            "field_id": str(status_field["id"]),
            "options": options,
        }

    def metadata(
        self,
        manifest: dict[str, Any],
        *,
        single_page: bool = False,
    ) -> dict[str, Any] | None:
        project_url = manifest.get("tracker", {}).get("project_url")
        if not project_url:
            return None
        project_url = str(project_url)
        if project_url in self._metadata:
            return self._metadata[project_url]
        coordinates = project_coordinates(project_url)
        if coordinates is None:
            raise self._error_type(f"unsupported tracker.project_url: {project_url}")
        owner_kind, owner, number = coordinates
        query = (
            PROJECT_METADATA_ORGANIZATION_QUERY
            if owner_kind == "organization"
            else PROJECT_METADATA_USER_QUERY
        )
        cursor: str | None = None
        project: dict[str, Any] | None = None
        status_field: dict[str, Any] | None = None
        for _page in range(MAX_PROJECT_FIELD_PAGES):
            strings = {"owner": owner}
            if cursor is not None:
                strings["endCursor"] = cursor
            response = self._graphql.request(
                query, strings=strings, integers={"number": number}
            )
            owner_data = response.get("data", {}).get(owner_kind)
            current = owner_data.get("projectV2") if isinstance(owner_data, dict) else None
            if not isinstance(current, dict):
                raise self._error_type(f"project {project_url} could not be resolved")
            project = current
            fields = current.get("fields")
            nodes = fields.get("nodes") if isinstance(fields, dict) else None
            page_info = fields.get("pageInfo") if isinstance(fields, dict) else None
            if not isinstance(nodes, list) or not isinstance(page_info, dict):
                raise self._error_type(f"project {project_url} fields are incomplete")
            status_field = next(
                (field for field in nodes if isinstance(field, dict)
                 and field.get("name") == "Status"),
                status_field,
            )
            if status_field is not None or not page_info.get("hasNextPage"):
                break
            if single_page:
                raise self._error_type(
                    "project-sync requires the Project Status field in the first "
                    "100 fields; use the dedicated/background Project lane for "
                    "broader discovery"
                )
            cursor = page_info.get("endCursor")
            if not isinstance(cursor, str) or not cursor:
                raise self._error_type(f"project {project_url} field pagination is invalid")
        else:
            raise self._error_type(
                f"project {project_url} exceeds {MAX_PROJECT_FIELD_PAGES} field pages"
            )
        if project is None or status_field is None:
            raise self._error_type(f"project {project_url} has no Status field")
        value = self._metadata_value(
            project_url, owner_kind, owner, number, project, status_field,
        )
        self._metadata[project_url] = value
        return value

    def status_target(
        self, manifest: dict[str, Any], status: str,
    ) -> dict[str, str] | None:
        metadata = self.metadata(manifest)
        if metadata is None:
            return None
        option_id = metadata["options"].get(status)
        if not option_id:
            raise self._error_type(
                f"project {metadata['url']} has no Status option {status!r}"
            )
        return {
            **{key: str(value) for key, value in metadata.items() if key != "options"},
            "option_id": str(option_id),
        }

    def issue_resource(
        self, issue_url: str, *, refresh: bool = False,
    ) -> dict[str, Any]:
        if not refresh and issue_url in self._issues:
            return self._issues[issue_url]
        try:
            repository, number = issue_reference(issue_url)
        except ValueError as exc:
            raise self._error_type(str(exc)) from exc
        raw = self._run_json(["gh", "api", f"repos/{repository}/issues/{number}"])
        node_id = raw.get("node_id") if isinstance(raw, dict) else None
        if not isinstance(node_id, str) or not node_id:
            raise self._error_type(f"issue {issue_url} lacks a REST node_id")
        if raw.get("pull_request") is not None:
            raise self._error_type(f"project-sync target {issue_url} is a pull request")
        self._issues[issue_url] = raw
        self._issue_nodes[issue_url] = node_id
        return raw

    def issue_node_id(self, issue_url: str) -> str:
        if issue_url in self._issue_nodes:
            return self._issue_nodes[issue_url]
        raw = self.issue_resource(issue_url)
        node_id = str(raw["node_id"])
        return node_id

    def require_sync_safe_issue(self, issue_url: str) -> dict[str, Any]:
        raw = self.issue_resource(issue_url, refresh=True)
        if str(raw.get("state") or "").lower() != "open":
            raise self._error_type(
                f"project-sync refuses closed issue {issue_url}; reconcile its "
                "canonical project state instead"
            )
        labels = {
            str(label.get("name"))
            for label in raw.get("labels", [])
            if isinstance(label, dict) and label.get("name")
        }
        if "agent: implementation" in labels:
            raise self._error_type(
                f"project-sync refuses claimed issue {issue_url}; lifecycle owns "
                "its In Progress/Review transition"
            )
        if lifecycle.BLOCKED_LABEL in labels:
            raise self._error_type(
                f"project-sync refuses blocked issue {issue_url}; resolve the blocker "
                "and use targeted lifecycle reconciliation"
            )
        repository, number = issue_reference(issue_url)
        authority = rest_issue_timeline_state(
            self._run_json, self._error_type, repository, number, raw,
        )
        records, errors = lifecycle.claim_comment_records(authority)
        current_records = [
            pair for pair in records if lifecycle.claim_pair_current(pair)
        ]
        unreleased_records = [
            pair for pair in records if not pair[1].get("released_at")
        ]
        preimplementation_releases = {
            "abandoned", "expired", "duplicate", "race-lost",
        }
        blocking_current = [
            pair for pair in current_records
            if not pair[1].get("released_at")
            or pair[1].get("release_reason") not in preimplementation_releases
        ]
        if errors or blocking_current or unreleased_records:
            detail = errors[0] if errors else (
                "a current lifecycle-owned claim cycle" if blocking_current
                else "an unreleased historical claim cycle"
            )
            raise self._error_type(
                f"project-sync refuses {issue_url} with canonical claim history "
                f"({detail}); run targeted claim/release/reconcile instead"
            )
        return raw

    def _prime_metadata_and_item(
        self,
        issue_url: str,
        manifest: dict[str, Any],
    ) -> None:
        """Prime Project metadata and one exact filtered item page together."""
        project_url_value = manifest.get("tracker", {}).get("project_url")
        if not project_url_value:
            return
        project_url = str(project_url_value)
        if project_url in self._metadata:
            return
        coordinates = project_coordinates(project_url)
        if coordinates is None:
            raise self._error_type(f"unsupported tracker.project_url: {project_url}")
        owner_kind, owner, number = coordinates
        issue_id = self.issue_node_id(issue_url)
        query = (
            PROJECT_METADATA_AND_PROJECT_ITEMS_ORGANIZATION_QUERY
            if owner_kind == "organization"
            else PROJECT_METADATA_AND_PROJECT_ITEMS_USER_QUERY
        )
        response = self._graphql.request(
            query,
            strings={
                "owner": owner,
                "itemQuery": self._project_item_filter(issue_url),
            },
            integers={"number": number},
        )
        owner_data = response.get("data", {}).get(owner_kind)
        project = owner_data.get("projectV2") if isinstance(owner_data, dict) else None
        if not isinstance(project, dict) or not project.get("id"):
            raise self._error_type(f"project {project_url} could not be resolved")
        fields = project.get("fields")
        field_nodes = fields.get("nodes") if isinstance(fields, dict) else None
        field_page = fields.get("pageInfo") if isinstance(fields, dict) else None
        if not isinstance(field_nodes, list) or not isinstance(field_page, dict):
            raise self._error_type(f"project {project_url} fields are incomplete")
        status_field = next(
            (
                field for field in field_nodes
                if isinstance(field, dict) and field.get("name") == "Status"
            ),
            None,
        )
        if status_field is None:
            # The bounded metadata paginator handles uncommon projects whose
            # Status field is beyond the first 100 fields.
            return
        metadata = self._metadata_value(
            project_url, owner_kind, owner, number, project, status_field,
        )
        self._metadata[project_url] = metadata

        items = project.get("items")
        item_nodes = items.get("nodes") if isinstance(items, dict) else None
        item_page = items.get("pageInfo") if isinstance(items, dict) else None
        if not isinstance(item_nodes, list) or not isinstance(item_page, dict):
            raise self._error_type(
                f"project {project_url} filtered items for {issue_url} are incomplete"
            )
        key = (str(metadata["project_id"]), issue_id)
        value = self._matching_item_value(
            item_nodes, str(metadata["project_id"]), issue_id, issue_url,
        )
        if value is not None:
            self._items[key] = value
            return
        if not item_page.get("hasNextPage"):
            self._items[key] = None
            return
        cursor = item_page.get("endCursor")
        if not isinstance(cursor, str) or not cursor:
            raise self._error_type(
                f"project item filter pagination for {issue_url} is invalid"
            )
        self._item_cursors[key] = cursor

    @staticmethod
    def _project_item_filter(issue_url: str) -> str:
        repository, number = issue_reference(issue_url)
        return f"repo:{repository} is:issue #{number}"

    def _item_value(
        self,
        item: Any,
        project_id: str,
        issue_id: str,
        issue_url: str,
    ) -> dict[str, Any] | None:
        if not isinstance(item, dict):
            return None
        if item.get("isArchived") is True:
            return None
        content = item.get("content")
        if not isinstance(content, dict) or str(content.get("id")) != issue_id:
            return None
        project = item.get("project")
        if not isinstance(project, dict) or str(project.get("id")) != project_id:
            raise self._error_type(
                f"project item for {issue_url} does not belong to the declared project"
            )
        item_id = item.get("id")
        if not isinstance(item_id, str) or not item_id:
            raise self._error_type(f"project item for {issue_url} has no identity")
        field = item.get("fieldValueByName")
        return {
            "id": item_id,
            "status": field.get("name") if isinstance(field, dict) else None,
            "option_id": field.get("optionId") if isinstance(field, dict) else None,
        }

    def _matching_item_value(
        self,
        nodes: list[Any],
        project_id: str,
        issue_id: str,
        issue_url: str,
    ) -> dict[str, Any] | None:
        matches = [
            value for item in nodes
            if (value := self._item_value(
                item, project_id, issue_id, issue_url,
            )) is not None
        ]
        if len(matches) > 1:
            raise self._error_type(
                f"project {project_id} returned duplicate items for {issue_url}"
            )
        return matches[0] if matches else None

    def _refresh_item(
        self,
        issue_url: str,
        project_id: str,
        issue_id: str,
        item_id: str,
    ) -> dict[str, Any] | None:
        response = self._graphql.request(
            PROJECT_ITEM_QUERY, strings={"item": item_id},
        )
        node = response.get("data", {}).get("node")
        key = (project_id, issue_id)
        if node is None:
            self._items[key] = None
            return None
        if isinstance(node, dict) and node.get("isArchived") is True:
            self._items[key] = None
            return None
        value = self._item_value(node, project_id, issue_id, issue_url)
        if value is None or value["id"] != item_id:
            raise self._error_type(
                f"project item {item_id} no longer identifies {issue_url}"
            )
        self._items[key] = value
        return value

    def item(
        self,
        issue_url: str,
        manifest: dict[str, Any],
        *,
        refresh: bool = False,
        single_page: bool = False,
    ) -> dict[str, Any] | None:
        project_url = manifest.get("tracker", {}).get("project_url")
        if project_url and str(project_url) not in self._metadata:
            self._prime_metadata_and_item(issue_url, manifest)
        metadata = self.metadata(manifest)
        if metadata is None:
            return None
        issue_id = self.issue_node_id(issue_url)
        key = (str(metadata["project_id"]), issue_id)
        cached = self._items.get(key)
        if refresh and isinstance(cached, dict):
            return self._refresh_item(
                issue_url,
                str(metadata["project_id"]),
                issue_id,
                str(cached["id"]),
            )
        if not refresh and key in self._items:
            return self._items[key]
        cursor: str | None = self._item_cursors.pop(key, None)
        for _page in range(MAX_TARGETED_PROJECT_ITEM_PAGES):
            strings = {
                "project": str(metadata["project_id"]),
                "itemQuery": self._project_item_filter(issue_url),
            }
            if cursor is not None:
                strings["endCursor"] = cursor
            response = self._graphql.request(PROJECT_ITEMS_QUERY, strings=strings)
            node = response.get("data", {}).get("node")
            items = node.get("items") if isinstance(node, dict) else None
            nodes = items.get("nodes") if isinstance(items, dict) else None
            page_info = items.get("pageInfo") if isinstance(items, dict) else None
            if not isinstance(nodes, list) or not isinstance(page_info, dict):
                raise self._error_type(
                    f"project {metadata['url']} filtered items for {issue_url} "
                    "are incomplete"
                )
            value = self._matching_item_value(
                nodes, str(metadata["project_id"]), issue_id, issue_url,
            )
            if value is not None:
                self._items[key] = value
                return value
            if not page_info.get("hasNextPage"):
                self._items[key] = None
                return None
            if single_page:
                raise self._error_type(
                    f"project-sync supports only the first 100 filtered Project item "
                    f"matches for {issue_url}; use the dedicated/background Project "
                    "lane or targeted lifecycle reconciliation"
                )
            cursor = page_info.get("endCursor")
            if not isinstance(cursor, str) or not cursor:
                raise self._error_type(
                    f"project item filter pagination for {issue_url} is invalid"
                )
        raise self._error_type(
            f"project item lookup for {issue_url} exceeds "
            f"{MAX_TARGETED_PROJECT_ITEM_PAGES} pages"
        )

    def status(
        self,
        issue_url: str,
        manifest: dict[str, Any],
        *,
        refresh: bool = False,
    ) -> str | None:
        item = self.item(issue_url, manifest, refresh=refresh)
        status = item.get("status") if isinstance(item, dict) else None
        return str(status) if status else None

    def _add_item(
        self,
        issue_url: str,
        issue_id: str,
        target: dict[str, str],
    ) -> dict[str, Any]:
        response = self._graphql.request(
            ADD_PROJECT_ITEM_MUTATION,
            strings={"project": target["project_id"], "content": issue_id},
        )
        added = response.get("data", {}).get("addProjectV2ItemById", {}).get("item")
        item = self._item_value(
            added, target["project_id"], issue_id, issue_url,
        )
        if item is None:
            raise self._error_type(
                f"could not add or find {issue_url} in the declared project"
            )
        self._items[(target["project_id"], issue_id)] = item
        return item

    def _update_status(
        self,
        issue_url: str,
        item: dict[str, Any],
        status: str,
        target: dict[str, str],
        issue_id: str,
    ) -> dict[str, Any]:
        response = self._graphql.request(
            UPDATE_PROJECT_STATUS_MUTATION,
            strings={
                "project": target["project_id"],
                "item": str(item["id"]),
                "field": target["field_id"],
                "option": target["option_id"],
            },
        )
        updated = response.get("data", {}).get(
            "updateProjectV2ItemFieldValue", {}
        ).get("projectV2Item")
        value = self._item_value(
            updated, target["project_id"], issue_id, issue_url,
        )
        if value is None or value["id"] != str(item["id"]) \
                or value["status"] != status \
                or value["option_id"] != target["option_id"]:
            raise self._error_type(
                f"project Status={status} mutation did not settle item {item['id']}"
            )
        self._items[(target["project_id"], issue_id)] = value
        return value

    def set_status(
        self,
        issue_url: str,
        status: str,
        manifest: dict[str, Any],
    ) -> None:
        target = self.status_target(manifest, status)
        if target is None:
            return
        issue_id = self.issue_node_id(issue_url)
        item = self.item(issue_url, manifest)
        if item is None:
            item = self._add_item(issue_url, issue_id, target)
        if item.get("status") != status:
            self._update_status(issue_url, item, status, target, issue_id)

    def project_sync(
        self,
        requests: list[ProjectStatusRequest],
        manifest: dict[str, Any],
        *,
        apply: bool,
        printer: Callable[[str], None] = print,
    ) -> dict[str, Any]:
        projected_points = PROJECT_SYNC_BASE_POINTS + (
            len(requests) * PROJECT_SYNC_POINTS_PER_ITEM
        )
        self._graphql.require_noncritical_capacity(
            projected_points + PROJECT_SYNC_COST_DRIFT_GUARD
        )
        metadata = self.metadata(manifest, single_page=True)
        if metadata is None:
            raise self._error_type(
                "project-sync requires tracker.project_url for a declared Project v2 tracker"
            )
        supported_remaining = projected_points - PROJECT_SYNC_BASE_POINTS

        plans: list[ProjectStatusPlan] = []
        seen_nodes: dict[str, str] = {}
        for request in requests:
            raw = self.require_sync_safe_issue(request.issue_url)
            node_id = str(raw["node_id"])
            previous = seen_nodes.get(node_id)
            if previous is not None:
                raise self._error_type(
                    f"project-sync issue aliases {previous} and {request.issue_url} "
                    "resolve to the same GitHub node; keep exactly one target"
                )
            seen_nodes[node_id] = request.issue_url
            self._graphql.require_noncritical_capacity(
                supported_remaining + PROJECT_SYNC_COST_DRIFT_GUARD
            )
            item = self.item(request.issue_url, manifest, single_page=True)
            supported_remaining -= 1
            self.status_target(manifest, request.status)
            current = item.get("status") if isinstance(item, dict) else None
            if current in LIFECYCLE_OWNED_PROJECT_STATUSES:
                raise self._error_type(
                    f"project-sync refuses {request.issue_url} at lifecycle-owned "
                    f"Status={current}; use claim/release/reconcile"
                )
            plans.append(ProjectStatusPlan(
                request=request,
                item=item,
                add_required=item is None,
                status_update_possible=item is None or current != request.status,
            ))

        additions = sum(int(plan.add_required) for plan in plans)
        updates = sum(int(plan.status_update_possible) for plan in plans)
        mutations = sum(plan.mutation_upper_bound for plan in plans)
        satisfied = len(plans) - sum(int(plan.status_update_possible) for plan in plans)
        printer(
            "project-sync plan: "
            f"items={len(plans)} satisfied={satisfied} additions={additions} "
            f"status_updates_upper_bound={updates} "
            f"planned_mutations={mutations} projected_points={projected_points} "
            f"cost_drift_guard={PROJECT_SYNC_COST_DRIFT_GUARD} "
            f"lifecycle_reserve={INTERACTIVE_LIFECYCLE_RESERVE_POINTS} "
            f"remaining={self._graphql.remaining} reset={self._graphql.reset_at} "
            f"apply={str(apply).lower()}"
        )
        result: dict[str, Any] = {
            "schema": "hv-agent-project-sync:v1",
            "apply": apply,
            "items": len(plans),
            "satisfied": satisfied,
            "additions": additions,
            "status_updates_upper_bound": updates,
            "planned_mutations": mutations,
            "projected_points": projected_points,
            "cost_drift_guard": PROJECT_SYNC_COST_DRIFT_GUARD,
            "lifecycle_reserve": INTERACTIVE_LIFECYCLE_RESERVE_POINTS,
            "remaining": self._graphql.remaining,
            "reset": self._graphql.reset_at,
            "completed": [],
            "skipped": [],
        }
        if not apply:
            return result

        # Every plan receives a fresh apply-time read, including plans that
        # appeared satisfied during the batch-wide planning pass. The bound
        # also covers a pre-update Project reread so lifecycle-owned status
        # cannot be overwritten from a stale item value.
        remaining_points = sum(
            plan.apply_point_upper_bound
            for plan in plans
        )
        for plan in plans:
            request = plan.request
            self.require_sync_safe_issue(request.issue_url)
            self._graphql.require_noncritical_capacity(
                remaining_points + PROJECT_SYNC_COST_DRIFT_GUARD
            )
            current = self.item(
                request.issue_url, manifest, refresh=True, single_page=True,
            )
            remaining_points -= 1
            current_status = current.get("status") if isinstance(current, dict) else None
            if current_status in LIFECYCLE_OWNED_PROJECT_STATUSES:
                raise self._error_type(
                    f"project-sync observed lifecycle-owned Status={current_status} "
                    f"for {request.issue_url}; rerun lifecycle reconciliation"
                )
            if current_status == request.status:
                remaining_points -= plan.apply_point_upper_bound - 1
                result["skipped"].append({
                    "issue": request.issue_url,
                    "status": request.status,
                    "reason": "satisfied-before-mutation",
                })
                continue
            if current is None and not plan.add_required:
                raise self._error_type(
                    f"project membership for {request.issue_url} changed after planning; "
                    "rerun the unchanged project-sync command"
                )

            target = self.status_target(manifest, request.status)
            if target is None:
                raise self._error_type("project-sync requires a declared Project v2 tracker")
            issue_id = self.issue_node_id(request.issue_url)
            item = current
            actions: list[str] = []
            if item is None:
                self.require_sync_safe_issue(request.issue_url)
                self._graphql.require_noncritical_capacity(
                    remaining_points + PROJECT_SYNC_COST_DRIFT_GUARD
                )
                item = self._add_item(request.issue_url, issue_id, target)
                actions.append("added")
                remaining_points -= 1
                if item.get("status") == request.status:
                    # The add inherited the requested default; release the
                    # pre-update read and conditional update points.
                    remaining_points -= 2
            if item.get("status") != request.status:
                self.require_sync_safe_issue(request.issue_url)
                self._graphql.require_noncritical_capacity(
                    remaining_points + PROJECT_SYNC_COST_DRIFT_GUARD
                )
                refreshed = self.item(
                    request.issue_url, manifest, refresh=True, single_page=True,
                )
                remaining_points -= 1
                refreshed_status = (
                    refreshed.get("status") if isinstance(refreshed, dict) else None
                )
                if refreshed_status in LIFECYCLE_OWNED_PROJECT_STATUSES:
                    raise self._error_type(
                        f"project-sync observed lifecycle-owned Status={refreshed_status} "
                        f"for {request.issue_url} immediately before mutation; run "
                        "targeted lifecycle reconciliation"
                    )
                if not isinstance(refreshed, dict) \
                        or refreshed.get("id") != item.get("id"):
                    raise self._error_type(
                        f"project membership for {request.issue_url} changed before "
                        "Status mutation; rerun the unchanged project-sync command"
                    )
                item = refreshed
                if refreshed_status == request.status:
                    remaining_points -= 1
                else:
                    self._graphql.require_noncritical_capacity(
                        remaining_points + PROJECT_SYNC_COST_DRIFT_GUARD
                    )
                    item = self._update_status(
                        request.issue_url, item, request.status, target, issue_id,
                    )
                    actions.append("status-updated")
                    remaining_points -= 1

            # Settle both authority and Project state after every write before
            # reporting completion. A concurrent claim becomes an explicit
            # reconciliation handoff, never a false success.
            self.require_sync_safe_issue(request.issue_url)
            self._graphql.require_noncritical_capacity(
                remaining_points + PROJECT_SYNC_COST_DRIFT_GUARD
            )
            verified = self.item(
                request.issue_url, manifest, refresh=True, single_page=True,
            )
            remaining_points -= 1
            if not isinstance(verified, dict) or verified.get("status") != request.status:
                actual = verified.get("status") if isinstance(verified, dict) else None
                raise self._error_type(
                    f"project-sync verification for {request.issue_url} expected "
                    f"Status={request.status}, found {actual!r}; run targeted lifecycle "
                    "reconciliation before retrying"
                )
            result["completed"].append({
                "issue": request.issue_url,
                "status": request.status,
                "actions": actions,
            })
        result["measured_requests"] = self._graphql.requests
        result["measured_points"] = self._graphql.points
        result["remaining"] = self._graphql.remaining
        result["reset"] = self._graphql.reset_at
        printer(
            "project-sync result: "
            f"completed={len(result['completed'])} skipped={len(result['skipped'])} "
            f"requests={self._graphql.requests} cost={self._graphql.points} "
            f"remaining={self._graphql.remaining} reset={self._graphql.reset_at}"
        )
        return result

    def background_items(
        self,
        manifest: dict[str, Any],
    ) -> list[dict[str, Any]]:
        metadata = self.metadata(manifest)
        if metadata is None:
            return []
        values: list[dict[str, Any]] = []
        cursor: str | None = None
        for _page in range(MAX_BACKGROUND_PROJECT_PAGES):
            strings = {"id": str(metadata["project_id"])}
            if cursor is not None:
                strings["endCursor"] = cursor
            response = self._graphql.request(
                BACKGROUND_PROJECT_ITEMS_QUERY, strings=strings
            )
            node = response.get("data", {}).get("node")
            items = node.get("items") if isinstance(node, dict) else None
            nodes = items.get("nodes") if isinstance(items, dict) else None
            page_info = items.get("pageInfo") if isinstance(items, dict) else None
            if not isinstance(nodes, list) or not isinstance(page_info, dict):
                raise self._error_type("background project item page is incomplete")
            values.extend(item for item in nodes if isinstance(item, dict))
            if not page_info.get("hasNextPage"):
                return values
            cursor = page_info.get("endCursor")
            if not isinstance(cursor, str) or not cursor:
                raise self._error_type("background project item pagination is invalid")
        raise self._error_type(
            "background project reconciliation exceeded its bounded "
            f"{MAX_BACKGROUND_PROJECT_PAGES}-page limit"
        )


def transient_failure(message: str) -> bool:
    value = message.lower()
    return any(token in value for token in (
        "http 502", "http 503", "http 504", "bad gateway",
        "service unavailable", "gateway timeout", "connection reset",
        "connection refused", "unexpected eof", "temporary failure",
        "temporarily unavailable", "timeout", "timed out",
        "secondary rate limit",
    ))


def retryable_gh_command(arguments: list[str]) -> bool:
    """Retry only reads and idempotent REST writes after transient failures."""
    if arguments[:2] != ["gh", "api"]:
        return arguments[:3] in (
            ["gh", "issue", "view"],
            ["gh", "issue", "list"],
            ["gh", "pr", "view"],
        )
    if len(arguments) > 2 and arguments[2] == "graphql":
        return False
    method = "GET"
    for index, value in enumerate(arguments):
        if value == "--method" and index + 1 < len(arguments):
            method = arguments[index + 1].upper()
    if method == "POST" and any(
        re.fullmatch(r"repos/[^/]+/[^/]+/issues/[1-9][0-9]*/labels", value)
        for value in arguments
    ):
        return True
    return method in {"GET", "PUT", "PATCH", "DELETE"}
