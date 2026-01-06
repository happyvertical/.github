# HappyVertical Organization Configuration

This repository contains organization-wide GitHub configuration, reusable workflows, and Claude Code Action integration for all HappyVertical repositories.

## Overview

The HappyVertical organization uses Claude Code Action for automated:
- **Issue triage** - Categorize, prioritize, and size new issues
- **Issue checkup** - Scheduled hygiene scan to catch issues needing attention
- **@claude mentions** - AI assistance in issues and PRs
- **CI failure auto-fix** - Automatically fix failing CI builds
- **Test failure analysis** - Analyze and detect flaky tests
- **Agent autopilot** - Full implementation automation via `agent: claude` label

## Quick Start

### 1. Add Caller Workflows to Your Repository

Copy the workflow templates from `.github/workflow-templates/` to your repository's `.github/workflows/` directory:

```bash
# From your repository root
cp ../../../.github/.github/workflow-templates/*.yml .github/workflows/
```

Or create them manually - see the templates for the required configuration.

### 2. Configure Repository Variables (Optional)

In your repository settings (Settings → Secrets and variables → Actions → Variables), add:

| Variable | Description | Example |
|----------|-------------|---------|
| `REPO_DESCRIPTION` | Brief repo description | "Core SDK packages" |
| `PACKAGE_PATTERN` | Package naming pattern | `@happyvertical/*` |
| `PROJECT_ID` | GitHub Projects board ID | `PVT_kwDOB9Y8ns4A8-TY` |
| `STATUS_FIELD_ID` | Status field ID | `PVTSSF_...` |
| `STATUS_*_ID` | Status option IDs | See your project settings |

### 3. Ensure Org Secrets Are Available

The following secrets should be configured at the org level:

| Secret | Description |
|--------|-------------|
| `CLAUDE_CODE_OAUTH_TOKEN` | Claude Code Max OAuth token |

## Reusable Workflows

### Issue Triage (`org-issue-triage.yml`)

Automatically triages new issues:
- Assigns type label (bug, feature, docs, maintenance, research, question)
- Assigns priority label (critical, high, medium, low, icebox)
- Assigns size label (xs, s, m, l, xl)
- Checks for duplicate issues
- Adds to project board

**Caller example:**
```yaml
name: Issue Opened
on:
  issues:
    types: [opened]

jobs:
  triage:
    uses: happyvertical/.github/.github/workflows/org-issue-triage.yml@main
    with:
      issue_number: ${{ github.event.issue.number }}
      issue_title: ${{ github.event.issue.title }}
      issue_body: ${{ github.event.issue.body || '' }}
      issue_author: ${{ github.event.issue.user.login }}
    secrets:
      CLAUDE_CODE_OAUTH_TOKEN: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### @claude Mention Handler (`org-claude-mention.yml`)

Responds to @claude mentions in:
- Issue comments
- PR comments
- PR reviews
- Issue body/title

Claude can read code, make changes, create PRs, and more.

### CI Failure Auto-Fix (`org-ci-failure-fix.yml`)

Triggered when CI workflows fail:
- Analyzes failure logs
- Attempts automatic fix
- Commits and pushes if successful
- Comments on PR if unable to fix

### Test Failure Analysis (`org-test-analysis.yml`)

Analyzes test failures:
- Identifies root causes
- Detects flaky tests
- Provides actionable recommendations
- Posts analysis as PR comment

### Agent Autopilot (`org-agent-autopilot.yml`)

Full implementation automation triggered by `agent: claude` label:
1. Validates Definition of Ready
2. Creates feature branch
3. Implements the solution
4. Runs quality checks
5. Creates pull request
6. Updates issue status

### Issue Checkup (`org-issue-checkup.yml`)

Scheduled hygiene workflow to catch issues that slipped through triage:
- Runs weekly (configurable) or on-demand via manual trigger
- Scans all open issues for missing labels or incomplete descriptions
- Adds `needs-info` label to issues requiring human input
- Claude comments with specific asks to move issues forward
- Non-destructive: never implements, only triages and flags

**Caller example:**
```yaml
name: Issue Checkup
on:
  schedule:
    - cron: '0 9 * * 1'  # Weekly on Mondays
  workflow_dispatch:
    inputs:
      max_issues:
        description: 'Maximum issues to process'
        default: '20'

jobs:
  checkup:
    uses: happyvertical/.github/.github/workflows/org-issue-checkup.yml@main
    with:
      max_issues: ${{ github.event.inputs.max_issues && fromJSON(github.event.inputs.max_issues) || 20 }}
      stale_days: 7
    secrets:
      CLAUDE_CODE_OAUTH_TOKEN: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Claude Commands

The `.claude/commands/` directory contains prompts for Claude:

| Command | Description |
|---------|-------------|
| `label-issue.md` | Issue triage prompt |
| `fix-ci.md` | CI failure fix prompt |
| `implement-issue.md` | Full implementation prompt |
| `analyze-tests.md` | Test failure analysis prompt |

## Label System

### Type Labels
- `type: bug` - Something isn't working
- `type: feature` - New feature or enhancement
- `type: docs` - Documentation improvements
- `type: maintenance` - Maintenance and refactoring
- `type: research` - Research and investigation
- `type: question` - Question or discussion

### Priority Labels
- `priority: critical` - Immediate attention required
- `priority: high` - High priority
- `priority: medium` - Normal priority (default)
- `priority: low` - Low priority
- `priority: icebox` - Future consideration

### Size Labels
- `size: xs` - < 2 hours
- `size: s` - 2-4 hours
- `size: m` - ~1 day
- `size: l` - 2-3 days
- `size: xl` - > 3 days

### Agent Labels
- `agent: claude` - Triggers autopilot for full implementation
- `agent: triage` - AI triage in progress
- `agent: planning` - AI planning in progress
- `agent: implementation` - AI implementation in progress
- `agent: testing` - AI testing in progress
- `agent: review` - AI code review in progress

### Status Labels
- `needs-info` - Issue needs more information before it can be worked on

## Kanban Board Integration

The workflows integrate with GitHub Projects:

| Status | Trigger |
|--------|---------|
| New | Issue opened |
| Backlog | Triage complete |
| Planning | Manual move |
| Ready | Definition of Ready met |
| In Progress | `agent: claude` label or manual |
| Review | PR created |
| Done | PR merged or issue closed |

## Project Board Setup

To get your project board IDs:

```bash
# Get project ID
gh api graphql -f query='
  query($org: String!) {
    organization(login: $org) {
      projectsV2(first: 10) {
        nodes {
          id
          title
        }
      }
    }
  }
' -f org="happyvertical"

# Get status field and option IDs
gh api graphql -f query='
  query($id: ID!) {
    node(id: $id) {
      ... on ProjectV2 {
        fields(first: 20) {
          nodes {
            ... on ProjectV2SingleSelectField {
              id
              name
              options {
                id
                name
              }
            }
          }
        }
      }
    }
  }
' -f id="PVT_xxx"
```

## Runner Requirements

All workflows use the `arc-happyvertical` self-hosted runner. Ensure your runner is configured and running.

## Contributing

When updating workflows:
1. Test changes in a single repository first
2. Update workflow templates
3. Update this README
4. Roll out to other repositories

## Related Documentation

- [WORKFLOW_ARCHITECTURE.md](https://github.com/happyvertical/sdk/blob/main/WORKFLOW_ARCHITECTURE.md)
- [Claude Code Action](https://github.com/anthropics/claude-code-action)
- [GitHub Reusable Workflows](https://docs.github.com/en/actions/using-workflows/reusing-workflows)
