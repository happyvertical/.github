# Implement Issue Command

Fully implement an issue from start to finish (autopilot mode).

## Context

You are implementing issues autonomously for the HappyVertical organization. You have full authority to:
- Create branches
- Write code
- Write tests
- Update documentation
- Create pull requests

## Parameters

- **REPO**: The repository (e.g., happyvertical/sdk)
- **ISSUE_NUMBER**: The issue to implement

## Prerequisites

The issue MUST have:
- A `type:` label (bug, feature, docs, maintenance, research)
- A `priority:` label
- A `size:` label
- A clear description (> 50 characters)

If prerequisites are missing, post a comment and remove the `agent: claude` label.

## Your Workflow

### 1. Understand the Issue

```bash
gh issue view $ISSUE_NUMBER --json title,body,labels,comments
```

Read all comments to understand:
- What needs to be done
- Any constraints or preferences
- Previous discussion or decisions

### 2. Create Feature Branch

```bash
# Get a slug from the issue title (lowercase, hyphenated)
git checkout main
git pull origin main
git checkout -b feat/issue-$ISSUE_NUMBER-[short-description]
```

Branch naming:
- `feat/issue-123-add-auth` for features
- `fix/issue-123-null-check` for bugs
- `docs/issue-123-api-docs` for documentation

### 3. Read the Codebase

Before coding:
- Read CLAUDE.md for repository-specific guidelines
- Understand existing patterns in similar files
- Identify files that will be affected

### 4. Implement the Solution

Follow these principles:
- **Minimal changes**: Only change what's necessary
- **Match patterns**: Follow existing code style
- **Write tests**: Add or update tests for your changes
- **Update docs**: Update relevant documentation

### 5. Quality Checks

Run all checks before committing:

```bash
# TypeScript
pnpm typecheck || npm run typecheck

# Linting
pnpm lint || npm run lint

# Tests
pnpm test || npm test

# Build
pnpm build || npm run build
```

Fix any failures before proceeding.

### 6. Commit Your Changes

Use conventional commit format:

```bash
git add -A
git commit -m "feat(scope): description

- Detailed change 1
- Detailed change 2

Closes #$ISSUE_NUMBER"
```

Commit types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Maintenance

### 7. Push and Create PR

```bash
git push -u origin [branch-name]

gh pr create \
  --title "[commit type](scope): description" \
  --body "## Summary

[What this PR does]

## Changes

- [Change 1]
- [Change 2]

## Testing

- [How to test]
- [Test coverage]

## Checklist

- [ ] Tests pass
- [ ] Linting passes
- [ ] Types check
- [ ] Documentation updated

Closes #$ISSUE_NUMBER"
```

### 8. Post Completion Update

```bash
gh issue comment $ISSUE_NUMBER --body "## Implementation Complete

I've created PR #[PR_NUMBER] to address this issue.

**Changes made**:
- [Summary of changes]

**Testing**:
- [How it was tested]

The PR is ready for review.

---
*Automated implementation by Claude*"
```

## Guidelines

- **Ask if unclear**: Post a comment asking for clarification rather than guessing
- **Progress updates**: Post comments for long-running implementations
- **Fail gracefully**: If blocked, post a comment explaining why and remove `agent: claude` label
- **Don't force push**: Never rewrite history after pushing
- **One issue, one PR**: Each issue gets its own PR
- **Keep PRs focused**: Don't add unrelated changes

## Blocked Situations

If you cannot proceed:
1. Post a comment explaining the blocker
2. Remove the `agent: claude` label
3. Add `status: blocked` label if appropriate

Common blockers:
- Unclear requirements
- Missing dependencies
- Environment issues
- Access restrictions
