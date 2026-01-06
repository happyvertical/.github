# Label Issue Command

Analyze and triage a newly opened GitHub issue.

## Context

You are triaging issues for the HappyVertical organization. This organization builds:
- **SDK**: Core foundation packages (@happyvertical/ai, sql, files, utils, logger)
- **SMRT Framework**: Application framework for vertical AI agents
- **Vertical Agents**: praeco (local news), caelus, ludis (sports data), aedile

## Parameters

- **REPO**: The repository (e.g., happyvertical/sdk)
- **ISSUE_NUMBER**: The issue number to triage
- **REPO_DESCRIPTION**: Brief description of the repository's purpose

## Your Task

1. **Read the issue**:
   ```bash
   gh issue view $ISSUE_NUMBER --json title,body,author,labels
   ```

2. **Categorize the issue type** (choose ONE):
   - `type: bug` - Something isn't working correctly
   - `type: feature` - New functionality or enhancement
   - `type: docs` - Documentation improvements
   - `type: maintenance` - Refactoring, dependency updates, cleanup
   - `type: research` - Investigation or exploration needed
   - `type: question` - Question or discussion

3. **Assess priority** (choose ONE):
   - `priority: critical` - Production broken, security issue, blocks all work
   - `priority: high` - Important, should be done soon
   - `priority: medium` - Normal priority (default)
   - `priority: low` - Nice to have, when time permits
   - `priority: icebox` - Future consideration, keep for reference

4. **Estimate size/effort** (choose ONE):
   - `size: xs` - < 2 hours, trivial change
   - `size: s` - 2-4 hours, small change
   - `size: m` - ~1 day, moderate change
   - `size: l` - 2-3 days, significant work
   - `size: xl` - > 3 days, large feature or refactor

5. **Check for duplicates**:
   ```bash
   gh issue list --search "is:issue [keywords from title]" --json number,title,state --limit 10
   ```

6. **Apply labels**:
   ```bash
   gh issue edit $ISSUE_NUMBER --add-label "type: X,priority: Y,size: Z"
   ```

7. **Post triage comment** with your reasoning:
   ```bash
   gh issue comment $ISSUE_NUMBER --body "## Triage Summary

   **Type**: [type] - [reason]
   **Priority**: [priority] - [reason]
   **Size**: [size] - [reason]

   **Notes**: [any additional context, duplicate references, questions]

   ---
   *Automated triage by Claude*"
   ```

## Label Format

Labels use the format `category: value` with a space after the colon:
- `type: bug` (not `type:bug`)
- `priority: high` (not `priority:high`)
- `size: m` (not `size:m`)

## Guidelines

- Be conservative with priority - most issues are medium
- Consider the repository context when sizing
- If unclear, ask clarifying questions in the comment
- Always provide reasoning for your choices
- Check if similar issues exist before applying labels
