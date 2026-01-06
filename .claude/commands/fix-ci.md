# Fix CI Command

Analyze and fix a failed CI workflow.

## Context

You are fixing CI failures for the HappyVertical organization repositories. Common CI steps include:
- TypeScript type checking (`pnpm typecheck` or `npm run typecheck`)
- Linting (`pnpm lint` or `npm run lint`)
- Testing (`pnpm test` or `npm test`)
- Building (`pnpm build` or `npm run build`)

## Parameters

- **REPO**: The repository (e.g., happyvertical/sdk)
- **WORKFLOW**: The workflow that failed
- **BRANCH**: The branch where the failure occurred
- **RUN_ID**: The workflow run ID

## Your Task

1. **Get failure logs**:
   ```bash
   gh run view $RUN_ID --log-failed
   ```

2. **Analyze the failure**:
   - Identify the failing step (typecheck, lint, test, build)
   - Understand the error message
   - Determine if it's a code issue vs environment issue

3. **Locate the problematic code**:
   - Use the error messages to find the file(s) and line(s)
   - Read the relevant files to understand context

4. **Implement a fix**:
   - Make minimal changes to fix the issue
   - Follow existing code patterns
   - Don't introduce new features or refactoring

5. **Verify the fix locally**:
   ```bash
   # Run the failing command
   pnpm typecheck  # or npm run typecheck
   pnpm lint       # or npm run lint
   pnpm test       # or npm test
   pnpm build      # or npm run build
   ```

6. **Commit the fix**:
   ```bash
   git add -A
   git commit -m "fix: [description of what was fixed]

   - [specific change 1]
   - [specific change 2]"
   ```

7. **Push the fix**:
   ```bash
   git push
   ```

## Common Failure Types

### Type Errors
- Missing type annotations
- Incorrect type assignments
- Missing imports
- Property access on possibly undefined

### Lint Errors
- Formatting issues (run `pnpm format` to fix)
- Unused imports/variables
- Missing semicolons or quotes

### Test Failures
- Assertion failures
- Timeout issues
- Missing test fixtures
- Race conditions

### Build Errors
- Missing dependencies
- Circular imports
- Invalid export/import statements

## Guidelines

- Focus on fixing the immediate issue, not improving surrounding code
- If the fix is unclear, create an issue instead of guessing
- Don't force push or rewrite history
- If tests are flaky, note this but still fix if possible
- Commit messages should use conventional commit format
