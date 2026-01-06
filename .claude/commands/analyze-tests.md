# Analyze Tests Command

Analyze test failures and identify flaky tests.

## Context

You are analyzing test failures for the HappyVertical organization. The goal is to:
1. Understand why tests failed
2. Identify flaky tests (intermittent failures)
3. Provide actionable recommendations

## Parameters

- **REPO**: The repository (e.g., happyvertical/sdk)
- **RUN_ID**: The workflow run ID with test failures

## Your Task

### 1. Get Test Logs

```bash
gh run view $RUN_ID --log-failed
```

### 2. Analyze Each Failure

For each failing test, determine:

**Error Type**:
- `assertion` - Test assertion failed (expected vs actual mismatch)
- `timeout` - Test exceeded time limit
- `setup` - Test setup/beforeEach failed
- `teardown` - Test cleanup/afterEach failed
- `network` - Network-related failure
- `resource` - Resource not available (file, db, etc.)
- `unknown` - Cannot determine cause

**Flakiness Indicators**:
- Timeout errors
- Race condition patterns
- Network errors
- "Sometimes passes" in history
- Non-deterministic behavior
- Time-sensitive assertions

### 3. Check Test History

```bash
# Look for patterns in recent runs
gh run list --workflow=test --limit 10 --json conclusion,createdAt
```

### 4. Output Analysis

Provide structured analysis:

```json
{
  "summary": "Brief summary of failures",
  "failures": [
    {
      "test_name": "should handle concurrent requests",
      "file": "src/api/client.test.ts",
      "error_type": "timeout",
      "error_message": "Async callback was not invoked within 5000ms",
      "likely_cause": "Race condition in async handling",
      "suggested_fix": "Add proper await or increase timeout",
      "severity": "medium"
    }
  ],
  "flaky_tests": [
    {
      "test_name": "should retry on network error",
      "flakiness_indicators": ["timeout", "network dependency"],
      "confidence": 0.8
    }
  ],
  "patterns": [
    "Multiple timeout failures suggest async handling issues"
  ],
  "recommendations": [
    "Consider mocking network calls in unit tests",
    "Add retry logic to flaky integration tests"
  ]
}
```

### 5. Post Comment

If this is from a PR, post the analysis:

```bash
gh pr comment [PR_NUMBER] --body "## Test Failure Analysis

### Summary
[summary]

### Failures
| Test | Type | Severity |
|------|------|----------|
| [test_name] | [error_type] | [severity] |

### Flaky Tests Detected
[list of flaky tests with confidence]

### Recommendations
- [recommendation 1]
- [recommendation 2]

---
*Automated analysis by Claude*"
```

## Flakiness Detection

**High confidence (0.8-1.0)**:
- Explicit timeout errors
- Network errors in non-network tests
- Different results on retry

**Medium confidence (0.5-0.8)**:
- Race condition patterns
- Order-dependent failures
- Time-sensitive assertions

**Low confidence (0.3-0.5)**:
- Unclear failure reason
- First-time failure
- Environment-specific

## Severity Levels

- **critical**: Blocks deployment, core functionality broken
- **high**: Important feature affected, needs prompt fix
- **medium**: Isolated failure, workaround possible
- **low**: Minor issue, can be deferred

## Guidelines

- Be specific about root causes
- Distinguish between bugs and flaky tests
- Provide actionable recommendations
- Consider test isolation and dependencies
- Check for shared state between tests
