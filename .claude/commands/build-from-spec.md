# Build from Spec

Build a feature from an implementation spec using structured planning, TDD, and self-review.

## Input

$ARGUMENTS

If no argument is provided, look in `docs/plans/` for pending spec files (ignore the `completed/` subdirectory). List them and ask which to build.

## Phase 1: Plan

1. Read the spec file completely
2. Break the work into sequential tasks of 2-5 minutes each. For each task specify:
   - What to build
   - Which files to create or modify
   - A verification step (test, assertion, or observable behavior)
3. Write the plan to `docs/plans/build-plan-<feature-slug>.md` with checkboxes:
   ```
   - [ ] Task 1: description
   - [ ] Task 2: description
   ```
4. **STOP. Show me the plan and wait for approval before writing any code.**

## Phase 2: Build

For each task in the plan:

1. **Test first.** Write a failing test that captures the expected behavior. Run it — confirm it fails. If the project has no test infrastructure or the task is not test-amenable (config, markup, static assets), skip to step 2 and note why.
2. **Implement.** Write the minimum code to make the test pass.
3. **Verify.** Run the test suite. All tests must pass before moving on.
4. **Review your diff against the spec.** Ask yourself:
   - Does this match what the spec asked for?
   - Did I introduce anything the spec didn't request?
   - Did I drift from the plan?
   If you drifted, flag it and course-correct before continuing.
5. **Commit** with a message referencing the task (e.g., `feat: add input validation per voice-tuning spec task 3`).
6. **Update the plan** — check off the completed task.

## Phase 3: Verify

After all tasks are complete:

1. Run the full test suite. Fix any failures.
2. Review the complete diff against the original spec. Summarize:
   - What was built
   - What was skipped or deferred (and why)
   - Any decisions you made that the spec didn't cover
3. Push the branch and create a PR if on a feature branch.

## Rules

- Do NOT skip the plan approval checkpoint. This is the most important step.
- Do NOT write implementation code before writing a test, unless explicitly noted as non-testable.
- If context gets long, re-read the plan file to reorient — it is your checkpoint.
- Keep tasks small. If a task is taking more than 5 minutes, split it.
- Ask me if anything in the spec is ambiguous. Do not guess.
