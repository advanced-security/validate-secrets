# Development

Use [architecture](architecture.md) to find the code and tests.
[Project instructions](../.github/project.instructions.md) cover contracts and
lessons learned. This guide is for humans and agents making changes.

## Setup

Use Python 3.11+ and uv. Run from the repository root:

```bash
uv sync --dev --locked
uv run validate-secrets --help
uv run validate-secrets list-validators
```

`--locked` checks that `uv.lock` matches the project instead of changing it.
No token or `.env` is needed for these commands or offline tests. Copy
[.env.example](../.env.example) only when needed; environment variables take
priority over values in the file.

CI uses Python 3.11. If your Python version or installed packages differ from CI,
say so when reporting results. Normal `uv run` may sync packages. Use `--no-sync`
only to inspect an existing environment, not as a substitute for setup.

## Tests and formatting

Start with tests for the code you changed:

```bash
uv run python -m pytest tests/test_registry.py tests/test_sources.py -v
uv run python -m pytest tests/test_validators.py -k Databricks -v
```

Before handing off Python changes, run the full suite and Black:

```bash
uv run python -m pytest tests/ -v
uv run black --check --diff src/ tests/
```

To format a changed file, use `uv run black <path-to-file.py>`, replacing the
placeholder with its path. Follow [Python instructions](../.github/python.instructions.md).
No other linter or type checker is set up.

For docs-only changes, check links, examples, and commands against the code, then
run `git diff --check`. There is no need to run network-backed validator tests.

### Offline tests

Three existing validator tests make live requests. To skip them:

```bash
uv run python -m pytest tests/ -k "not test_valid_format_structure and not test_api_call_structure" -v
```

This also skips a local identity-number test. Report it as a subset, not a full
pass. Mock network calls in new unit tests. See
[lessons learned](../.github/project.instructions.md#lessons-learned) for other traps.

### Dependency changes

Only change dependencies when the task needs it. Edit `pyproject.toml`, run
`uv lock`, and review both files. Do not edit `uv.lock` by hand.

### Discover a new validator

After adding the synthetic checker in [CONTRIBUTING](../CONTRIBUTING.md#adding-new-validators):

```bash
uv run validate-secrets list-validators
uv run validate-secrets validate "mysecret_123" my_secret
```

## Change workflow

Follow these stages for changes. Keep notes short for small fixes or docs, but
do not skip the reviews.

Before implementation, create a task folder under gitignored `.logs/`.
Use a date and short name; add a suffix if the name is already in use.
Keep the plan, work log, reviews, and supporting files together:

```text
.logs/<date>-<task>/
  plan.md          # Findings, goals, approach, checks
  execution.md     # Changes, commands, results, limits
  reviews.md       # Plan review, challenge, final review
  artifacts/       # Optional safe output, examples, diagrams
```

Filenames can vary. Never save real secrets, auth headers, alert payloads, or
sensitive provider output. Gitignore does not protect file contents. Do not
force-add logs to Git. Put lasting guidance in tracked docs and summarize the
work in the PR; other contributors will not have your local logs.

1. **Investigate.** Check the branch and existing edits. Keep others' work and
   create a feature branch if needed. Read the relevant code, tests, and history.
   Record how it works now and any existing test failures.
2. **Plan.** In `plan.md`, describe the goal, smallest useful change, files to
   touch, risks, and tests. Ask about unclear choices that would change the scope
   or behavior; routine plans do not need approval.
3. **Rubber-duck the plan.** Explain it to a reviewer before coding. Look for
   wrong assumptions, missing failure cases, and simpler options. Record the
   feedback and why you accepted or rejected it. Update the plan.
4. **Implement.** Make small changes and add tests for changed behavior. Run
   focused checks as you go. Record changes, commands, and results in
   `execution.md`.
5. **Adversarial challenge.** Try to show the change is wrong. Check relevant
   bad inputs, failures, timeouts, side effects, and compatibility. Use code and
   test evidence, not just a green exit code. Fix important findings.
6. **Final rubber duck.** Review the result after fixes. Check the original goal,
   missing cases, and unnecessary complexity. Make improvements that help;
   leave unrelated cleanup for later. Rerun affected checks after edits and
   review again if the design changes. Finish the log with results, remaining
   risks, and a summary for the handoff.

Use a separate person or agent for reviews when available. Give them a clear
question and the plan, diff, and results. Otherwise, make a separate self-review
pass and say so; do not call it independent. No particular tool is required.

### Completion checks

- Check that the goal is met and important review findings are resolved.
  Be clear about anything untested or blocked; do not weaken checks to pass.
- Run the checks above for the type of change. Check ignore rules if changed.
- Read the final diff and status for accidental edits, secrets, or generated files.
- Update docs for changed behavior. Include changes, checks, limits, and the
  task-log path in the handoff. Do not commit or push unless asked.
