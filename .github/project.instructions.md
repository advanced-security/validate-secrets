# Project instructions

Read [architecture](../docs/architecture.md) to find the code and tests.
Use [development](../docs/development.md) for commands and the change workflow,
and [Python instructions](python.instructions.md) for coding style.
Read only the code needed for the task; check its history when a choice is unclear.

## Contracts and guardrails

- `Checker.check(secret)` returns `True` (valid), `False` (invalid), or `None`
  (error/unknown). Check these values explicitly; `False` and `None` differ.
- Define one `Checker` subclass per validator module. The registry uses its
  `name`, or the module name if unset. GitHub-backed names must match GitHub's
  secret type; there is no mapping table.
- Checkers must allow construction without arguments so metadata listing works.
  Keep provider-specific options in that checker. Use `cli._create_validator()`
  to pass only supported options.
- Source records contain `secret`, `type`, and `metadata`. Keep source details
  and output formats intact unless the task calls for a change.
- GitHub filters use `active`/`inactive`/`unknown`, not result status names.
- Mock provider calls in new tests. Never put real secrets in fixtures, logs,
  review notes, or PRs. Treat `.env` and secret input/output as sensitive.
- Live checks need explicit authorization for the target and side effects.
  Teams `--notify` sends a message. Reading GitHub alerts needs `GITHUB_TOKEN`.
- Keep changes small. Leave unrelated bugs, dependencies, and formatting alone.

## Lessons learned

Add a lesson when a verified mistake could waste time again: what went wrong,
why, and what to do instead. Include a code, test, or history pointer. Keep task
notes in `.logs/`, merge repeated lessons, and update or remove lessons as code
changes. Never include sensitive evidence.

- **Use the validator name, not the filename.** `google_api_keys.py` defines
  `google_api_key`. Read the checker's `name` before choosing an ID.
- **Do not pass provider options to every checker.** This broke other validators
  when `host_url` was added. Keep it provider-specific and use
  `_create_validator()` (`cli.py`, fix `a2896a5`).
- **A green command is not proof of a valid secret.** Commands can exit
  successfully with error results, and some tests accept any result. Check the
  result and request details (`cli.py`, `tests/test_validators.py`).
- **Check output, not just the format option.** JSON stdout includes progress;
  use an output file for separate JSON. Table output ignores that option, and
  JSON `timestamp` currently holds the working directory (`cli.py`, `utils.py`).
- **Trace settings before debugging them.** CLI output defaults do not use
  `Config.get_output_config()`, even though the settings exist (`config.py`).
- **Check the environment behind a passing test.** An old `.venv` may differ
  from the lockfile and CI. Use the setup in development and report differences.
- **Check where timeouts and buffering happen.** `with_timeout` is unused;
  GitHub requests lack explicit timeouts. The CLI collects records/results and
  JSON input is loaded in memory. Do not assume global cancellation or streaming
  (`core/base.py`, `sources/`, `cli.py`).

These are current limits, not rules to preserve bugs. Fix them when in scope,
add regression tests, and update the guidance.
