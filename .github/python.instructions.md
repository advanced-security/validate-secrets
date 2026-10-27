# Python instructions

Applies to new and substantively changed Python; do not modernize untouched code
just to match this guide. [pyproject.toml](../pyproject.toml) defines executable
formatter settings; use the [development checks](../docs/development.md).
Project-specific validator and source contracts live in
[project instructions](project.instructions.md), not this style guide.

## Keep code small and idiomatic

- Target Python 3.11. Use four spaces, PEP 8 naming (`snake_case` functions/files,
  `PascalCase` classes, `UPPER_CASE` constants), and Black with a 100-column limit.
  Let Black handle wrapping and quotes.
- Type new/changed function signatures, including return types and `-> None`.
  Prefer `list[str]`, `dict[str, Any]`, and `bool | None` in new code; do not
  rewrite legacy `typing.List`/`Optional` solely for consistency.
- Use concise PEP 257 docstrings for public interfaces and non-obvious behavior.
  Comments explain intent or constraints, not each line. Prefer descriptive
  names to redundant comments/docstrings in simple private helpers.
- Group imports as standard library, third party, local. Follow existing
  relative imports inside `validate_secrets`; no production `sys.path` edits.
- Reuse existing helpers and boundaries. Avoid new frameworks, dependencies,
  generic abstractions, or parallel/async execution without a concrete need.
  The current application is synchronous; keep Requests calls synchronous.
- Keep the dictionary record/output contracts; do not migrate them to a new
  model framework for incidental typing. Add a shared type only when useful
  across real call sites.

## Validation and errors

- Use identity checks when branching on tri-state results, as defined in the
  project contracts.
- Set explicit request timeouts using `self.timeout`. Mock the actual HTTP
  path in tests: some existing validators use module-level calls, others
  `Session.send`. Do not infer request correctness from a mocked return alone.
- Handle expected failures narrowly at the owning boundary. Use `SourceError`,
  `ConfigurationError`, or `ValidatorError` where appropriate; do not add broad
  catch-all blocks to hide programming errors. Existing CLI catch-alls are not
  a general pattern to copy.
- Use `LOG = logging.getLogger(__name__)` and lazy formatting:
  `LOG.warning("Unexpected response status: %s", response.status_code)`.
  Never log credentials, authorization headers, secret-bearing URLs, or raw
  provider bodies. Keep sensitive result output separate from diagnostics.
- Use context managers and UTF-8 for text file I/O. Preserve source metadata.
  Avoid mutation of imported modules or other components' private state.

## Tests that demonstrate behavior

- Use pytest in `tests/test_<area>.py`; extend the owning test file unless a new
  concern warrants its own. Prefer focused functions or existing test classes.
- Use synthetic inputs, `tmp_path`, `monkeypatch`, and small mocks/fakes.
  Isolate environment-dependent config; no developer tokens or implicit `.env`.
- Mock network calls in new unit tests. Cover the relevant valid/invalid/unknown
  responses, exceptions/timeouts, and request method/URL/auth construction for
  changed provider behavior. Use dummy credentials and never contact providers
  just to prove a unit test.
- Assert meaningful outcomes, metadata, or side effects. Avoid tautologies such
  as `result in [True, False, None]` and tests that only restate constants.
- For CLI changes use Click's `CliRunner`; assert result contents and relevant
  exit behavior. For output changes parse generated CSV/JSON, not just exit code.
- Add only tests for introduced/fixed behavior and material edge cases. Keep
  intentionally malformed fixtures intentional; do not weaken tests to pass CI.
