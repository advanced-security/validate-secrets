# Architecture

validate-secrets is a small Python CLI. It reads secrets, picks a validator for
each type, and writes the results. There is no server or database.

```text
CLI + configuration
        |
File or GitHub source
        |
Validator registry -> Checker
        |
Results -> CSV, JSON, or table
```

## Main parts

- **CLI** (`cli.py`) connects the parts and handles command options. Both the
  installed command and the package entry point call `cli.main`.
- **Configuration** (`config.py`) reads environment variables and an optional
  `.env` file.
- **Sources** (`sources/`) read text, CSV, JSON, or GitHub secret scanning alerts.
  Each record includes a secret, its type, and metadata about where it came from.
- **Registry** (`core/registry.py`) discovers validators in `validators/`.
  The CLI uses the secret type to look up a checker class.
- **Validators** (`validators/`) inherit `Checker` from `core/base.py`.
  A checker uses a local check or a provider request to return valid, invalid,
  or unknown/error.
- **Output** (`utils.py`) writes the collected results.

The CLI runs checks synchronously and collects records/results in memory.
Adding a validator normally needs only a new module and tests, not a registry
edit. See the [validator example](../CONTRIBUTING.md#adding-new-validators) and
[project contracts](../.github/project.instructions.md#contracts-and-guardrails).

## Find the code and tests

Source paths below are relative to `src/validate_secrets/`.

| Change | Source | Tests |
| --- | --- | --- |
| Commands and options | `cli.py` | Add CLI tests; CI currently has smoke checks |
| Environment settings | `config.py` | Add config tests |
| Plugin discovery | `core/registry.py` | `tests/test_registry.py` |
| Checker contract and timeouts | `core/base.py`, `core/exceptions.py` | `tests/test_validators.py`; add direct tests as needed |
| File input | `sources/file.py`, `sources/base.py` | `tests/test_sources.py` |
| GitHub alerts and pagination | `sources/github.py` | `tests/test_github.py` |
| A provider check | `validators/<provider>.py` | `tests/test_validators.py` |
| Output formats | `utils.py` | Add output tests |

Use [development](development.md) for commands and the change workflow.
Known traps are in [lessons learned](../.github/project.instructions.md#lessons-learned).
