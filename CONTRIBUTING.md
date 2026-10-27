# Contributing

Contributions are welcome: new validators, fixes, tests, and clearer docs.

## Start here

1. Follow [installation](README.md#installation), then
   [development setup](docs/development.md#setup).
2. Read [architecture](docs/architecture.md) to see how the parts fit together
   and find the code and tests for your change.
3. Use [project instructions](.github/project.instructions.md) for contracts and
   lessons learned, and [Python instructions](.github/python.instructions.md)
   for coding style.

## Make a change

1. Fork the repository if needed and create a feature branch.
2. Follow the [change workflow](docs/development.md#change-workflow).
3. Add tests for the behavior you change and run the
   [tests and formatting checks](docs/development.md#tests-and-formatting).
4. Open a pull request explaining the change, how you checked it, and any limits.
   Do not include real secrets or local logs.

## Architecture in brief

The CLI reads configuration and secrets from a file or GitHub. The registry picks
a checker for each secret type. Checkers validate the secrets, then output helpers
write the results. See [architecture](docs/architecture.md) for the small code map.

## Adding New Validators

Create a module in `src/validate_secrets/validators/` and inherit from `Checker`.
Set a unique `name` and a short `description`, then implement `check()`.
Return `True` for valid, `False` for invalid, and `None` for errors or unknown
results. See [project contracts](.github/project.instructions.md#contracts-and-guardrails)
for discovery and constructor rules.

```python
# src/validate_secrets/validators/my_validator.py

from ..core.base import Checker


class MySecretChecker(Checker):
    """Custom secret validator."""

    name = "my_secret"
    description = "Validates my custom secrets"

    def check(self, secret: str) -> bool | None:
        """Check the format of a synthetic example secret, not a credential."""
        return secret.startswith("mysecret_")
```

This only checks a made-up format; it does not verify a credential.
The registry discovers it automatically. Next:

- Add cases in `tests/test_validators.py`. Mock requests for a network-backed
  validator and check valid, invalid, and error responses.
- Use [discovery commands](docs/development.md#discover-a-new-validator) to check
  that the CLI can find and run it.
- Update the available validators in README when adding a supported type.
