# Contribution Guidelines for Validate Secrets

This document outlines the contribution process for the Validate Secrets project, including information about the structure and architecture of the project as well as how to add new validators, run tests, etc.

## Architecture

### Core Components

- **Registry System** (`core/registry.py`): Auto-discovers and manages validators
- **Base Classes** (`core/base.py`): Abstract base class for validators
- **Data Sources** (`sources/`): Abstraction layer for different input sources
- **CLI Interface** (`cli.py`): Click-based command-line interface

### Plugin Discovery

The system uses `pkgutil.iter_modules()` to scan the `validators/` directory and automatically register any class that inherits from `Checker`.

### Timeout Handling

All validators support configurable timeouts using signal-based interruption to prevent hanging on network requests.

### Performance

- **Timeout Controls**: Prevent hanging on slow network requests
- **Memory Efficient**: Streaming file processing for large files
- **Progress Indicators**: Real-time progress feedback

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-validator`
3. Add your validator to `src/validate_secrets/validators/`
4. Add tests for your validator
5. Submit a pull request

### Setup Development Environment

```bash
git clone https://github.com/advanced-security/validate_secrets.git
cd validate_secrets
uv install --dev
```

### Running Tests

```bash
uv run python -m pytest tests/ -v
```

### Code Formatting

```bash
uv run black src/ tests/
```

### Adding New Validators

- Inherit from `Checker` base class
- Implement `check(secret: str) -> Optional[bool]` method
- Return `True` for valid, `False` for invalid, `None` for errors
- Add proper error handling and logging
- Include timeout support for network requests
- Provide clear name and description attributes

The plugin system automatically discovers new validators. Create a new file in `src/validate_secrets/validators/`:

```python
# src/validate_secrets/validators/my_validator.py

from ..core.base import Checker

class MySecretChecker(Checker):
    """Custom secret validator."""
    
    name = "my_secret"
    description = "Validates my custom secrets"
    
    def check(self, secret: str) -> Optional[bool]:
        """Validate the secret."""
        # Your validation logic here
        if secret.startswith("mysecret_"):
            # Make API call or validate format
            return True  # Valid
        return False  # Invalid
```

The validator will be automatically discovered and available via CLI:

```bash
validate-secrets list-validators
validate-secrets validate "mysecret_123" my_secret
```
