# validate-secrets

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An extensible secret validation tool with dynamic plugin system for identifying and validating leaked credentials. `validate-secrets` is designed to help developers and security teams to identify and validate  credentials that have been accidentally exposed in code repositories or other data sources. It supports multiple validators, integrates with GitHub Secret Scanning REST API. It provides a CLI interface with support for ease of use and further integration.

## Use cases

1. Post Incident Credential Validation - When a security incident because of exposed credentials, security teams need to quickly determine which credentials are still active.

2. Continuous Monitoring of GitHub Secret Scanning Alerts - Development teams using GitHub's Secret Scanning can automate the validation of open alerts to prioritize remediation efforts, reduce false positives, and focus on actual threats.

## Features

- **Dynamic Plugin System**: Auto discovers validators using `pkgutil` scanning
- **Multiple Data Sources**: Local file input based and GitHub Secret Scanning integration via REST API
- **Flexible Configuration**: Environment based configuration with .env support or command line arguments
- **Multiple Input and Output Formats**: CSV, JSON, and table output
- **Extensible Architecture**: Rather easy to add new/your own validators

## Quick Start

### Installation

Using `uv` (recommended):

```bash
git clone https://github.com/advanced-security/validate_secrets.git
cd validate_secrets
uv pip install -e .
```

Using `pip`:

```bash
git clone https://github.com/advanced-security/validate_secrets.git
cd validate_secrets
pip install -e .
```

### Basic Usage

Best way to get familiar with the CLI is to run the help command:

```bash
validate-secrets --help
```

List available validators:

```bash
validate-secrets list-validators
```

Validate a single secret:

```bash
validate-secrets validate "AIzaSyABC123..." google_api_keys
```

Check GitHub Secret Scanning alerts:

```bash
validate-secrets check-github --org myorg --format json
```

Validate secrets from files:

**Text files** (secret_type required):

```bash
validate-secrets check-file input/secrets_file.txt google_api_keys --file-format text --format table
```

**CSV files** (secret_type read from file):

```bash
validate-secrets check-file input/secrets_file.csv --file-format csv --format table
```

**JSON files** (secret_type read from file):

```bash
validate-secrets check-file input/secrets_file.json --file-format json --format table
```

## Available Validators

| Validator | Description | Supported Formats |
|-----------|-------------|-------------------|
| `fodselsnummer` | Norwegian National Identity Numbers | Text |
| `google_api_key` | Google API Keys | AIza... format |
| `microsoft_teams_webhook` | Microsoft Teams/Office 365 Webhooks | webhook.office.com URLs |
| `snyk_api_token` | Snyk API Tokens | API tokens |

Note: Most accurate way to see available validators is to run `validate-secrets list-validators` command.

## Configuration

Create a `.env` file for configuration is the recommended way to setup the tool. You can copy the example file provided in the repository:

```bash
cp .env.example .env
```

### Environment Variables

Depending on the usage a lot of these options can be provided via command line interface (CLI) as well. The `.env` file is just another way to configure the tool and primarily used to override default values. The `GITHUB_TOKEN` is required for GitHub integration.

```bash
# GitHub Configuration
GITHUB_TOKEN=ghp_xxx
GITHUB_ORG=my-organization # Optional, can be provided in CLI
GITHUB_REPO=my-repository # Optional, can be provided in CLI

# Validation Configuration - All options are optional, can be provided in CLI
VALIDATION_TIMEOUT=30 
ENABLE_NOTIFICATIONS=false

# Output Configuration - All options are optional, can be provided in CLI
DEFAULT_OUTPUT_FORMAT=csv
DEFAULT_INPUT_FORMAT=text
LOG_LEVEL=INFO
```

## Data Sources

### File Sources

Support multiple file formats with different requirements for secret type specification:

**Text files** (one secret per line, secret_type required as command argument):

```text
AIzaSyABC123...
AIzaSyDEF456...
```

Usage:

```bash
validate-secrets check-file secrets.txt google_api_keys --file-format text
```

**CSV files** (secret_type read from 'type' column):

```csv
secret,type
AIzaSyABC123...,google_api_key
sk_test_123...,stripe_key
```

Usage:

```bash
validate-secrets check-file secrets.csv --file-format csv
```

**JSON files** (secret_type read from 'type' property):

```json
[
  {"secret": "AIzaSyABC123...", "type": "google_api_key"},
  {"secret": "sk_test_123...", "type": "stripe_key"}
]
```

Usage:

```bash
validate-secrets check-file secrets.json --file-format json
```

### GitHub Integration

Integrate with GitHub Secret Scanning alerts via the REST API:

```bash
# Organization level
validate-secrets check-github --org myorg

# Repository level   
validate-secrets check-github --repo owner/repo

# Filter by secret type, state and validity
validate-secrets check-github --org myorg --secret-type google_api_key --state open --validity unknown
```

## Outputs

Supports multiple output formats for results with the `--format` option:

- **CSV**: Comma-separated values (default)
- **JSON**: JSON format with metadata
- **Table**: Rich table format for terminal output

With the `--output` option you can also specify the file to write the output to:

```bash
validate-secrets check-file secrets.txt google_api_key --file-format csv --output results.csv
```

## License

This project is licensed under the terms of the MIT open source license. Please refer to [LICENSE.md](LICENSE.md) for the full terms.

## Maintainers

- [@theztefan](https://github.com/theztefan) - Core Maintainer
- [@aegilops](https://github.com/aegilops) - Core Maintainer

## Support

- **Issues**: Report bugs and feature requests on GitHub [issues page](https://github.com/advanced-security/validate_secrets/issues)
- **Contributions**: Contributions are welcome! Please read the [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
- **Security**: Check our security policy [SECURITY.md](SECURITY.md)
