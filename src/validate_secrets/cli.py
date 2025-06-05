#!/usr/bin/env python3

"""Command line interface for validate-secrets."""

import sys
import logging

import click
from rich.console import Console
from rich.table import Table
from rich.progress import track

from .config import Config
from .core.registry import (
    get_validators,
    get_validator,
    list_validators as list_available_validators,
    get_validator_info,
)
from .core.exceptions import ValidateSecretsError, SourceError, ConfigurationError
from .sources.file import FileSource
from .sources.github import GitHubSource
from .utils import output_results

LOG = logging.getLogger(__name__)
console = Console()


@click.group()
@click.option("--config", "-c", help="Path to .env configuration file")
@click.option(
    "--debug",
    "-d",
    is_flag=True,
    help="Enable debug logging. To use, add the flag as a first argument!",
)
@click.pass_context
def cli(ctx, config, debug):
    """Extensible secret validation tool."""
    ctx.ensure_object(dict)

    # Initialize configuration
    ctx.obj["config"] = Config(config)

    # Set up logging
    if debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        ctx.obj["config"].setup_logging()

    ctx.obj["debug"] = debug


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.argument("secret_type", type=click.Choice(list_available_validators()), required=False)
@click.option("--output", "-o", help="Output file (default: stdout)")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["csv", "json", "table"]),
    default="csv",
    help="Output format",
)
@click.option(
    "--file-format",
    type=click.Choice(["text", "csv", "json"]),
    help="Input file format",
)
@click.option("--notify", "-n", is_flag=True, help="Send notifications to endpoints")
@click.pass_context
def check_file(ctx, file_path, secret_type, output, output_format, file_format, notify):
    """Check secrets from a file."""
    try:
        config = ctx.obj["config"]
        validation_config = config.get_validation_config()

        # Get default file format from config if not provided via CLI
        if file_format is None:
            input_config = config.get_input_format()
            file_format = input_config["input_format"]

        # Validate secret_type requirement for text files
        if file_format == "text" and not secret_type:
            console.print("[red]Error: secret_type is required when using text file format[/red]")
            console.print(
                "Usage: validate-secrets check-file <file_path> <secret_type> --file-format text|json|csv"
            )
            sys.exit(1)

        # Create file source
        source = FileSource(file_path, file_format, secret_type)

        # Process secrets
        results = []
        secret_count = 0
        secrets_by_type = {}

        for secret_data in source.get_secrets():
            secret_count += 1

            secret_type_from_data = secret_data.get("type")
            if not secret_type_from_data:
                console.print(
                    f"[yellow]Warning: No type specified for secret: {secret_data['secret'][:20]}...[/yellow]"
                )
                continue

            if secret_type_from_data not in secrets_by_type:
                secrets_by_type[secret_type_from_data] = []
            secrets_by_type[secret_type_from_data].append(secret_data)

        if secret_count == 0:
            console.print("[yellow]No secrets found in file[/yellow]")
            return

        console.print(f"Processing {secret_count} secrets...")

        # Validate secrets by type
        for current_secret_type, secret_list in secrets_by_type.items():
            try:
                # Get validator for this secret type
                validator_class = get_validator(current_secret_type)
                validator = validator_class(
                    notify=notify or validation_config["notifications"],
                    debug=ctx.obj["debug"],
                    timeout=validation_config["timeout"],
                )

                for secret_data in track(
                    secret_list, description=f"Validating {current_secret_type}..."
                ):
                    secret = secret_data["secret"]
                    status = validator.check(secret)

                    status_text = "invalid"
                    if status is True:
                        status_text = "valid"
                    elif status is None:
                        status_text = "error"

                    result = {
                        "secret": secret,
                        "type": current_secret_type,
                        "status": status_text,
                        "metadata": secret_data.get("metadata", {}),
                    }
                    results.append(result)

            except Exception as validator_error:
                console.print(
                    f"[red]Error with validator for {current_secret_type}: {validator_error}[/red]"
                )
                # Add error results for these secrets
                for secret_data in secret_list:
                    result = {
                        "secret": secret_data["secret"],
                        "type": current_secret_type,
                        "status": "error",
                        "metadata": secret_data.get("metadata", {}),
                    }
                    results.append(result)

        # Output results
        output_results(results, output, output_format)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option("--org", help="GitHub organization name")
@click.option("--repo", help="GitHub repository (owner/repo)")
@click.option("--secret-type", help="Filter by secret type")
@click.option(
    "--state", type=click.Choice(["open", "resolved"]), default="open", help="Alert state filter"
)
@click.option(
    "--validity",
    type=click.Choice(["valid", "invalid", "unknown"]),
    default="unknown",
    help="Secret validity filter",
)
@click.option("--output", "-o", help="Output file (default: stdout)")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["csv", "json", "table"]),
    default="csv",
    help="Output format",
)
@click.option("--notify", "-n", is_flag=True, help="Send notifications to endpoints")
@click.pass_context
def check_github(ctx, org, repo, secret_type, state, validity, output, output_format, notify):
    """Check secrets from GitHub secret scanning alerts."""
    try:
        config = ctx.obj["config"]
        github_config = config.get_github_config()
        validation_config = config.get_validation_config()

        # Use CLI args or fallback to config
        org = org or github_config.get("org")
        repo = repo or github_config.get("repo")

        if not (org or repo):
            raise ConfigurationError(
                "Either --org or --repo must be specified, or set GITHUB_ORG/GITHUB_REPO"
            )

        # Create GitHub source
        source = GitHubSource(
            token=github_config["token"],
            org=org,
            repo=repo,
            base_url=github_config["api_url"],
            state=state,
            secret_type=secret_type,
            validity=validity,
        )

        console.print(f"Fetching alerts from {source.get_name()}...")

        # Get all alerts
        alerts = list(source.get_secrets())

        if not alerts:
            console.print("[yellow]No secret scanning alerts found[/yellow]")
            return

        console.print(f"Found {len(alerts)} alerts")

        # Process alerts and validate secrets
        results = []

        for alert_data in track(alerts, description="Validating..."):
            secret = alert_data["secret"]
            github_secret_type = alert_data["type"]

            try:
                # Try to get validator using the GitHub secret type directly
                validator_class = get_validator(github_secret_type)
                validator = validator_class(
                    notify=notify or validation_config["notifications"],
                    debug=ctx.obj["debug"],
                    timeout=validation_config["timeout"],
                )

                status = validator.check(secret)

                status_text = "invalid"
                if status is True:
                    status_text = "valid"
                elif status is None:
                    status_text = "error"

                result = {
                    "secret": (
                        secret[:10] + "..." if len(secret) > 10 else secret
                    ),  # Truncate for display
                    "type": github_secret_type,
                    "status": status_text,
                    "validator": github_secret_type,
                    "metadata": alert_data.get("metadata", {}),
                }
                results.append(result)

            except Exception as e:
                error_msg = str(e)
                if "Unknown validator" in error_msg:
                    status = "no_validator"
                    console.print(
                        f"[yellow]No validator available for secret type: {github_secret_type}[/yellow]"
                    )
                else:
                    status = "validation_error"
                    console.print(
                        f"[yellow]Warning: Failed to validate {github_secret_type} secret: {e}[/yellow]"
                    )

                result = {
                    "secret": (
                        secret[:10] + "..." if len(secret) > 10 else secret
                    ),  # Truncate for display
                    "type": github_secret_type,
                    "status": status,
                    "error": error_msg,
                    "metadata": alert_data.get("metadata", {}),
                }
                results.append(result)

        # Output results
        output_results(results, output, output_format)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command("list-validators")
def list_validators_cmd():
    """List all available validators."""
    try:
        validator_info = get_validator_info()

        table = Table(title="Available Validators")
        table.add_column("Name", style="cyan")
        table.add_column("Description", style="green")
        table.add_column("Class", style="yellow")

        for name, info in validator_info.items():
            table.add_row(
                name, info.get("description", "No description"), info.get("class", "Unknown")
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.argument("secret")
@click.argument("secret_type", type=click.Choice(list_available_validators()))
@click.option("--notify", "-n", is_flag=True, help="Send notifications to endpoints")
@click.pass_context
def validate(ctx, secret, secret_type, notify):
    """Validate a single secret."""
    try:
        config = ctx.obj["config"]
        validation_config = config.get_validation_config()

        # Get validator
        validator_class = get_validator(secret_type)
        validator = validator_class(
            notify=notify or validation_config["notifications"],
            debug=ctx.obj["debug"],
            timeout=validation_config["timeout"],
        )

        # Validate secret
        with console.status("Validating secret..."):
            status = validator.check(secret)

        if status is True:
            console.print("[green]✓ Secret is valid[/green]")
        elif status is False:
            console.print("[red]✗ Secret is invalid[/red]")
        else:
            console.print("[yellow]? Validation error or unknown status[/yellow]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


def main():
    """Main entry point."""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
