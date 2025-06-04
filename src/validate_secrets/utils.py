"""Utility functions for validate-secrets CLI."""

import sys
import csv
import json
from pathlib import Path
from typing import Dict, Any, List

from rich.console import Console
from rich.table import Table

console = Console()


def output_results(results: List[Dict[str, Any]], output_file: str, format_type: str):
    """Output results in the specified format."""
    if format_type == "table":
        output_table(results)
    elif format_type == "json":
        output_json(results, output_file)
    else:  # default to csv
        output_csv(results, output_file)


def output_table(results: List[Dict[str, Any]]):
    """Output results as a table."""
    table = Table(title="Validation Results")
    table.add_column("Secret", style="cyan", max_width=30)
    table.add_column("Type", style="green")
    table.add_column("Status", style="yellow")
    table.add_column("Source", style="blue")

    for result in results:
        secret = result["secret"]
        if len(secret) > 27:
            secret = secret[:24] + "..."

        source = result.get("metadata", {}).get("source", "Unknown")
        if isinstance(source, str) and len(source) > 20:
            source = Path(source).name

        status_style = ""
        if result["status"] == "valid":
            status_style = "[green]"
        elif result["status"] == "invalid":
            status_style = "[red]"
        else:
            status_style = "[yellow]"

        table.add_row(secret, result["type"], f"{status_style}{result['status']}[/]", str(source))

    console.print(table)


def output_csv(results: List[Dict[str, Any]], output_file: str):
    """Output results as CSV."""
    output = sys.stdout if not output_file else open(output_file, "w", newline="")

    try:
        writer = csv.writer(output)
        writer.writerow(["secret", "type", "status", "source", "metadata"])

        for result in results:
            metadata = result.get("metadata", {})
            source = metadata.get("source", "Unknown")
            metadata_str = json.dumps(metadata) if metadata else ""

            writer.writerow(
                [result["secret"], result["type"], result["status"], source, metadata_str]
            )
    finally:
        if output_file:
            output.close()


def output_json(results: List[Dict[str, Any]], output_file: str):
    """Output results as JSON."""
    output_data = {
        "timestamp": str(Path().cwd()),
        "total_secrets": len(results),
        "results": results,
    }

    if output_file:
        with open(output_file, "w") as f:
            json.dump(output_data, f, indent=2)
    else:
        print(json.dumps(output_data, indent=2))
