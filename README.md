# Check Teams Webhooks

This Python module checks a list of secrets for validity and returns the results as a CSV file.

It can optionally notify the secret user if it is still valid, for some secrets.

## Installation

You can install this module using pip:

```bash
python3 -mpip install .
```

## Usage

You can use this module from the command line:

```bash
validate-secrets input_file secret_type [--output-file OUTPUT_FILE] [--notify] [--debug] [--help]
```

Where:

* `input_file` is a text file containing a list of Teams webhook URLs, one per line.
* `secret_type` is the type of secret to check out of: `office_webhook`, `snyk_api_token`.
* `--output-file` or `-o` is an optional argument specifying the output file. If not provided, the results will be printed to the standard output.
* `--notify` or `-n` is an optional argument. If provided, the Teams channel will be notified the webhook is still valid.
* `--debug` or `-d` is an optional argument. If provided, debug output will be turned on.

## License

This project is Copyright GitHub (c) 2023.
