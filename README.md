# Validate Secrets

This Python module checks a list of secrets for validity and returns the results as a CSV file.

It can optionally notify the secret user if it is still valid, for some secrets.

It will return 'valid', 'invalid' or 'error' for each secret.

For secrets that don't have an "activity" state (e.g. identity numbers), they will either be 'valid' or 'error' for those that are not real secrets.

> [!WARNING]
> Validation in some cases requires connecting to a cloud service to try the credential. You need to check the legal implications of this for yourself before using this tool. This is not legal advice.

> [!CAUTION]
> ⚠Notification will require connecting to a cloud service to use the credential and create some form of message. You need to check the legal implications of this for yourself before using this tool. This is not legal advice.

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
* `secret_type` is the type of secret to check out of: `office_webhook`, `snyk_api_token`, `google_api_key`.
* `--output-file` or `-o` is an optional argument specifying the output file. If not provided, the results will be printed to the standard output.
* `--notify` or `-n` is an optional argument. If provided, then if compatible if the secret type, an attempt will be made to use the secret to notify the owner that the secret has been leaked.
* `--debug` or `-d` is an optional argument. If provided, debug output will be turned on.

## License

This project is Copyright GitHub (c) 2023.
