#!/usr/bin/env python3

import sys
from argparse import ArgumentParser
import logging
from defusedcsv import csv

from . import types
from . import office_webhooks, snyk_api_tokens, google_api_keys

LOG = logging.getLogger(__name__)

SECRETS: dict[str, type[types.Checker]] = {
    "office_webhooks": office_webhooks.OfficeWebHookChecker,
    "snyk_api_tokens": snyk_api_tokens.SnykAPITokenChecker,
    "google_api_keys": google_api_keys.GoogleApiKeyChecker,
}


def add_args(parser: ArgumentParser) -> None:
    """Add arguments to the parser."""
    parser.add_argument('input_file', help='The file containing the list of secrets, one per line')
    parser.add_argument('secret_type', choices=SECRETS.keys(), help='The type of secret to check')
    parser.add_argument('--output-file', '-o', help='The output file')
    parser.add_argument('--notify', '-n', action="store_true", help='Whether to send notifications to the secret endpoint using the secret')
    parser.add_argument('--debug', '-d', action="store_true", help='Debug output on')


def main() -> None:
    """Main function."""
    parser = ArgumentParser()
    add_args(parser)
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.secret_type not in SECRETS:
        LOG.error(f'Unknown secret type {args.secret_type}')
        return

    checker: types.Checker = SECRETS[args.secret_type](args.notify, args.debug)

    writer = csv.writer(sys.stdout if args.output_file is None else open(args.output_file, 'w'))

    with open(args.input_file, 'r') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line:
                continue
            status = checker.check(line)

            status_text = "invalid"

            if status:
                status_text = "valid"
            elif status is None:
                status_text = "error"

            writer.writerow([line, args.secret_type, status_text])
