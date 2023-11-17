#!/usr/bin/env python3

import requests
from argparse import ArgumentParser
from typing import Optional
from urllib3.util.url import parse_url
import json
import defusedcsv as csv

import logging

LOG = logging.getLogger(__name__)


def add_args(parser: ArgumentParser) -> None:
    """Add arguments to the parser."""
    parser.add_argument('input_file', help='The file containing the list of Teams webhook URLs, one per line')
    parser.add_argument('--output-file', '-o', help='The output file')
    parser.add_argument('--notify', '-n', action="store_true", help='The output file')
    parser.add_argument('--debug', '-d', action="store_true", help='Debug output on')


class TeamsWebHookChecker:
    """Class to check if a Microsoft Teams Webhook is still valid."""
    def __init__(self, notify: bool=False) -> None:
        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'application/json'})
        self.notify = notify

    def check(self, url) -> Optional[bool]:
        """Check if a webhook is still valid."""

        # confirm the webhook is an office webhook
        parsed_url = parse_url(url)

        if parsed_url.host is None:
            LOG.error(f'Error for link {url}: not a valid URL, no host')
            return None

        if parsed_url.path is None:
            LOG.error(f'Error for link {url}: not a valid URL, no path')
            return None

        if not parsed_url.host.endswith('.webhook.office.com'):
            LOG.error(f'Error for link {url}: not a webhook.office.com link')
            return None

        if not parsed_url.path.startswith('/webhookb2/'):
            LOG.error(f'Error for link {url}: not a webhook.office.com link')
            return None

        url_to_check = parsed_url.url

        if url_to_check != url:
            LOG.error(f'URL {url} is not normalized, refusing to check URL')
            return None

        data = {}

        if self.notify:
            data['@type'] = 'MessageCard'
            data['@context'] = 'http://schema.org/extensions'
            data['summary'] = 'Teams webhook detected in leaked secret'
            data['themeColor'] = 'FF0000'
            data['title'] = 'Teams webhook detected in leaked secret'
            data['text'] = 'A Teams webhook for this channel has been detected in a secret leaked in GitHub.\n\nPlease delete the webhook and create a new one, and store the webhook URL in a secure location.\n\nSecrets such as webhooks should not be stored in code or related locations in the repository such as an issue.'

        response = requests.post(url_to_check, data=json.dumps(data))

        if not self.notify and response.status_code == 400 and response.text == 'Summary or Text is required.':
            return True
        elif self.notify and response.status_code == 200 and response.text == '1':
            return True
        elif response.status_code == 410:
            return False
        else:
            LOG.error(f'Error for link {url_to_check}: {response.text} ({response.status_code})')
            return None


def main():
    """Command-line entrypoint."""
    parser = ArgumentParser(description='Check a list of Teams webhook URLs for validity, and return the results as CSV.')
    add_args(parser)
    args = parser.parse_args()

    with open(args.input_file, 'r') as file:
        urls = file.read().splitlines()

    checker = TeamsWebHookChecker(notify=args.notify)

    writer = csv.csv.writer(sys.stdout if args.output_file is None else open(args.output_file, 'w'))

    for url in urls:
        status = checker.check(url)
        
        status_text = "invalid"

        if status:
            status_text = "valid"
        elif status is None:
            status_text = "error"

        writer.writerow([url, status_text])


if __name__ == "__main__":
    main()
