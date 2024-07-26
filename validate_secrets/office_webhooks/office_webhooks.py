#!/usr/bin/env python3

"""Validator for Microsoft Office incoming webhook URLs."""

import sys
import requests
from typing import Optional
from urllib3.util.url import parse_url
import json
import logging
from .. import types

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class OfficeWebHookChecker(types.Checker):
    """Class to check if a Microsoft Teams Webhook is still valid."""
    def __init__(self, notify: bool=False, debug=False) -> None:
        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'application/json'})
        self.notify = notify

        if debug:
            LOG.setLevel(logging.DEBUG)

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
            data['summary'] = 'Webhook detected as leaked secret'
            data['themeColor'] = 'FF0000'
            data['title'] = 'Webhook detected as leaked secret'
            data['text'] = 'This webhook has been detected as a secret leaked in GitHub.\n\nPlease delete the Incoming Webhook connector with the name shown at the top of this message and create a new one.\n\nYou should store the new webhook URL in a secure location.\n\nSecrets such as webhooks should not be stored in code or related locations in the repository such as an issue.'

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
