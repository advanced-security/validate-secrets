#!/usr/bin/env python3

"""Validator for a Fodsels Nummer (Norwegian National Identity Number)."""

import sys
from typing import Optional
import re
import logging
from .. import types

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


# TODO: expand like in the custom pattern
FODSELSNUMMER_RE = re.compile(r'^(([04][1-9]|[15][0-9]|[26][0-9])(0[1-9]|1[0-2])|[37]0(0[469]|11)|[37][01](0[13578]|1[02]))[0-9]{2} ?[0-9]{3} ?[0-9]{2}$')


class FodselsNummerChecker(types.Checker):
    """Class to check if a Fodsels Nummer is valid."""
    def __init__(self, notify: bool=False, debug=False) -> None:
        self.notify = notify

        if debug:
            LOG.setLevel(logging.DEBUG)

    def check(self, number: str) -> Optional[bool]:
        """Check if a Fodels Nummer is valid."""
        number = number.replace(' ', '')

        # check the format against the regex
        if not FODSELSNUMMER_RE.match(number):
            return None

        # check the number against the checksum algorithm
        return self._validate_checksum(number)

    @staticmethod
    def _calculate_checksum(number):
        """Calculate checksum of a Fodels Nummer."""
        # The checksum is calculated by multiplying each digit by a weight and summing the results
        weights = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2]
        checksum = 0

        try:
            for i in range(9):
                checksum += int(number[i]) * weights[i]
        except (ValueError, IndexError):
            LOG.error(f'Error for number {number}: not a valid number')
            return None

        remainder = checksum % 11
        return 0 if remainder == 0 else 11 - remainder

    @staticmethod
    def _validate_checksum(number):
        """Validate checksum of a Fodels Nummer."""
        checksum = FodselsNummerChecker._calculate_checksum(number)

        if checksum is None:
            return None

        if checksum == int(number[10]):
            return True

        return None
