#!/usr/bin/env python3

"""Validator for a Fodsels Nummer (Norwegian National Identity Number)."""

import re
import logging
from typing import Optional

from ..core.base import Checker

LOG = logging.getLogger(__name__)

# TODO: expand like in the custom pattern
FODSELSNUMMER_RE = re.compile(
    r"^(([04][1-9]|[15][0-9]|[26][0-9])(0[1-9]|1[0-2])|[37]0(0[469]|11)|[37][01](0[13578]|1[02]))[0-9]{2} ?[0-9]{3} ?[0-9]{2}$"
)


class FodselsNummerChecker(Checker):
    """Class to check if a Fodsels Nummer is valid."""

    name = "fodselsnummer"  # Not a GitHub secret type but still a validator we can use
    description = "Validates Norwegian National Identity Numbers (Fødselsnummer)"

    def check(self, number: str) -> Optional[bool]:
        number = number.replace(" ", "")
        if not FODSELSNUMMER_RE.match(number):
            return False
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
            LOG.error(f"Error for number {number}: not a valid number")
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

        return False
