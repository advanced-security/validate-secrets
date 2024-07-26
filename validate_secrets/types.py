from typing import Optional

class Checker():
    def __init__(self, notify: bool=False, debug=False) -> None:
        self.notify = notify
        self.debug = debug

    def check(self, secret) -> Optional[bool]:
        return None

    def __str__(self):
        return self.__class__.__name__

    def __repr__(self):
        return self.__str__()