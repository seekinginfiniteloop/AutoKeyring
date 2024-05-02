#!/usr/bin/env /usr/bin/python
import sys

from typing import Literal

import secretstorage


def keyring_is_locked(collection) -> Literal[1] | Literal[0]:

    return 1 if collection.is_locked() else 0

def main() -> sys.NoReturn:
    bus = secretstorage.dbus_init()
    collection = secretstorage.get_default_collection(bus)
    exit_status = keyring_is_locked(collection)
    sys.exit(exit_status)

if __name__ == "__main__":
    main()
