#!/usr/bin/env /usr/bin/python
import secretstorage


def unlock_keyring(collection) -> None:
    if collection.is_locked():
        collection.unlock()
        if collection.is_locked():
            print("failed to unlock keyring")
        else:
            print("keyring unlocked")
    else:
        print("Keyring already unlocked")

def main():
    bus = secretstorage.dbus_init()
    collection = secretstorage.get_default_collection(bus)
    unlock_keyring(collection)

if __name__ == "__main__":
    main()
