#!/bin/bash

#  check if default keyring is locked
/usr/local/bin/check_lock.py

if [ $? -eq 1 ]; then
	echo "Keyring locked; let's get our keyring back."
	systemctl start gnomekey.service &&
	systemctl start keyunlock.service &&
	systemctl start keywipe.service
fi
