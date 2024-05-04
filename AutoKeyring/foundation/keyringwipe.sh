#!/bin/bash
sleep 120

RANDOM_STRING=$(openssl rand -base64 32 | tr -d '=/+')
echo "${RANDOM_STRING}"
echo -n "${RANDOM_STRING}" | xclip -selection clipboard
echo "xclip wipe: {$?}"
shred -ufz /tmp/temppw
echo "shred: {$?}"
echo '' >&2
