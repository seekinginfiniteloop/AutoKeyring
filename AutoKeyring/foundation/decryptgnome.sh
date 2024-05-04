#!/bin/bash
## Script decrypts the key.jwe file and stores it in a temporary file. The script uses the  clevis decrypt  command to decrypt the key.jwe file. The decrypted key is stored in a temporary file located in the /run/user/$id/tempkey directory. 
## The script next changes the permissions of the temporary file to 400 and changes the ownership of the file to the user who is currently logged in.

# requires root permissions for clevis decrypt

USER_ID="$1"

# Only proceed for UIDs >= 1000 (typically human users)
if [ "$USER_ID" -ge 1000 ]; then
    # Convert UID back to username
    USER_NAME=$(getent passwd "$USER_ID" | cut -d: -f1)

    runuser -u $USER_NAME -- some-command
else
    echo "Login detected for system user with UID $USER_ID, no action taken."
fi


whoami=$(loginctl list-sessions --no-legend | awk '{print $3}' | head -1)
id=$(id -u)

key_path="/home/$whoami/.autokey/key.jwe"
decrypt_path="/run/user/$id/tempkey"


clevis decrypt tpm2 '{}' < "$key_path" > "$decrypt_path"
chmod 400 "$decrypt_path"
chown "$whoami":"$whoami" "$decrypt_path"
