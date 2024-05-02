#!/bin/bash

# Must be run as user, not root

# For debugging:
# log=~/key.log
# echo "Starting keyringlaunch.sh" >> $log

# set path to our password
key_path="/run/user/$UID/tempkey"
logged_in_user=$LOGNAME || $USER || $USERNAME

timer () {
    sleep 6
}

get_env_var() {
    # Get the value of an environment variable from a process
    local pid=$1
    local var=$2
    local value
    value=$(cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n' | grep "^$var=" | cut -d= -f2-)
    echo "$value"  # Return the value
}

# Try to find a running graphical process to steal environment variables from
get_display() {
    local pids
    for pid in $pids; do
        DISPLAY=$(get_env_var "$pid" DISPLAY)
        XAUTHORITY=$(get_env_var "$pid" XAUTHORITY)
        if [ -n "$DISPLAY" ] && [ -n "$XAUTHORITY" ]; then
            break
        fi
    done
    # echo "DISPLAY: $DISPLAY" >> $log
    if [ -z "$DISPLAY" ] || [ -z "$XAUTHORITY" ]; then
    # echo "Failed to find DISPLAY and XAUTHORITY variables." >> $log
    exit 1
fi
    echo "$DISPLAY" "$XAUTHORITY"
}

timer
# Get PIDs
pids=$(pgrep -u "$logged_in_user" gnome-shell)
get_display "$pids"
export DISPLAY=$1
export XAUTHORITY=$2

echo "$DISPLAY $XAUTHORITY"

< "$key_path" tr -d '\n\t ' 2>/dev/null | /usr/bin/xclip -i -selection clipboard

# "/usr/local/bin/unlock_keyring.py"
