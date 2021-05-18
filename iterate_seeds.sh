#!/usr/bin/env bash

set -Eeuo pipefail

ls -la samples/file_harness/

IFS=$'\n'
for args in $3; do
    OLDIFS=$IFS
    IFS=' ' read -ra args_array <<< "$args"
    IFS=$OLDIFS
    echo "executing:" "$2" ${args_array[@]}
    TRIGGERED_FOLDER="$1" "$2" ${args_array[@]}
done
