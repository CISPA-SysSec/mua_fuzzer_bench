#!/usr/bin/env bash

set -Eeuo pipefail

for seed_file in "$3"/*; do
    echo "$seed_file"
    TRIGGERED_FOLDER="$1" "$2" "$seed_file"
done