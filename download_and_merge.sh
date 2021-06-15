#!/usr/bin/env bash

set -Eeuo pipefail

if [ "$#" == 0 ]; then
    echo "Please specify the ssh remotes to load databases from, at least one."
    exit 1
fi

remotes=( "$@" )

echo "Downloading dbs from: ${remotes[*]}"

rm -rf /tmp/mutator_dbs/
mkdir -p /tmp/mutator_dbs/

db_paths=()

for remote in "${remotes[@]}"; do
    db_path="/tmp/mutator_dbs/stats_$remote.db"
    (ssh "$remote" 'cp /dev/shm/mutator/stats.db /dev/shm/mutator/stats_copy.db' && \
        scp "$remote":/dev/shm/mutator/stats_copy.db "$db_path") &
    db_paths+=("$db_path")
done

wait

echo "Merging dbs:"

./eval.py merge ~/stats_all.db "${db_paths[@]}"

echo "Plotting merged db:"

./eval.py plot ~/stats_all.db

