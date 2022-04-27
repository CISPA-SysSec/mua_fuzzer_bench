#!/usr/bin/env bash

set -Eeuo pipefail

COMBINED_DB_NAME="stats_all"

if [ "$#" == 0 ]; then
    echo "Specify target folder."
    exit 1
fi

TARGET="$1"
RESULT_DIR="data/$TARGET"
CUR_RESULT_DIR="$RESULT_DIR/$(date '+%Y_%m_%d_%H:%M')"

echo "Writing data to $RESULT_DIR"

shift

if [ "$#" == 0 ]; then
    echo "Please specify the ssh remotes to load databases from, at least one."
    exit 1
fi

remotes=( "$@" )

echo "Downloading dbs from: ${remotes[*]}"

mkdir -p "$CUR_RESULT_DIR"

for remote in "${remotes[@]}"; do
    db_path="$(pwd)/$CUR_RESULT_DIR/stats_$remote.db"
    (ssh "$remote" 'cp /dev/shm/mutator/stats.db /dev/shm/mutator/stats_copy.db' && \
        scp "$remote":/dev/shm/mutator/stats_copy.db "$db_path") &
    active_db="$RESULT_DIR/$remote"
    touch "$active_db" && rm "$active_db"
    ln -s "$db_path" "$active_db"
done

wait

echo "Merging dbs:"

db_paths=()
for db in "$RESULT_DIR"/*; do
    if [[ -f "$db" && ! $(basename "$db") =~ ^$COMBINED_DB_NAME ]]; then
        num_execs=$(sqlite3 ${db} "select count() from progs;")
        if (( num_execs != 1 )); then
            echo "$db has $num_execs executions, exactly one expected"
            exit
        fi
        exec=$(sqlite3 ${db} "select prog from progs;")
        normalized_db="${RESULT_DIR}/${exec}.db"
        mv "${db}" "${normalized_db}" || true
        if [[ " ${db_paths[*]} " =~ " ${normalized_db} " ]]; then
            continue
        fi
        echo "will merge db: $normalized_db"
        db_paths+=("$normalized_db")
    fi
done

COMBINED_DB="$RESULT_DIR/$COMBINED_DB_NAME.db"

./eval.py merge "$COMBINED_DB" "${db_paths[@]}"

echo "Plotting merged db:"

./eval.py plot "$COMBINED_DB"
