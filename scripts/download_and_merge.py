#!/usr/bin/env python3

import os
import argparse
import sqlite3
from datetime import datetime
from pathlib import Path
import subprocess
import sys
from typing import Any, List, Set

DATA_BASE_DIR = Path("./data")
COMBINED_DB_NAME = "stats_all"


def run(cmd):
    # print(cmd)
    assert os.system(cmd) == 0


def download_from_server(result_dir, download_dir, server):
    db_path=download_dir / f"{server}.db"
    run(f"""ssh "{server}" 'cp /dev/shm/mutator/stats.db /dev/shm/mutator/stats_copy.db'""")
    run(f'''scp "{server}":/dev/shm/mutator/stats_copy.db "{db_path}"''')

    exec_ids = query(db_path, "select exec_id from execution")
    assert len(exec_ids) == 1
    exec_id_db = result_dir / f"{exec_ids[0][0]}.db"

    run(f'''ln -sfn "{db_path.resolve()}" "{exec_id_db}"''')


def query(db: Path, query: str) -> List[Any]:
    conn = sqlite3.connect(db)
    return conn.execute(query).fetchall()


def get_tables_of_db(db: Path) -> Set[Any]:
    return set(rr[0] for rr in query(db, "select name from sqlite_master where type == 'table'"))


def merge_dbs(out_path: Path, in_paths: List[Path]) -> None:
    out_db_path = Path(out_path)
    if out_db_path.is_file():
        print(f"Removing file: {out_db_path}")
        out_db_path.unlink()

    # copy the first database
    proc = subprocess.run(f'sqlite3 {in_paths[0]} ".dump" | sqlite3 {out_path}',
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode != 0:
        print("Failed to copy the first db.", proc)
        sys.exit(1)

    main_tables = get_tables_of_db(in_paths[0])

    # copy all data
    for in_db in in_paths[1:]:
        assert main_tables == get_tables_of_db(in_db)

        inserts = "\n".join((f"insert into {table} select * from to_merge.{table};" for table in main_tables))
        command = f'''sqlite3 {out_db_path} "
attach '{in_db}' as to_merge;
BEGIN;
{inserts}
COMMIT;
detach to_merge;"'''
        proc = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if proc.returncode != 0:
            print(f"Failed to merge the db. {proc}")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("result_dir")
    parser.add_argument("remote_servers", nargs='*')

    args = parser.parse_args()
    result_dir = DATA_BASE_DIR / args.result_dir
    remote_servers = sorted(set(args.remote_servers))

    print(f"Merging data with {result_dir}, loading from {remote_servers}")
    if len(remote_servers) > 0:
        download_dir = result_dir / datetime.now().strftime("%Y_%m_%d-%H:%M:%S")
        download_dir.mkdir(parents=True)

        for rs in remote_servers:
            download_from_server(result_dir, download_dir, rs)

    dbs = list(pp for pp in result_dir.glob("*.db") if pp.stem != COMBINED_DB_NAME)
    print(f"Resulting dbs:")
    progs = set()
    for dd in dbs:
        print(dd)
        dd_hostname = query(dd, "select hostname from execution")
        dd_hostname = dd_hostname[0][0]
        print(dd_hostname)

        dd_progs = query(dd, "select prog from progs")
        for ddp in dd_progs:
            ddp = ddp[0]
            print(ddp)
            assert ddp not in progs
            progs.add(ddp)

    combined_db = result_dir / f"{COMBINED_DB_NAME}.db"

    print(f"Merging to {combined_db} from {dbs}")
    merge_dbs(combined_db, dbs)

    print(f"Executing eval script on: {combined_db}")
    con = sqlite3.connect(combined_db)
    with open("eval.sql", "rt") as f:
        cur = con.cursor()
        cur.executescript(f.read())
    # run(f"./eval.py plot --artifacts --seed-dir seeds/seeds_coverage/ {combined_db}")


if __name__ == "__main__":
    main()