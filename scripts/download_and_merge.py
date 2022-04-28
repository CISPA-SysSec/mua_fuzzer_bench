#!/usr/bin/env python3

import os
import argparse
import sqlite3
from datetime import datetime
from pathlib import Path

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


def query(db, query):
    conn = sqlite3.connect(db)
    return conn.execute(query).fetchall()
    conn.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("result_dir")
    parser.add_argument("remote_servers", nargs='+')

    args = parser.parse_args()
    result_dir = DATA_BASE_DIR / args.result_dir
    remote_servers = sorted(set(args.remote_servers))

    print(f"Merging data with {result_dir}, loading from {remote_servers}")
    assert len(remote_servers) > 0, "Please specify the ssh remotes to load databases from, at least one."

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
    dbs_args = ' '.join(str(dd) for dd in dbs)

    run(f"./eval.py merge {combined_db} {dbs_args}")
    run(f"./eval.py plot --artifacts {combined_db}")


if __name__ == "__main__":
    main()