#%%
import os
from pathlib import Path
import sqlite3

from helper import db_connect, fix_path, out_path, query

all_queries = []
for pp in [
    # "data/24_hours_2/stats_all.db",
    # "data/24_hours_3/stats_all.db",
    "data/24_3/stats_all.db",
]:
    db = db_connect(pp)
    all_queries.append(query(db, """
        select * from run_results
    """))

#%%
progs = set()
fuzzers = set()
for runs in all_queries:
    for run in runs:
        prog = run.get("prog")
        fuzzer = run.get("fuzzer")
        progs.add(prog)
        fuzzers.add(fuzzer)

fuzzers = list(fuzzers)
progs = list(progs)

print(fuzzers)
print(progs)

#%%
from collections import defaultdict
totals = defaultdict(lambda: {
    'total': set(),
    **{ff: set() for ff in fuzzers},
    'err': set()
})

for runs in all_queries:
    for run in runs:
        prog = run.get("prog")
        fuzzer = run.get("fuzzer")
        covered_file_seen = run.get("covered_file_seen")
        covered_by_seed = run.get("covered_by_seed")
        time_found = run.get("time_found");
        found_by_seed = run.get("found_by_seed")
        seed_timeout = run.get("seed_timeout")
        mut_id = run.get("mut_id")

        res = totals[prog]
        res['total'].add(mut_id)
        if time_found is not None:
            res[fuzzer].add(mut_id)
        if seed_timeout is not None:
            print("err for", prog, mut_id, fuzzer)
            res['err'].add(mut_id)

filtered_totals = defaultdict(lambda: {
    'total': 0,
    **{ff: 0 for ff in fuzzers},
})

for prog, dd in totals.items():
    ft = filtered_totals[prog]
    filtered_total_muts =dd['total'] - dd['err'] 
    ft['total'] = len(filtered_total_muts)
    for ff in fuzzers:
        ft[ff] = len(dd[ff] & filtered_total_muts)

table = ""

table += f"Prog & Total & {' & '.join(fuzzers)} \\\\ \n"
table += f"\\midrule \n"

for prog, dd in filtered_totals.items():
    table += f"{prog} & {dd['total']} & {' & '.join([str(dd[ff]) for ff in fuzzers])} \\\\ \n"
    # print(f"{prog} & {fuzzer} & {dd['total']} & {dd['found']}")

print(table)
with open(out_path("24-hour.tex"), 'wt') as f:
    f.write(table)