#%%
import os
from pathlib import Path
import sqlite3

PREFIX = ""
if Path(os.getcwd()).name == "plot_scripts":
    PREFIX += "../"

print(os.getcwd())
db_path = PREFIX + "data/24_hours/stats_all.db"

print(db_path)
db = sqlite3.connect(db_path)
# asan_db = sqlite3.connect("data/asan/stats_all.db")


#%%
from collections import defaultdict
res = db.execute("""
select * from run_results
""")
default_columns = [dd[0] for dd in res.description]

all_runs = list(res.fetchall())

indices = {nn: ii for ii, nn in enumerate(default_columns)}

print(default_columns)
print(indices)

def get(run, name):
    return run[indices[name]]

#%%
progs = set()
fuzzers = set()
for run in all_runs:
    prog = get(run, "prog")
    fuzzer = get(run, "fuzzer")
    progs.add(prog)
    fuzzers.add(fuzzer)
fuzzers = list(fuzzers)
progs = list(progs)

#%%
totals = defaultdict(lambda: {
    'total': 0,
    **{ff: 0 for ff in fuzzers}
})

for run in all_runs:
    prog = get(run, "prog")
    fuzzer = get(run, "fuzzer")
    covered_file_seen = get(run, "covered_file_seen")
    covered_by_seed = get(run, "covered_by_seed")
    time_found = get(run, "time_found");
    found_by_seed = get(run, "found_by_seed")

    res = totals[prog]
    res['total'] += 1
    if time_found is not None:
        res[fuzzer] += 1

table = ""

table += f"Prog & Total & {' & '.join(fuzzers)} \\\\ \n"
table += f"\\hline \n"

for prog, dd in totals.items():
    table += f"{prog} & {dd['total']} & {' & '.join([str(dd[ff]) for ff in fuzzers])} \\\\ \n"
    # print(f"{prog} & {fuzzer} & {dd['total']} & {dd['found']}")

print(table)
with open(PREFIX + "plot/fig/24-hour.tex", 'wt') as f:
    f.write(table)