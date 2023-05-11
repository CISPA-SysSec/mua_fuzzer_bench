#%%
import sqlite3

db = sqlite3.connect("data/asan/stats_all.db")

q = db.execute("select * from run_results")
data = q.fetchall()
columns = [dd[0] for dd in q.description]

#%%
indices = {nn: ii for ii, nn in enumerate(columns)}

print(columns)
print(indices)

def get(run, name):
    return run[indices[name]]

#%%
import json
from collections import defaultdict
done_runs = defaultdict(set)
ii = 1
while True:
    runs_path = f"24_hour_runs_{ii:02}.json"
    print(runs_path)

    try:
        with open(runs_path) as f:
            cur_runs = json.load(f)
            for kk, vv in cur_runs.items():
                done_runs[kk] |= set(vv['ids'])
    except FileNotFoundError:
        break

    ii += 1


#%%
from collections import defaultdict

candidates = defaultdict(set)

for run in data:
    prog = get(run, "prog")
    fuzzer = get(run, "fuzzer")
    mut_id = get(run, "mut_id")
    covered_file_seen = get(run, "covered_file_seen")
    covered_by_seed = get(run, "covered_by_seed")
    time_found = get(run, "time_found")
    found_by_seed = get(run, "found_by_seed")
    crashed = get(run, "crashed")
    seed_timeout = get(run, "seed_timeout")
    if covered_file_seen is not None and time_found is None and crashed is None and seed_timeout is None and mut_id not in done_runs[prog]:
        candidates[(prog, mut_id)].add(fuzzer)


#%%

len(candidates)

all_covered_candidates = {kk: vv for kk, vv in candidates.items() if len(vv) == 4}

len(all_covered_candidates)


#%%

import json
import random

runs_todo = defaultdict(lambda: {'ids': [], 'mode': 'single'})

for prog, m_id in all_covered_candidates:
    runs_todo[prog]['ids'].append(m_id)

for pp, dd in runs_todo.items():
    dd['ids'] = random.sample(dd['ids'], k=min(104, len(dd['ids'])))
    print(pp, len(dd['ids']))

#%%

with open(runs_path, "wt") as f:
    json.dump(runs_todo, f, indent=2)
