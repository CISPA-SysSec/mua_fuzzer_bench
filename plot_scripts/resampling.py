#%%
import sqlite3

db = sqlite3.connect("data/current/stats_all.db")


#%%
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
all_runs_list = []

for run in all_runs:
    prog = get(run, "prog")
    fuzzer = get(run, "fuzzer")
    covered_file_seen = get(run, "covered_file_seen")
    covered_by_seed = get(run, "covered_by_seed")
    time_found = get(run, "time_found");
    found_by_seed = get(run, "found_by_seed")
    all_runs_list.append({
        'prog': prog,
        'fuzzer': fuzzer,
        'covered': covered_file_seen is not None,
        'covered_by_seed': bool(covered_by_seed),
        'found': time_found is not None,
        'found_by_seed': bool(found_by_seed),
    })

#%%
import pandas as pd
data = pd.DataFrame.from_records(all_runs_list)

progs = data['prog'].unique()
fuzzers = data['fuzzer'].unique()

print(progs, fuzzers)

print(data[data['prog'] == 're2'])

#%%

# Assert only covered are found
assert data[(data['covered'] == False) & (data['found'] == True)].shape[0] == 0

#%%
dd = data[(data['prog'] == 're2') & (data['fuzzer'] == 'aflpp')]

#%%
from collections import defaultdict
import json
from time import time
from pathlib import Path

# sample_sizes = [10, 100, 500, 1000, 2000, 3000, 4000, 5000] + [int(pp * dd.shape[0]) for pp in (.01, .02, .05, .1, .2, .3, .4, .5, .6, .7, .8, .9, 1)]
sample_sizes = [int(pp * dd.shape[0]) for pp in (.1, .2, .3, .4, .5, .6, .7, .8, .9, 1)]
samples_sizes = [ss for ss in sample_sizes if dd.shape[0] >= ss]
sample_sizes = sorted(sample_sizes)
print(sample_sizes)

res = defaultdict(lambda: {
    'cov_seed': [],
    'cov': [],
    'kill_seed': [],
    'kill': [],
})

for ii, ss in enumerate(sample_sizes):
    start = time()
    ss_res = res[ss]
    for _ in range(1000):
        sdd = dd.sample(ss)
        ss_res['cov_seed'].append(sdd.loc[data['covered_by_seed'] == True].shape[0] / sdd.shape[0])
        ss_res['cov'].append(sdd.loc[data['covered'] == True].shape[0] / sdd.shape[0])
        ss_res['kill_seed'].append(sdd.loc[data['found_by_seed'] == True].shape[0] / sdd.shape[0])
        ss_res['kill'].append(sdd.loc[data['found'] == True].shape[0] / sdd.shape[0])
    print(f"{ii + 1} / {len(sample_sizes)}: {ss}, {time() - start:.2f}")

out_path = Path("plot/tmp_data/resampling.json")
out_path.parent.mkdir(parents=True, exist_ok=True)
with open(out_path, "wt") as f:
    json.dump(res, f)

    # print("sample size:", exp_total)
    # print("Per Covered Seed:", ", ".join([f"{ee * 100:3.2f}" for ee in ss_res['cov_seed']]))
    # print("Per Covered:     ", ", ".join([f"{ee * 100:3.2f}" for ee in ss_res['cov']]))
    # print("Per Killed Seed: ", ", ".join([f"{ee * 100:3.2f}" for ee in ss_res['kill_seed']]))
    # print("Per Killed:      ", ", ".join([f"{ee * 100:3.2f}" for ee in ss_res['kill']]))
    # print()
    # print()
