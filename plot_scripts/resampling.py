#%%
import sqlite3
from helper import db_connect, fix_path, query, to_latex_table, out_path, data_path

db = db_connect("data/current/stats_all.db")


#%%
sampling_results = query(db, """
select * from run_results
""")

#%%
all_runs_list = []

for run in sampling_results:
    prog = run.get("prog")
    fuzzer = run.get("fuzzer")
    covered_file_seen = run.get("covered_file_seen")
    covered_by_seed = run.get("covered_by_seed")
    time_found = run.get("time_found");
    found_by_seed = run.get("found_by_seed")
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

all_progs = data['prog'].unique()
all_fuzzers = data['fuzzer'].unique()

print(all_progs, all_fuzzers)

#%%

# Assert only covered are found
assert data[(data['covered'] == False) & (data['found'] == True)].shape[0] == 0

#%%
from collections import defaultdict
import json
from time import time
from pathlib import Path

sampling_results = defaultdict(lambda: defaultdict(lambda: {
    'cov_seed': [],
    'cov': [],
    'kill_seed': [],
    'kill': [],
}))

REPEATS = 1000

for prog in all_progs:
    for fuzzer in all_fuzzers:
        print(prog, fuzzer)
        pf_res = sampling_results[f"{prog}-{fuzzer}"]
        dd = data[(data['prog'] == prog) & (data['fuzzer'] == fuzzer)]
        sample_sizes = [int(pp * dd.shape[0]) for pp in (.1, .2, .3, .4, .5, .6, .7, .8, .9)]
        samples_sizes = [ss for ss in sample_sizes if dd.shape[0] >= ss]
        sample_sizes = sorted(sample_sizes)

        ss_res = pf_res[dd.shape[0]]
        sdd = dd
        expected_cov_seed =  sdd.loc[sdd['covered_by_seed'] == True].shape[0] / sdd.shape[0]
        expected_cov =       sdd.loc[sdd['covered']         == True].shape[0] / sdd.shape[0]
        expected_kill_seed = sdd.loc[sdd['found_by_seed']   == True].shape[0] / sdd.shape[0]
        expected_kill =      sdd.loc[sdd['found']           == True].shape[0] / sdd.shape[0]

        ss_res['cov_seed'].extend([0]*REPEATS)
        ss_res['cov'].extend([0]*REPEATS)
        ss_res['kill_seed'].extend([0]*REPEATS)
        ss_res['kill'].extend([0]*REPEATS)


        for ii, ss in enumerate(sample_sizes):
            start = time()
            ss_res = pf_res[ss]
            for _ in range(REPEATS):
                sdd = dd.sample(ss)
                ss_res['cov_seed'].append(
                    abs(expected_cov_seed  - sdd.loc[data['covered_by_seed'] == True].shape[0] / sdd.shape[0]))
                ss_res['cov'].append(
                    abs(expected_cov       - sdd.loc[data['covered']         == True].shape[0] / sdd.shape[0]))
                ss_res['kill_seed'].append(
                    abs(expected_kill_seed - sdd.loc[data['found_by_seed']   == True].shape[0] / sdd.shape[0]))
                ss_res['kill'].append(
                    abs(expected_kill      - sdd.loc[data['found']           == True].shape[0] / sdd.shape[0]))
            print(f"{ii + 1} / {len(sample_sizes)}: {ss}, {time() - start:.2f}")

#%%

with open(data_path("resampling.json"), "wt") as f:
    json.dump(sampling_results, f)

        # print("sample size:", exp_total)
        # print("Per Covered Seed:", ", ".join([f"{ee * 100:3.2f}" for ee in ss_res['cov_seed']]))
        # print("Per Covered:     ", ", ".join([f"{ee * 100:3.2f}" for ee in ss_res['cov']]))
        # print("Per Killed Seed: ", ", ".join([f"{ee * 100:3.2f}" for ee in ss_res['kill_seed']]))
        # print("Per Killed:      ", ", ".join([f"{ee * 100:3.2f}" for ee in ss_res['kill']]))
        # print()
        # print()
