#%%
from collections import defaultdict
from helper import db_connect, fix_path, query, to_latex_table, out_path, data_path

con = db_connect("data/current/stats_all.db")

run_results = query(con, "select * from run_results")

#%%

all_fuzzers = set()
all_found = defaultdict(set)
count = defaultdict(int)

for rr in run_results:
    exec_id = rr.get("exec_id")
    prog = rr.get("prog")
    mut_id = rr.get("mut_id")
    fuzzer = rr.get("fuzzer")
    killed = rr.get("confirmed")
    complete = rr.get("complete")
    max_complete = rr.get("max_len")

    if complete == max_complete:
        count['total'] += 1
        if killed is not None:
            all_fuzzers.add(fuzzer)
            key = (exec_id, prog, mut_id)
            all_found[key].add(fuzzer)
            count[fuzzer] += 1

print(count)

#%%
all_found_list = defaultdict(list)
for kk, fuzzers_found in all_found.items():
    for ff in all_fuzzers:
        if ff in fuzzers_found:
            res = True
        else:
            res = False
        all_found_list[ff].append(res)

#%%
import json

TRANSLATE_FUZZERS = {
    'afl': 'AFL',
    'aflpp': 'AFL++',
    'honggfuzz': 'Honggfuzz',
    'libfuzzer': 'libFuzzer',
}

with open(data_path("wayne.json"), "wt") as f:
    json.dump(all_found_list, f)
