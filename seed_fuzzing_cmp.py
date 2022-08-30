
import json
import sqlite3
import pandas as pd
from pathlib import Path
from collections import defaultdict

con = sqlite3.connect("data/run_22_04_11/stats_all.db")

run_results = pd.read_sql_query("select * from run_results", con)
print(run_results.head())

seed_dir = Path("seeds/seeds_coverage")
run_res = defaultdict(list)
for rr in run_results[['exec_id', 'prog', 'fuzzer', 'mut_id', 'covered_by_seed', 'found_by_seed']].itertuples():
    if rr[5] == 1:
        run_res[(rr[2], rr[3])].append(rr[4])
    # index = (rr[0][1], rr[0][2])
    # cov = rr[1]['covered_by_seed']
    # found = rr[1]['found_by_seed']
    # run_res[index] = (cov, found)

run_data = []
for res_json in seed_dir.glob("info_*.json"):
    with open(res_json, 'rt') as f:
        run_data.extend(json.load(f))

bucketed = defaultdict(list)
for dd in run_data:
    bucketed[(dd['prog'], dd['fuzzer'])].append(dd)

data = defaultdict(lambda: defaultdict(dict))
for (prog, fuzzer), bb in bucketed.items():
    if prog != 'cares_name':
        continue

    sorted_bb = sorted(bb, key=lambda x: len(x['covered_mutations']))
    median_bb = sorted_bb[len(sorted_bb)//2]
    bb = median_bb

    covered_during_runs = bb['covered_mutations']

    data[bb['prog']][bb['fuzzer']] = median_bb

all_progs = sorted(set(data.keys()))
all_fuzzers = sorted(set(kk for dd in data.values() for kk in dd.keys()))

print(data.keys())

# res_table = ""

# all_fuzzers_str = ' & '.join(all_fuzzers)
# res_table += rf"Program &   \#Type &&   {all_fuzzers_str} \\" + "\n"
# res_table += r"\midrule" + "\n"


# seed coverage fuzzing
    # fuzzing by fuzzer for coverage (vanilla binary)
    # binary triggers only used to get num covered mutation             <- mutations ids in json
    # get mutationlocation binary
    # take median run of the the 11 runs per fuzzer
    # -> this run is the seed corpus for later runs
# = seed inputs

# testing fuzzer intelligence
    # vanilla binary
    # get mutationlocation binary -> json
    # for mut
        # mutated binary
        # for each fuzzer instrumented mutated binary 
        # first execute seed corpus -> num covered (mutated binary)       <- mutations ids covered during run
        # vanilla binary -> 0 || mutated binary -> !0 -> killed mutant
        # fuzzing -> crashing inputs ^


for ii, pp in enumerate(all_progs):
#     f_line = rf"\multirow{{4}}{{*}}{{{pp}}} & F: &"
#     m_line = rf"                     & M: &"
#     k_line = rf"                     & K: &"
#     l_line = rf"                     & L: &"

    for ff in all_fuzzers:
        json_res = data[pp][ff]
        json_covered = set(json_res['covered_mutations'])
        run_covered = set(run_res[(pp, ff)])
        json_covered_set = set(int(mm) for mm in json_covered)
        run_covered_set = set(run_covered)
        print(pp, ff,
            "\nonly in json:", sorted(json_covered_set - run_covered_set),
            "\nonly during runs:", sorted(run_covered_set - json_covered_set))
        # print(len(run_covered), len(seed_covered))
        # print(len(run_covered ^ seed_covered))
#         f_line += f" & {num_seeds}"
#         m_line += f" & {covered_mutations} / {seed_res[(pp, ff)][0]}"
#         k_line += f" & {seed_res[(pp, ff)][1]}"
#         l_line += f" & {covered_lines}"

#     # max_num_mutations = "---"
#     # max_num_lines = "---"
#     # f_line += rf" & & \\"
#     # m_line += rf" & & {max_num_mutations} \\"
#     # l_line += rf" & & {max_num_lines} \\"

#     f_line += rf" \\"
#     m_line += rf" \\"
#     k_line += rf" \\"
#     l_line += rf" \\"
#     res_table += f_line + "\n"
#     res_table += m_line + "\n"
#     res_table += k_line + "\n"
#     res_table += l_line + "\n"
#     if ii < len(all_progs) - 1:
#         res_table += r"\cmidrule{4-7}" + "\n"

# with open(out_dir/"seed-stats.tex", "wt") as f:
#     f.write(res_table)