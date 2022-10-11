#%%
from argparse import ArgumentParser
import json
from pathlib import Path
from collections import defaultdict
from typing import List, Optional
import pandas as pd

from helper import db_connect, fix_path, query, to_latex_table, out_path

args = ArgumentParser("")
args.add_argument("db_path")
args.add_argument("out_name")

args = args.parse_args()

con = db_connect(args.db_path)
seed_dir = fix_path("seeds/seeds_coverage/")
print(seed_dir)

run_results = pd.read_sql_query("select * from run_results", con)

#%%

full_res = {}
for rr in run_results[['exec_id', 'prog', 'fuzzer', 'mut_id', 'covered_by_seed', 'found_by_seed']
    ].groupby(['exec_id', 'prog', 'fuzzer']
    )['covered_by_seed', 'found_by_seed'].sum().iterrows():
    index = (rr[0][1], rr[0][2])
    cov = rr[1]['covered_by_seed']
    found = rr[1]['found_by_seed']
    full_res[index] = (cov, found)

all_progs = sorted(set(pp for pp, ff in full_res.keys()))

run_data = []
for res_json in seed_dir.glob("info_*.json"):
    with open(res_json, 'rt') as f:
        run_data.extend(json.load(f))

bucketed = defaultdict(list)
for dd in run_data:
    bucketed[(dd['prog'], dd['fuzzer'])].append(dd)

seed_data = defaultdict(lambda: defaultdict(dict))
for _, bb in bucketed.items():
    sorted_bb = sorted(bb, key=lambda x: len(x['covered_mutations']))
    median_bb = sorted_bb[len(sorted_bb)//2]
    bb = median_bb
    seed_data[bb['prog']][bb['fuzzer']] = median_bb

prog_fuzzer_stats = pd.read_sql_query("SELECT * from run_results_by_prog_and_fuzzer", con)
# print(prog_fuzzer_stats.loc[(prog_fuzzer_stats['fuzzer'] == "afl") & (prog_fuzzer_stats['prog'] == "curl")])

all_fuzzers = sorted(set(kk for dd in seed_data.values() for kk in dd.keys()))

#res_table += rf"Program &   \#Type &&   {all_fuzzers_str} \\" + "\n"

table_lines = []
headers = [rf'Program', r'\#Mutations', 'Fuzzer', r'Phase~I Covered', r'Phase~I Killed', r'Phase~II Covered', r'Phase~II Killed', r'Total Covered', r'Total Killed']
table_lines.append(headers)
num_columns = len(headers)
table_lines.append(fr"\cmidrule{{1-{num_columns}}}")
table_suffixes = [None]*2

for ii, pp in enumerate(all_progs):
    lines = []
    for _ in range(len(all_fuzzers) + 1):
        lines.append([None]*len(headers))

    # add prog name
    lines[0][0] = rf"\multirow{{5}}{{*}}{{{pp}}}"

    combined_covered_lines = set()
    total_muts_list = []

    for ffii, ff in enumerate(all_fuzzers):
        seed_fuzzer_data = seed_data[pp][ff]
        # covered_mutations = len(seed_fuzzer_data['covered_mutations'])
        covered_lines = set(tuple(ll) for ll in seed_fuzzer_data['kcov_res']['covered_lines'])
        combined_covered_lines |= covered_lines
        covered_lines = len(covered_lines)
        # num_seeds = seed_fuzzer_data['num_seeds_minimized']
        this_prog_fuzzer = prog_fuzzer_stats.loc[(prog_fuzzer_stats['fuzzer'] == ff) & (prog_fuzzer_stats['prog'] == pp)]
        covered_seed = full_res[(pp, ff)][0]
        killed_seed = full_res[(pp, ff)][1]
        covered_dyn = this_prog_fuzzer['c_by_f'].iat[0]
        killed_dyn = this_prog_fuzzer['f_by_f'].iat[0]
        crashed = this_prog_fuzzer['crashed'].iat[0]
        covered_total = covered_seed + covered_dyn
        killed_total = killed_seed + killed_dyn
        total_muts = this_prog_fuzzer['total'].iat[0]
        total_muts_list.append(total_muts)
        
        if ffii > 0:
            lines[ffii][0] = ""
            lines[ffii][1] = ""
        lines[ffii][2] = f"{ff}"
        # lines[ffii][3] = f"{num_seeds:,}"                # files after minimization
        # lines[ffii][4] = f"{covered_lines:,}"            # covered lines
        lines[ffii][3] = f"{covered_seed:,}"  # covered by seed
        lines[ffii][4] = f"{killed_seed:,}"    # killed by seed
        lines[ffii][5] = f"{covered_dyn:,}"
        lines[ffii][6] = f"{killed_dyn:,}"
        lines[ffii][7] = f"{covered_total:,}"
        lines[ffii][8] = f"{killed_total:,}"
        # lines[ffii] += f" & {crashed:,}"

    assert all(el == total_muts_list[0] for el in total_muts_list)
    lines[0][1] = rf"\multirow{{5}}{{*}}{{{total_muts_list[0]}}}"

    lines[-1][0] = ""
    lines[-1][1] = ""

    seed_covered = len(pd.read_sql_query(f"""
    select * from run_results
    where prog like "{pp}" and covered_by_seed is 1
    group by mut_id
    """, con))

    seed_killed = len(pd.read_sql_query(f"""
    select * from run_results
    where prog like "{pp}" and found_by_seed is 1
    group by mut_id
    """, con))

    all_covered = len(pd.read_sql_query(f"""
    select * from run_results
    where prog like "{pp}" and covered_file_seen is not null
    group by mut_id
    """, con))

    all_killed = len(pd.read_sql_query(f"""
    select * from run_results
    where prog like "{pp}" and confirmed is 1
    group by mut_id
    """, con))

    lines[-1][2] = f"\\g{{\\textbf{{combined}}}}"
    # lines[-1][3] = "\\g{{ }}"
    # lines[-1] = f" & {len(combined_covered_lines):,}"            # covered lines
    lines[-1][3] = f"\\g{{{seed_covered:,}}}"  # covered by seed
    lines[-1][4] = f"\\g{{{seed_killed:,}}}"    # killed by seed
    lines[-1][5] = "\\g{{ }}" # f"\\g{{{all_covered - seed_covered:,}}}"
    lines[-1][6] = "\\g{{ }}" # f"\\g{{{all_killed - seed_killed:,}}}"
    lines[-1][7] = f"\\g{{{all_covered:,}}}"
    lines[-1][8] = f"\\g{{{all_killed:,}}}"
    # lines[-1] += f" & {total_muts:,}"

    # lines.insert(-1, fr"\cmidrule{{3-{num_columns}}}")
    # if ii < len(all_progs) - 1:
    #     lines.append(fr"\cmidrule{{1-{num_columns}}}")

    hlines = [None]*len(lines)
    if ii < len(all_progs) - 1:
        hlines[-1] = fr"\cmidrule{{3-{num_columns}}}"
    table_suffixes.extend(hlines)

    table_lines.extend(lines)

#%%

with open(out_path(args.out_name), "wt") as f:
    f.write(to_latex_table(table_lines, suffixes=table_suffixes))
