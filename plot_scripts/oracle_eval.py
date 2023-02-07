
#%%
from collections import defaultdict
import sqlite3

from helper import db_connect, fix_path, query, to_latex_table, out_path

default_db = db_connect("data/current/stats_all.db")
asan_db = db_connect("data/asan/stats_all.db")


#%%
default_res = default_db.execute("""
select run_results.exec_id, run_results.prog, funname, instr, fuzzer, run_ctr, covered_file_seen, covered_by_seed, time_found, found_by_seed from run_results
left join mutations
on run_results.exec_id is mutations.exec_id
    and run_results.prog is mutations.prog
    and run_results.mut_id is mutations.mutation_id
""")
default_columns = [dd[0] for dd in default_res.description]

asan_res = asan_db.execute("""
select run_results.exec_id, run_results.prog, funname, instr, fuzzer, run_ctr, covered_file_seen, covered_by_seed, time_found, found_by_seed from run_results
left join mutations
on run_results.exec_id is mutations.exec_id
    and run_results.prog is mutations.prog
    and run_results.mut_id is mutations.mutation_id
""")
asan_columns = [dd[0] for dd in asan_res.description]

assert default_columns == asan_columns

#%%
all_runs = list(default_res.fetchall())
asan_runs = list(asan_res.fetchall())

#%%
indices = {nn: ii for ii, nn in enumerate(default_columns)}

print(default_columns)
print(indices)

def get(run, name):
    return run[indices[name]]

#%%

all_progs = set()
all_fuzzers = set()
for run in all_runs:
    prog = get(run, "prog")
    fuzzer = get(run, "fuzzer")
    all_progs.add(prog)
    all_fuzzers.add(fuzzer)

print("all progs", all_progs)

#%%

def get_ctr(all_runs, keep):
    pairs = {}
    for run in all_runs:
        prog = get(run, "prog")
        fuzzer = get(run, "fuzzer")
        if not keep(prog, fuzzer):
            continue
        funname = get(run, "funname")
        instr = get(run, "instr")
        covered_file_seen = get(run, "covered_file_seen")
        covered_by_seed = get(run, "covered_by_seed")
        time_found = get(run, "time_found")
        found_by_seed = get(run, "found_by_seed")
        pairs[(prog, funname, instr, fuzzer)] = {
            "def_covered_by_seed": covered_by_seed,
            "def_covered_file_seen": covered_file_seen,
            "def_time_found": time_found,
            "def_found_by_seed": found_by_seed,
        }
    print("default results:", len(pairs))

    failed = 0
    asan_results = set()
    for run in asan_runs:
        prog = get(run, "prog")
        fuzzer = get(run, "fuzzer")
        if not keep(prog, fuzzer):
            continue
        funname = get(run, "funname")
        instr = get(run, "instr")
        covered_file_seen = get(run, "covered_file_seen")
        covered_by_seed = get(run, "covered_by_seed")
        time_found = get(run, "time_found")
        found_by_seed = get(run, "found_by_seed")
        key = (prog, funname, instr, fuzzer)
        asan_results.add(key)
        cur = pairs.get(key)
        if cur is not None:
            cur["asan_covered_by_seed"] = covered_by_seed
            cur["asan_covered_file_seen"] = covered_file_seen
            cur["asan_time_found"] = time_found
            cur["asan_found_by_seed"] = found_by_seed
        else:
            failed += 1

    pairs = {kk: vv for kk, vv in pairs.items() if kk in asan_results}
    print("default and asan results:", len(pairs))
    print(f"no match {failed}")


    ctr = defaultdict(lambda: 0)
    for pp in pairs.values():

        # skip everything that is not covered by both
        if not (pp['def_covered_by_seed'] == 1 and pp['asan_covered_by_seed'] == 1):
            continue

        ctr['total'] += 1

        if pp['def_covered_by_seed'] == 0 and pp['asan_covered_by_seed'] == 1:
            ctr['covered_by_seed_asan'] += 1

        if pp['def_covered_by_seed'] == 1 and pp['asan_covered_by_seed'] == 0:
            ctr['covered_by_seed_def'] += 1

        if pp['def_covered_by_seed'] == 1 and pp['asan_covered_by_seed'] == 1:
            ctr['covered_by_seed__both'] += 1


        if pp['def_covered_file_seen'] is None and pp['asan_covered_file_seen'] is not None:
            ctr['covered__asan'] += 1

        if pp['def_covered_file_seen'] is not None and pp['asan_covered_file_seen'] is None:
            ctr['covered__def'] += 1

        if pp['def_covered_file_seen'] is not None and pp['asan_covered_file_seen'] is not None:
            ctr['covered___both'] += 1


        if pp['def_found_by_seed'] == 1 and pp['asan_found_by_seed'] == 0:
            ctr['found_by_seed_def'] += 1

        if pp['def_found_by_seed'] == 0 and pp['asan_found_by_seed'] == 1:
            ctr['found_by_seed_asan'] += 1

        if pp['def_found_by_seed'] == 1 and pp['asan_found_by_seed'] == 1:
            ctr['found_by_seed__both'] += 1


        if pp['def_time_found'] is None and pp['asan_time_found'] is not None:
            ctr['found__asan'] += 1

        if pp['def_time_found'] is not None and pp['asan_time_found'] is None:
            ctr['found__def'] += 1

        if pp['def_time_found'] is not None and pp['asan_time_found'] is not None:
            ctr['found___both'] += 1

    ctr = sorted(ctr.items(), key=lambda x: x[0])
    return ctr

import csv
out_path = fix_path("plot/tmp_data/def_asan_results.csv")
out_path.parent.mkdir(exist_ok=True, parents=True)

with open(out_path, "w", newline='') as f:
    fields = [
        "prog", "fuzzer", "total",
        "covered___both", "covered__asan", "covered__def", "covered_by_seed__both",
        "covered_by_seed_asan", "covered_by_seed_def", "found___both", "found__asan",
        "found__def", "found_by_seed__both", "found_by_seed_asan", "found_by_seed_def"
    ]
    csv_writer = csv.DictWriter(f, fieldnames=fields, restval=0)

    csv_writer.writeheader()

    for prog in all_progs:
        print("="*50, "\n", prog)
        for fuzzer in all_fuzzers:
            ctr = get_ctr(all_runs, lambda a_prog, a_fuzzer: a_prog == prog and a_fuzzer == fuzzer)
            print("---", fuzzer)
            csv_writer.writerow({nn: vv for nn, vv in ctr} | {"prog": prog, "fuzzer": fuzzer})
            for nn, vv in ctr:
                print(nn, vv)

#%%

# import pandas as pd

# df = pd.read_csv("def_asan_results.csv")

# #%%

# df

# df[['prog', 'fuzzer', 'found___both', 'found__asan', 'found__def']].plot(kind='bar', subplots=True)


# #%%

# df.groupby(['prog']).plot(kind='bar', subplots=True)