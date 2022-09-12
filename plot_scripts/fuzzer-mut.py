#%%
from dataclasses import dataclass
import os
from pathlib import Path
import sqlite3
from typing import List, Optional
from helper import db_connect, fix_path, query, out_path, to_latex_table

def_con = db_connect(fix_path("data/current/stats_all.db"))
asan_con = db_connect(fix_path("data/asan/stats_all.db"))

#%%
@dataclass
class QueryResult():
    run: list
    indices: dict

    def get(self, idx, name):
        return self.run[idx][self.indices[name]]

    def len(self):
        return len(self.run)


def query(db: sqlite3.Connection, stmt: str) -> QueryResult:
    res = db.execute(stmt)
    columns = [dd[0] for dd in res.description]
    indices = {nn: ii for ii, nn in enumerate(columns)}
    res = list(res.fetchall())
    return QueryResult(res, indices)


def fix_path(path: Path | str) -> Path:
    path = Path(path)
    if Path(os.getcwd()).name in ["plot_scripts"]:
        print("In plot_scripts")
        if path.parts[0] in ["data", "seeds", "plot"]:
            path = Path("..")/path
    return path


def_res = query(def_con, """
select run_results.exec_id, run_results.prog, funname, instr, run_results.mut_type, fuzzer, run_ctr, covered_file_seen, covered_by_seed, time_found, found_by_seed from run_results
left join mutations
on run_results.exec_id is mutations.exec_id
    and run_results.prog is mutations.prog
    and run_results.mut_id is mutations.mutation_id
""")

asan_res = query(asan_con, """
select run_results.exec_id, run_results.prog, funname, instr, run_results.mut_type, fuzzer, run_ctr, covered_file_seen, covered_by_seed, time_found, found_by_seed from run_results
left join mutations
on run_results.exec_id is mutations.exec_id
    and run_results.prog is mutations.prog
    and run_results.mut_id is mutations.mutation_id
""")

muts_res = query(def_con, """
select pattern_name, mut_type from mutation_types
""")

mut_types = {muts_res.get(ii, 'mut_type'): muts_res.get(ii, 'pattern_name') for ii in range(muts_res.len())}
print(mut_types)

#%%
from collections import defaultdict

results = defaultdict(lambda: {
    'covered_default': set(),
    'covered_asan': set(),
    'default': set(),
    'asan': set(),
})

for ii in range(def_res.len()):
    fuzzer = def_res.get(ii, 'fuzzer')
    prog = def_res.get(ii, "prog")
    fuzzer = def_res.get(ii, "fuzzer")
    funname = def_res.get(ii, "funname")
    instr = def_res.get(ii, "instr")
    covered_file_seen = def_res.get(ii, "covered_file_seen")
    covered_by_seed = def_res.get(ii, "covered_by_seed")
    time_found = def_res.get(ii, "time_found")
    found_by_seed = def_res.get(ii, "found_by_seed")
    mut_type = def_res.get(ii, "mut_type")

    mut_id = (prog, funname, instr)

    if covered_file_seen is not None:
        results[(mut_type, fuzzer)]['covered_default'].add(mut_id)

    if time_found is not None:
        results[(mut_type, fuzzer)]['default'].add(mut_id)


for ii in range(asan_res.len()):
    fuzzer = asan_res.get(ii, 'fuzzer')
    prog = asan_res.get(ii, "prog")
    fuzzer = asan_res.get(ii, "fuzzer")
    funname = asan_res.get(ii, "funname")
    instr = asan_res.get(ii, "instr")
    covered_file_seen = asan_res.get(ii, "covered_file_seen")
    covered_by_seed = asan_res.get(ii, "covered_by_seed")
    time_found = asan_res.get(ii, "time_found")
    found_by_seed = asan_res.get(ii, "found_by_seed")
    mut_type = asan_res.get(ii, "mut_type")

    mut_id = (prog, funname, instr)

    if covered_file_seen is not None:
        results[(mut_type, fuzzer)]['covered_asan'].add(mut_id)

    if time_found is not None:
        results[(mut_type, fuzzer)]['asan'].add(mut_id)


#%%

all_mut_types = set(rr[0] for rr in results)
all_fuzzers = set(rr[1] for rr in results)

print(all_mut_types)
print(all_fuzzers)

#%%
table = []
suff = []
header = ['Mutation Type', 'Fuzzer', 'Cov Def', 'Cov Asan', 'Kill Def', 'Kill Asan']
num_columns = len(header)
table.append(header)
suff.append(None)

for mt_idx, mt in enumerate(all_mut_types):
    lines = [None]*len(all_fuzzers)

    for ii in range(len(lines)):
        lines[ii] = [None]*len(header)

    mut_str = mut_types[mt].replace("_", " ")
    
    lines[0][0] = rf"\multirow{{4}}{{\linewidth}}{{{mut_str}}}"
    # lines[0][0] = rf"{mut_str}"

    for ffii, ff in enumerate(all_fuzzers):
        rr = results[(mt, ff)]

        if ffii > 0:
            lines[ffii][0] = ''
        lines[ffii][1] = ff
        lines[ffii][2] = f"{len(rr['covered_default']):,}"
        lines[ffii][3] = f"{len(rr['covered_asan']):,}"
        lines[ffii][4] = f"{len(rr['default']):,}"
        lines[ffii][5] = f"{len(rr['asan']):,}"

    # for ll in lines:
    #     print(ll)

    suff.extend([None]*len(all_fuzzers))
    # if mt_idx < len(all_mut_types) - 1:
    #     suff[-1] = fr"\cmidrule{{2-{num_columns}}}"


    table.extend(lines)

two_col_table = [table[0] + table[0]]
suff = ['\\midrule']

for mm in range(len(table)):
    combined = []
    for ff in range(len(all_fuzzers)):
        left_idx = mm*8 + ff + 1
        right_idx = (mm)*8 + ff + 4 + 1

        try:
            left_row = table[left_idx]
        except IndexError:
            break

        suff.append(None)
        
        try:
            right_row = table[right_idx]
        except IndexError:
            right_row = ['']*num_columns
        combined.append(left_row + right_row)

    two_col_table.extend(combined)
    suff[-1] = '\\midrule'

print(suff)

for rr in two_col_table:
    print(rr)

#%%




# for ii, rr in enumerate(table[1:]):
#     tc_idx = (ii//2) + 1
#     if ii % 2 == 0:
#         two_col_table.append([])

#     two_col_table[tc_idx] += rr

# for rr in two_col_table:
#     print(rr)


#%%

# with open(out_path("fuzzer-mut-head.tex"), "wt") as f:
#     f.write(to_latex_table([table[0]], suffixes=[suff[0]]))

print(len(two_col_table), len(suff))

with open(out_path("fuzzer-mut.tex"), "wt") as f:
    f.write(to_latex_table(two_col_table, suffixes=suff))
    # f.write(to_latex_table(table[1:], suffixes=suff[1:]))

