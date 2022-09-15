#%%
from helper import db_connect, fix_path, query, to_latex_table, out_path

con = db_connect("data/current/stats_all.db")

run_results = query(con, """
    select prog, fuzzer, count() as cnt from (
    select *, multi_ids, count() as cnt, group_concat(group_id) as multi_mut_ids from super_mutants_multi
    group by exec_id, prog, run_ctr, fuzzer, multi_ids
    order by cnt desc
    )
    group by prog, fuzzer
""")
#%%

all_progs = set()
all_fuzzer = set()

rr_map = {}

for rr in run_results:
    prog = rr.get("prog")
    fuzzer = rr.get("fuzzer")
    cnt = rr.get("cnt")
    all_progs.add(prog)
    all_fuzzer.add(fuzzer)
    rr_map[(prog, fuzzer)] = cnt

all_fuzzer = sorted(all_fuzzer)
all_progs = sorted(all_progs)

table = [["Program"] + [ff for ff in all_fuzzer]]

for pp in all_progs:
    new_line = []
    new_line.append(pp)
    for ff in all_fuzzer:
        new_line.append(f"{rr_map.get((pp, ff), 0):,}")
    table.append(new_line)

suff = [None]*len(table)
suff[0] = r"\midrule"

# for tt in table:
#     print(tt)

#%%

with open(out_path("independent.tex"), "wt") as f:
    f.write(to_latex_table(table, suffixes=suff))

