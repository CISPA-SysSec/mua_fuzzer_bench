#%%
from helper import db_connect, fix_path, query, to_latex_table, out_path, data_path

con = db_connect("data/current/stats_all.db")

#%%
import pandas as pd

stats = pd.read_sql_query("SELECT prog, mutations, supermutants, reduction from reduction_per_prog", con)
stats = stats[['prog', 'mutations', 'supermutants', 'reduction']]

#%%

#%%
actual_years = query(con, """
select prog, sum(total_time) / 60 / 60 / 24 / 365 as cpu_years
from (
	select *
	from (
		select all_run_results.exec_id as exec_id, all_run_results.prog as prog, mut_id, all_run_results.fuzzer as fuzzer, super_mutant_id, all_run_results.total_time as total_time from all_run_results
		left join initial_super_mutants on (
			all_run_results.exec_id = initial_super_mutants.exec_id and 
			all_run_results.prog = initial_super_mutants.prog and 
			all_run_results.mut_id = initial_super_mutants.mutation_id)
	)
	group by exec_id, prog, fuzzer, super_mutant_id, total_time
)
group by prog
""")

#%%

naive_years = query(con, """
select prog, count() * 4 / 365 as cpu_years from mutations
group by prog
""")

#%%


#%%

table = stats.to_numpy().tolist()

table = [
    [
        rr[0],
        f"{rr[1]:,}",
        f"{rr[2]:,}",
        f"{rr[3]:0.2f}",
    ]
    for rr in table
]

table = [
    r"& \multicolumn{3}{c}{No. Mutants} & \multicolumn{3}{c}{CPU years}",
    ["Subject", "Mutants", "Supermutants", "Reduction", "Naive", "Actual", "Reduction"]
] + table

suff = [None]*len(table)
suff[0] = r"\cmidrule(lr){2-4} \cmidrule(lr){5-7}"
suff[1] = r"\midrule"

for ny in naive_years:
    prog = ny.get("prog")
    cpu_years = ny.get("cpu_years")

    for ee in table:
        if ee[0] == prog:
            ee.append(f"{cpu_years:.2f}")


for ay in actual_years:
    prog = ay.get("prog")
    cpu_years = ay.get("cpu_years")

    for ee in table:
        if ee[0] == prog:
            ee.append(f"{cpu_years:.2f}")

for rr in table[2:]:
    rr.append(f"{float(rr[-2]) / float(rr[-1]):.2f}")

for rr in table:
    print(rr)

#%%

with open(out_path("reduction-prog.tex"), "wt") as f:
    f.write(to_latex_table(table, suffixes=suff))
