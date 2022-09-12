#%%
from helper import db_connect, fix_path, query, to_latex_table, out_path, data_path

con = db_connect("data/current/stats_all.db")

#%%
import pandas as pd

stats = pd.read_sql_query("SELECT prog, mutations, supermutants, reduction from reduction_per_prog", con)
stats = stats[['prog', 'mutations', 'supermutants', 'reduction']]

#%%
table = stats.to_numpy().tolist()

table = [
    [
        rr[0],
        f"{rr[1]}",
        f"{rr[2]}",
        f"{rr[3]:0.2f}",
    ]
    for rr in table
]

table = [["Subject", "Mutants", "Supermutants", "Reduction"]] + table

suff = [None]*len(table)
suff[0] = r"\midrule"

with open(out_path("reduction-prog.tex"), "wt") as f:
    f.write(to_latex_table(table, suffixes=suff))
