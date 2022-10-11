
#%%
from dataclasses import dataclass
import os
from pathlib import Path
import sqlite3
from typing import List, Optional
from helper import db_connect, fix_path, query, out_path, to_latex_table

def_con = db_connect(fix_path("data/current/stats_all.db"))
asan_con = db_connect(fix_path("data/asan/stats_all.db"))
long_con = db_connect(fix_path("data/24_3/stats_all.db"))

#%%

def_time = query(def_con, "select total_time from execution")
asan_time = query(asan_con, "select total_time from execution")
long_time = query(long_con, "select total_time from execution")

#%%
def_time_sum = 0
for rr in def_time:
    def_time_sum += rr.get("total_time")


asan_time_sum = 0
for rr in asan_time:
    asan_time_sum += rr.get("total_time")


long_time_sum = 0
for rr in long_time:
    long_time_sum += rr.get("total_time")


#%%
seed_days = 2 * 7
default_days = def_time_sum / 60 / 60 / 24
asan_days = asan_time_sum / 60 / 60 / 24
long_days = long_time_sum / 60 / 60 / 24
sum_days = seed_days + default_days + asan_days + long_days



table = [
    ["", "CPU (Years)", "4 Blades (Days)"],
    [f"Seed Collection", f"{seed_days * 52 / 365:.2f}", f"{seed_days/4:.2f}"],
    [f"Default", f"{default_days * 52 / 365:.2f}", f"{default_days/4:.2f}"],
    [f"Seed + Default", f"{(seed_days + default_days) * 52 / 365:.2f}", f"{(seed_days + default_days)/4:.2f}"],
    [f"ASAN", f"{asan_days * 52 / 365:.2f}", f"{asan_days/4:.2f}"],
    [f"24 Hours Runs", f"{long_days * 52 / 365:.2f}", f"{long_days/4:.2f}"],
    [f"Sum", f"{sum_days * 52 / 365:.2f}", f"{sum_days/4:.2f}"],
]

with open(fix_path("plot/fig/compute-time.tex"), "wt") as f:
    f.write(to_latex_table(table, suffixes=[r"\midrule", None, None, None, None, r"\midrule", None]))
