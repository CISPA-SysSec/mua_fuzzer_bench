#%%
import sqlite3
from helper import db_connect, fix_path, query, to_latex_table, out_path, data_path

db = db_connect("data/current/stats_all.db")


#%%
sampling_results = query(db, """
SELECT pattern_name, fuzzer, sum(done) AS done, sum(covered) AS covered, sum(found) AS found
FROM run_results_by_mut_type_and_fuzzer
JOIN mutation_types USING (mut_type)
GROUP BY mut_type, fuzzer;
""")

#%%
all_runs_list = []

for run in sampling_results:
    pattern_name = run.get("pattern_name")
    fuzzer = run.get("fuzzer")
    done = run.get("done")
    covered = run.get("covered")
    found = run.get("found");
    all_runs_list.append({
        'pattern_name': pattern_name,
        'fuzzer': fuzzer,
        'covered': covered,
        'found': found,
        'done': done,
    })

#%%
import pandas as pd
data = pd.DataFrame.from_records(all_runs_list)

data.to_csv("plot/tmp_data/mutation_types.csv")
