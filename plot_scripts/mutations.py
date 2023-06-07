#%%
import pandas as pd

from helper import db_connect, fix_path, query, to_latex_table, out_path

con = db_connect(fix_path("data/basic/stats_all.db"))

pd.set_option('display.max_colwidth', 1000)

stats = pd.read_sql_query("SELECT * from mutation_types group by mut_type", con)
stats = stats[['pattern_name', 'description', 'procedure']]
stats['pattern_name'] = stats['pattern_name'].transform(lambda x: x.replace('_', ' '))

stats.to_csv(path_or_buf=out_path("mutations.csv"))

#%%
data = stats.to_numpy().tolist()
# suff = ['\\midrule'] * ((len(data)) - 1) + [None]

with open(out_path("mutations.tex"), "wt") as f:
    f.write(
        to_latex_table(data).replace("%", "\\%")
    )

#%%

# # stats.rename(columns={'pattern_name': 'mutation'}, inplace=True)
# styler = stats.style
# styler.na_rep = '---'
# styler.hide(axis='index')
# styler.format(escape='latex')
# latex_repr = styler.to_latex(
#     column_format="p{.18\\textwidth}p{.4\\textwidth}p{.4\\textwidth}",
#     # buf=out_path("mutations.tex"),
#     environment='longtable',
#     # longtable=True,
#     # multirow_=True,
# )

# print(latex_repr.replace("\\\\\n", "\\\\ \\hline \n"))
