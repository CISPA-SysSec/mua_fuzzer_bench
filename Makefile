.PHONY: plot clean resampling twenty_four_hours big_table big_table_asan oracle fuzzer-mut mutations wayne reduction mutation_types

plot: resampling twenty_four_hours big_table big_table_asan oracle fuzzer-mut wayne reduction mutation_types

clean:
	-rm -r plot/fig
	-rm -r plot/tmp_data


# reduction
reduction: plot/fig/reduction-prog.tex

plot/fig/reduction-prog.tex: plot_scripts/reduction.py data/basic/stats_all.db
	python3 plot_scripts/reduction.py


# wayne
wayne: plot/fig/wayne.pdf

plot/fig/wayne.pdf: plot/tmp_data/wayne.json plot_scripts/wayne.R
	Rscript plot_scripts/wayne.R

plot/tmp_data/wayne.json: data/basic/stats_all.db plot_scripts/wayne.py
	python3 plot_scripts/wayne.py


# mutation_types
mutation_types: plot/fig/mutation_types.pdf

plot/fig/mutation_types.pdf: plot_scripts/data/mutation_types.csv plot_scripts/mutation_types.R
	Rscript plot_scripts/mutation_types.R

plot_scripts/data/mutation_types.csv: data/basic/stats_all.db plot_scripts/mutation_types.py
	python3 plot_scripts/mutation_types.py

# # mutations
# mutations: plot/fig/mutations.tex plot/fig/mutations.csv

# plot/fig/mutations.tex plot/fig/mutations.csv: plot_scripts/mutations.py data/basic/stats_all.db
# 	python3 plot_scripts/mutations.py


# fuzzer-mut
fuzzer-mut: plot/fig/fuzzer-mut.tex

plot/fig/fuzzer-mut.tex: data/basic/stats_all.db data/asan/stats_all.db
	python3 plot_scripts/fuzzer-mut.py


# oracle
oracle: plot/fig/oracle-percentages-aflpp.pdf plot/fig/oracle-percentages-full.pdf

plot/fig/oracle-percentages-aflpp.pdf plot/fig/oracle-percentages-full.pdf: plot/tmp_data/def_asan_results.csv plot_scripts/asan_vis.R
	Rscript plot_scripts/asan_vis.R

plot/tmp_data/def_asan_results.csv: data/basic/stats_all.db data/asan/stats_all.db plot_scripts/oracle_eval.py
	python3 plot_scripts/oracle_eval.py


# big-table-asan
big_table_asan: plot/fig/big-table-asan.tex

plot/fig/big-table-asan.tex: plot_scripts/big-table.py data/asan/stats_all.db
	python3 plot_scripts/big-table.py data/asan/stats_all.db big-table-asan.tex


# big-table
big_table: plot/fig/big-table.tex

plot/fig/big-table.tex: plot_scripts/big-table.py data/basic/stats_all.db
	python3 plot_scripts/big-table.py data/basic/stats_all.db big-table.tex



# 24 hours
twenty_four_hours: plot/fig/24-hour.tex plot_scripts/24-hours.py

plot/fig/24-hour.tex: data/24_hours/stats_all.db
	python3 plot_scripts/24-hours.py



# # resampling
# resampling: plot/fig/resampling.pdf

# plot/fig/resampling.pdf: plot/tmp_data/resampling.json plot_scripts/resampling.R
# 	Rscript plot_scripts/resampling.R

# plot/tmp_data/resampling.json: plot_scripts/resampling.py
# 	python3 plot_scripts/resampling.py
