.PHONY: plot clean resampling twenty_four_hours big_table big_table_asan oracle fuzzer-mut mutations wayne reduction

plot: resampling twenty_four_hours big_table big_table_asan oracle fuzzer-mut wayne reduction

clean:
	-rm -r plot/fig
	-rm -r plot/tmp_data


# reduction
reduction: plot/fig/reduction-prog.tex

plot/fig/reduction-prog.tex: plot_scripts/reduction.py data/current/stats_all.db
	python3 plot_scripts/reduction.py


# wayne
wayne: plot/fig/wayne.pdf

plot/fig/wayne.pdf: plot/tmp_data/wayne.json plot_scripts/wayne.R
	Rscript plot_scripts/wayne.R

plot/tmp_data/wayne.json: data/current/stats_all.db plot_scripts/wayne.py
	python3 plot_scripts/wayne.py


# # mutations
# mutations: plot/fig/mutations.tex plot/fig/mutations.csv

# plot/fig/mutations.tex plot/fig/mutations.csv: plot_scripts/mutations.py data/current/stats_all.db
# 	python3 plot_scripts/mutations.py


# fuzzer-mut
fuzzer-mut: plot/fig/fuzzer-mut.tex

plot/fig/fuzzer-mut.tex: data/current/stats_all.db data/asan/stats_all.db
	python3 plot_scripts/fuzzer-mut.py


# oracle
oracle: plot/fig/oracle-percentages-aflpp.pdf plot/fig/oracle-percentages-full.pdf

plot/fig/oracle-percentages-aflpp.pdf plot/fig/oracle-percentages-full.pdf: plot/tmp_data/def_asan_results.csv plot_scripts/asan_vis.R
	Rscript plot_scripts/asan_vis.R

plot/tmp_data/def_asan_results.csv: data/current/stats_all.db data/asan/stats_all.db plot_scripts/oracle_eval.py
	python3 plot_scripts/oracle_eval.py


# big-table-asan
big_table_asan: plot/fig/big-table-asan.tex

plot/fig/big-table-asan.tex: plot_scripts/big-table.py data/asan/stats_all.db
	python3 plot_scripts/big-table.py data/asan/stats_all.db big-table-asan.tex


# big-table
big_table: plot/fig/big-table.tex

plot/fig/big-table.tex: plot_scripts/big-table.py data/current/stats_all.db
	python3 plot_scripts/big-table.py data/current/stats_all.db big-table.tex



# 24 hours
twenty_four_hours: plot/fig/24-hour.tex plot_scripts/24-hours.py

plot/fig/24-hour.tex: data/24_hours_2/stats_all.db data/24_3/stats_all.db
	python3 plot_scripts/24-hours.py



# # resampling
# resampling: plot/fig/resampling.pdf

# plot/fig/resampling.pdf: plot/tmp_data/resampling.json plot_scripts/resampling.R
# 	Rscript plot_scripts/resampling.R

# plot/tmp_data/resampling.json: plot_scripts/resampling.py
# 	python3 plot_scripts/resampling.py
