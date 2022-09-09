.PHONY: plot clean resampling twenty_four_hours big_table oracle

plot: resampling twenty_four_hours big_table oracle

clean:
	-rm -r plot/fig
	-rm -r plot/tmp_data


# oracle
oracle: plot/fig/oracle-percentages-aflpp.pdf plot/fig/oracle-percentages-full.pdf

plot/fig/oracle-percentages-aflpp.pdf plot/fig/oracle-percentages-full.pdf: plot/tmp_data/def_asan_results.csv
	Rscript plot_scripts/asan_vis.R

plot/tmp_data/def_asan_results.csv: data/current/stats_all.db data/asan/stats_all.db
	python3 plot_scripts/oracle_eval.py


# big-table
big_table: plot/fig/big-table.tex

plot/fig/big-table.tex: data/current/stats_all.db
	python3 plot_scripts/big-table.py



# 24 hours
twenty_four_hours: plot/fig/24-hour.tex

plot/fig/24-hour.tex: data/24_hours/stats_all.db
	python3 plot_scripts/24-hours.py



# resampling
resampling: plot/fig/resampling.pdf

plot/fig/resampling.pdf: plot/tmp_data/resampling.json
	Rscript plot_scripts/resampling.R

plot/tmp_data/resampling.json:
	python3 plot_scripts/resampling.py

