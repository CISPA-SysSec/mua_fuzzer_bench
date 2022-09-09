.PHONY: plot clean resampling twenty_four_hours big_table

plot: resampling twenty_four_hours big_table

clean:
	-rm -r plot/fig
	-rm -r plot/tmp_data


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

