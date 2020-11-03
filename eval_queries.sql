-- This file assumes that the views of `eval_views.sql` are available.

--------------------------------------------------------------------------------
-- afl++

-- get runtime stats
-- get runtime stats
select sum(totals_execs) / 1000000.0 as million_execs,
	   sum(time) / (60*60) as cpu_hours,
	   cast(count(nullif(unique_crashes, "0")) as float) / count(*) as percent_crashing_runs,
	   cast(count(nullif(unique_hangs, "0")) as float) / count(*) as percent_hanging_runs,
	   cast(sum(map_size) as float) / count(*) as average_map_size
from aflpp_runs_last_line;