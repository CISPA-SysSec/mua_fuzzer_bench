--------------------------------------------------------------------------------
-- afl++

-- get the last line of the plot data based on time for each mutation_id
DROP VIEW IF EXISTS aflpp_runs_last_line;
CREATE TEMP VIEW aflpp_runs_last_line
as
select *
from aflpp_runs a
inner join (
	select mutation_id, max(time) time
	from aflpp_runs
	group by mutation_id
) b ON a.mutation_id = b.mutation_id and a.time = b.time;
