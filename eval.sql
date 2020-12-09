---------------------------------------------------------------------------------
-- afl++

-- get the last line of the plot data based on time for each mutation_id
DROP VIEW IF EXISTS aflpp_runs_last_line;
CREATE TEMP VIEW aflpp_runs_last_line
as
select *
from aflpp_runs a
inner join (
	select mutation_id, max(total_time) total_time
	from aflpp_runs
	group by mutation_id
) b ON a.mutation_id = b.mutation_id and a.total_time = b.total_time;

-- get runtime stats for afl++ based fuzzers
DROP VIEW IF EXISTS runtime_stats;
CREATE TEMP VIEW runtime_stats
as
select fuzzer,
	   sum(totals_execs) / 1000000.0 as million_execs,
	   sum(total_time) / (60*60) as cpu_hours,
	   sum(total_time) / (60*60*80) as blade_time,
	   cast(count(nullif(unique_crashes, "0")) as float) / count(*) as percent_crashing_runs,
	   cast(count(nullif(unique_hangs, "0")) as float) / count(*) as percent_hanging_runs,
	   cast(sum(map_size) as float) / count(*) as average_map_size
from aflpp_runs_last_line
group by fuzzer;

---------------------------------------------------------------------------------
-- general stats on mutation types

-- combines the different stats into an overview
DROP VIEW IF EXISTS mut_type_stats;
CREATE TEMP VIEW mut_type_stats
as
select
	count_mut_type.mut_type,
	count_mut_type.fuzzer,
	amount as total_mutations,
	count_crashed_seeds_mut_type.amount_crashed as "afl seeds crashed",
	printf("%.2f", (cast(count_crashed_seeds_mut_type.amount_crashed as float) / cast(amount as float)) * 100, 2) as "% afl seed crashed",
	count_crashing_inputs_mut_type.triggered as "mutation triggered",
	printf("%.2f", (cast(count_crashing_inputs_mut_type.triggered as float) / cast(amount as float)) * 100, 2) as "% mutations triggered",
	count_crashing_inputs_mut_type.diff_ret as "different return on check",
	printf("%.2f", (cast(count_crashing_inputs_mut_type.diff_ret as float) / cast(amount as float)) * 100, 2) as "% diff ret",
	printf("%.2f", 100 * cast(count_crashing_inputs_mut_type.diff_ret as float) / cast(count_crashing_inputs_mut_type.triggered as float)) as "% triggered and found",
	(count_crashed_mut_type.amount_crashed - count_crashed_seeds_mut_type.amount_crashed) as "run crashed",
	printf("%.2f", (cast(count_crashed_mut_type.amount_crashed - count_crashed_seeds_mut_type.amount_crashed as float) / cast(amount as float)) * 100, 2) as "% runs crashed"
from count_mut_type
left join count_crashed_mut_type on count_mut_type.mut_type == count_crashed_mut_type.mut_type and count_mut_type.fuzzer == count_crashed_mut_type.fuzzer
left join count_crashed_seeds_mut_type on count_mut_type.mut_type == count_crashed_seeds_mut_type.mut_type and count_mut_type.fuzzer == count_crashed_seeds_mut_type.fuzzer
left join count_crashing_inputs_mut_type on count_mut_type.mut_type == count_crashing_inputs_mut_type.mut_type and count_mut_type.fuzzer == count_crashing_inputs_mut_type.fuzzer;

-- total count of mutation types
DROP VIEW IF EXISTS count_mut_type;
CREATE TEMP VIEW count_mut_type
as
select count(*) amount, mut_type, fuzzer from runs
group by mut_type, fuzzer;

-- total count of mutation types that resulted in a crashed run
DROP VIEW IF EXISTS count_crashed_mut_type;
CREATE TEMP VIEW count_crashed_mut_type
as
select count(*) amount_crashed, mut_type, runs.fuzzer from runs
inner join (
	select *
	from run_crashed
) run_crashed on 
	runs.mutation_id = run_crashed.mutation_id and
	runs.fuzzer = run_crashed.fuzzer and
	runs.prog = run_crashed.prog
group by mut_type, runs.fuzzer;

-- total count of mutation types that resulted in a crashed run due to afl choking on the seeds
DROP VIEW IF EXISTS count_crashed_seeds_mut_type;
CREATE TEMP VIEW count_crashed_seeds_mut_type
as
select count(*) amount_crashed, mut_type, runs.fuzzer from runs
inner join (
	select * from run_crashed
	where crash_trace like '%PROGRAM ABORT :% results in a crash%'
) run_crashed on 
	runs.mutation_id = run_crashed.mutation_id and
	runs.fuzzer = run_crashed.fuzzer and
	runs.prog = run_crashed.prog
group by mut_type, runs.fuzzer;

-- crashing inputs stats
DROP VIEW IF EXISTS count_crashing_inputs_mut_type;
CREATE TEMP VIEW count_crashing_inputs_mut_type
as
select mut_type, runs.fuzzer, sum(diff_ret) diff_ret, count(*) total, sum(triggered) triggered from runs
inner join (
	select max(a.diff_ret) diff_ret, max(triggered) triggered, a.prog as prog, a.mutation_id as mutation_id, fuzzer
	from (
		select orig_return_code != mut_return_code as diff_ret, num_triggered > 0 as triggered, prog, mutation_id, fuzzer from crashing_inputs
	) a
	group by mutation_id, fuzzer
) found_crash on 
	runs.mutation_id = found_crash.mutation_id and
	runs.fuzzer = found_crash.fuzzer and
	runs.prog = found_crash.prog
group by mut_type, runs.fuzzer;

