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

---------------------------------------------------------------------------------
-- general stats on mutation types

-- combines the different stats into an overview
DROP VIEW IF EXISTS mut_type_stats;
CREATE TEMP VIEW mut_type_stats
as
select
	count_mut_type.mut_type,
	amount as total_mutations,
	(count_crashed_mut_type.amount_crashed - count_crashed_seeds_mut_type.amount_crashed) as crashed,
	count_crashed_seeds_mut_type.amount_crashed as "afl seeds crashed",
	printf("%.2f", (cast(count_crashed_mut_type.amount_crashed - count_crashed_seeds_mut_type.amount_crashed as float) / cast(amount as float)) * 100, 2) as "percentage crashed",
	printf("%.2f", (cast(count_crashed_seeds_mut_type.amount_crashed as float) / cast(amount as float)) * 100, 2) as "percentage afl seed crashed",
	count_crashing_inputs_mut_type.diff_ret as diff_ret,
	count_crashing_inputs_mut_type.triggered as triggered,
	printf("%.2f", (cast(count_crashing_inputs_mut_type.diff_ret as float) / cast(amount as float)) * 100, 2) as "percentage diff ret",
	printf("%.2f", (cast(count_crashing_inputs_mut_type.triggered as float) / cast(amount as float)) * 100, 2) as "percentage triggered"
from count_mut_type
inner join count_crashed_mut_type on count_mut_type.mut_type == count_crashed_mut_type.mut_type
inner join count_crashed_seeds_mut_type on count_mut_type.mut_type == count_crashed_seeds_mut_type.mut_type
inner join count_crashing_inputs_mut_type on count_mut_type.mut_type == count_crashing_inputs_mut_type.mut_type;

-- total count of mutation types
DROP VIEW IF EXISTS count_mut_type;
CREATE TEMP VIEW count_mut_type
as
select count(*) amount, mut_type from runs
group by mut_type;

-- total count of mutation types that resulted in a crashed run
DROP VIEW IF EXISTS count_crashed_mut_type;
CREATE TEMP VIEW count_crashed_mut_type
as
select count(*) amount_crashed, mut_type from runs
inner join (
	select *
	from run_crashed
) run_crashed on 
	runs.mutation_id = run_crashed.mutation_id and
	runs.fuzzer = run_crashed.fuzzer and
	runs.prog = run_crashed.prog
group by mut_type;

-- total count of mutation types that resulted in a crashed run due to afl choking on the seeds
DROP VIEW IF EXISTS count_crashed_seeds_mut_type;
CREATE TEMP VIEW count_crashed_seeds_mut_type
as
select count(*) amount_crashed, mut_type from runs
inner join (
	select * from run_crashed
	where crash_trace like '%PROGRAM ABORT :% results in a crash%'
) run_crashed on 
	runs.mutation_id = run_crashed.mutation_id and
	runs.fuzzer = run_crashed.fuzzer and
	runs.prog = run_crashed.prog
group by mut_type;

-- crashing inputs stats
DROP VIEW IF EXISTS count_crashing_inputs_mut_type;
CREATE TEMP VIEW count_crashing_inputs_mut_type
as
select sum(diff_ret) diff_ret, sum(triggered) triggered, mut_type from runs
inner join (
	select max(a.diff_ret) diff_ret, max(a.triggered) triggered, a.prog as prog, a.mutation_id as mutation_id
	from (
		select orig_return_code != mut_return_code as diff_ret, instr(mut_stdout, 'Triggered!') != 0 as triggered, prog, mutation_id from crashing_inputs
		where crashing_inputs.path not like '%README.txt'
	) a
	group by mutation_id
) found_crash on 
	runs.mutation_id = found_crash.mutation_id and
	-- TODO runs.fuzzer = run_crashed.fuzzer and
	runs.prog = found_crash.prog
group by mut_type;

