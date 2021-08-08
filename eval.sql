-- Rerun this script after adding new data, due to performance reasons tables are created to make queries faster.
-- These tables need to be recreated when adding new data or the results will be stale.

-- indeces to create:

drop index if exists index_all_runs;
create unique index index_all_runs on all_runs (exec_id, prog, mutation_id, run_ctr, fuzzer);

drop index if exists index_progs;
create unique index index_progs on progs (exec_id, prog);

drop index if exists index_mutations;
create unique index index_mutations on mutations (exec_id, prog, mutation_id);

drop index if exists index_mutations_types;
create index index_mutations_types on mutations (mut_type);

drop index if exists index_distinct_seed_crashing_inputs;
create index index_distinct_seed_crashing_inputs on seed_crashing_inputs (exec_id, prog, mutation_id) where orig_return_code != mut_return_code;

drop index if exists index_distinct_crashing_inputs;
create index index_distinct_crashing_inputs on crashing_inputs (exec_id, prog, mutation_id, run_ctr, fuzzer) where orig_return_code != mut_return_code;


-- useful views / tables:

-- size of the tables in the database
DROP VIEW IF EXISTS table_sizes;
CREATE VIEW table_sizes
as
SELECT name, printf("%.2f", cast(SUM("pgsize") as float) / (1024*1024)) as "MiBi" FROM dbstat group by name;


-- collect info on all runs
DROP VIEW IF EXISTS runs;
CREATE VIEW runs
as
select * from all_runs
inner join progs using (exec_id, prog)
inner join mutations using (exec_id, prog, mutation_id);

-- results for all mut types
DROP VIEW IF EXISTS mut_types;
CREATE VIEW mut_types
as
select distinct(mut_type) as mut_type from runs
order by mut_type;

-- a distinct list of crashing seed inputs one for each prog, mutation_id if available
DROP VIEW IF EXISTS distinct_seed_crashing_inputs;
CREATE VIEW distinct_seed_crashing_inputs
as
select * from seed_crashing_inputs
where orig_return_code != mut_return_code
group by exec_id, prog, mutation_id;

-- a distinct list of crashing inputs one for each prog, mutation_id, fuzzer if available
DROP VIEW IF EXISTS distinct_crashing_inputs;
CREATE VIEW distinct_crashing_inputs
as
select * from crashing_inputs
where orig_return_code != mut_return_code
group by exec_id, prog, mutation_id, run_ctr, fuzzer;

-- results for all runs
DROP TABLE IF EXISTS all_run_results;
CREATE TABLE all_run_results
as
select
	exec_id,
	prog,
	mutation_id as mut_id,
	run_ctr,
	fuzzer,
	mut_type,
	
	-- if covered by seeds then time is zero, if not we check if covered during run else it is null
	case
	when executed_seeds.covered_file_seen is not NULL then 0
	when executed_runs.covered_file_seen  is not NULL then executed_runs.covered_file_seen
	else NULL
	-- divide by 60 to get time in minutes
	end / 60
	as covered_file_seen,
	
	case when executed_seeds.covered_file_seen is not NULL
	then 1 else 0 end
	as covered_by_seed,
		
	-- if covered by seeds then time is zero, if not we check if covered during run else it is null
	case
	when dsci.time_found is not NULL then 0
	when dci.time_found  is not NULL then dci.time_found
	else NULL
	-- divide by 60 to get time in minutes
	end / 60
	as time_found,
	
	case when dsci.time_found is not NULL
	then 1 else 0 end
	as found_by_seed,
	
	(ifnull(executed_seeds.total_time, 0) + ifnull(executed_runs.total_time, 0)) / 60 as total_time,
	
	case when ifnull(dsci.time_found, dci.time_found) is not NULL then 1 else NULL end as confirmed,
	
	executed_seeds.timed_out as seed_timeout,
	
	case when ifnull(crashing_mutation_preparation.crash_trace, run_crashed.crash_trace) is not NULL then 1 else NULL end as crashed,
	
	case
	when crashing_mutation_preparation.crash_trace is not NULL then "mutation_crashed"
	when run_crashed.crash_trace is not NULL then "run_crashed"
	when dsci.time_found is not NULL then "seed_found"
	when dci.time_found is not NULL then "run_found"
	when ifnull(executed_seeds.total_time, executed_runs.total_time) is not NULL then "done"
	else NULL
	end
	as stage
from all_runs
left join executed_seeds using (exec_id, prog, mutation_id)
left join executed_runs using (exec_id, prog, mutation_id, run_ctr, fuzzer)
left join distinct_seed_crashing_inputs as dsci using (exec_id, prog, mutation_id) 
left join distinct_crashing_inputs as dci using (exec_id, prog, mutation_id, run_ctr, fuzzer)
left join crashing_mutation_preparation using (exec_id, prog, mutation_id)
left join run_crashed using (exec_id, prog, mutation_id, run_ctr, fuzzer)
inner join progs using (exec_id, prog)
inner join mutations using (exec_id, prog, mutation_id);

-- add indeces the newly created all_run_results table
drop index if exists index_all_run_results;
create unique index index_all_run_results on all_run_results (exec_id, prog, mut_id, run_ctr, fuzzer);

drop index if exists index_all_run_results_stage;
create index index_all_run_results_stage on all_run_results (stage, fuzzer, exec_id, prog, mut_id, run_ctr);

-- get the prog and mut_id for all run_results that have been completed for all fuzzers
DROP TABLE IF EXISTS completed_runs;
CREATE TABLE completed_runs
as
select a.exec_id, a.prog, a.mut_id, a.run_ctr, complete from (
	select group_concat(fuzzer) as complete, length(group_concat(fuzzer)) as len, prog, mut_id, * from (
		select * from all_run_results where stage is not null order by fuzzer
	) group by exec_id, prog, mut_id, run_ctr
) a
left join (
	select max(length(complete)) as max_len from (
		select group_concat(fuzzer) as complete, prog, mut_id, * from (
			select * from all_run_results where stage is not null order by fuzzer
		) group by exec_id, prog, mut_id, run_ctr
	)
) m
where a.len = m.max_len;

drop index if exists index_completed_runs;
create index index_completed_runs on completed_runs (exec_id, prog, mut_id, run_ctr);

DROP TABLE IF EXISTS run_results;
CREATE TABLE run_results
as
select * from all_run_results
inner join completed_runs using (exec_id, prog, mut_id, run_ctr);

-- results for all runs grouped by mut_type, create this as a table as many views depend on it
DROP TABLE IF EXISTS run_results_by_mut_type_and_fuzzer;
CREATE TABLE run_results_by_mut_type_and_fuzzer
as
select
	runs_mut_type.mut_type,
	runs_mut_type.fuzzer, runs_mut_type.prog,
	total,
	done,
	covered,
	c_by_seed,
	covered - c_by_seed as c_by_f,
	found,
	f_by_seed,
	found - f_by_seed as f_by_f,
	c_by_seed - f_by_seed as interesting,
	seed_timeout,
	crashed,
	round(avg(total_time) / done, 2) as avg_run_min,
	round(sum(total_time) / 60 / 24, 2) as cpu_days
from (
	select mut_type, fuzzer, prog, count(*) as total
	from runs
	group by mut_type, fuzzer, prog
) runs_mut_type
left join (
	select mut_type,
	       fuzzer,
		   exec_id,
		   prog,
		   count(*) as done,
		   count(covered_file_seen) as covered,
		   count(crashed) as crashed,
		   count(case when covered_by_seed is 1 then 1 else null end) as c_by_seed,
		   count(time_found) as found,
		   count(case when stage = "seed_found" and confirmed then 1 else null end) as f_by_seed,
		   sum(seed_timeout) as seed_timeout,
		   sum(total_time) as total_time
    from run_results
	group by mut_type, fuzzer, exec_id, prog
) res using (mut_type, prog, fuzzer)
group by runs_mut_type.mut_type, runs_mut_type.prog, runs_mut_type.fuzzer;

-- add indeces the newly created table
drop index if exists index_run_results_by_mut_type_and_fuzzer_mut_type;
create index index_run_results_by_mut_type_and_fuzzer_mut_type on run_results_by_mut_type_and_fuzzer (mut_type);

drop index if exists index_run_results_by_mut_type_and_fuzzer_fuzzer;
create index index_run_results_by_mut_type_and_fuzzer_fuzzer on run_results_by_mut_type_and_fuzzer (fuzzer);

drop index if exists index_run_results_by_mut_type_and_fuzzer_prog;
create index index_run_results_by_mut_type_and_fuzzer_prog on run_results_by_mut_type_and_fuzzer (prog);

	
-- results for all runs grouped by mut type
DROP VIEW IF EXISTS run_results_by_mut_type;
CREATE VIEW run_results_by_mut_type
as
select	
	mutation_types.pattern_name as name,
	mutation_types.mut_type as mut_type,
	sum(total) as total,
	sum(done) as done,
	sum(covered) as covered,
	sum(c_by_seed) as c_by_seed,
	sum(c_by_f) as c_by_f,
	sum(found) as found,
	sum(f_by_seed) as f_by_seed,
	sum(f_by_f) as f_by_f,
	sum(interesting) as interesting,
	sum(seed_timeout) as seed_timeout,
	sum(crashed) as crashed,
	round(avg(avg_run_min), 2) as avg_run_min,
	round(sum(cpu_days), 2) as cpu_days
from run_results_by_mut_type_and_fuzzer
join mutation_types on run_results_by_mut_type_and_fuzzer.mut_type == mutation_types.mut_type
group by mutation_types.mut_type;

-- results for all runs grouped by fuzzer
DROP VIEW IF EXISTS run_results_by_fuzzer;
CREATE VIEW run_results_by_fuzzer
as
select fuzzer,
	sum(total) as total,
	sum(done) as done,
	sum(covered) as covered,
	sum(c_by_seed) as c_by_seed,
	sum(c_by_f) as c_by_f,
	sum(found) as found,
	sum(f_by_seed) as f_by_seed,
	sum(f_by_f) as f_by_f,
	sum(interesting) as interesting,
	sum(seed_timeout) as seed_timeout,
	sum(crashed) as crashed,
	round(avg(avg_run_min), 2) as avg_run_min,
	round(sum(cpu_days), 2) as cpu_days
from run_results_by_mut_type_and_fuzzer
group by fuzzer;

-- results for all runs grouped by fuzzer
DROP VIEW IF EXISTS run_results_by_prog;
CREATE VIEW run_results_by_prog
as
select prog,
	sum(total) as total,
	sum(done) as done,
	sum(covered) as covered,
	sum(c_by_seed) as c_by_seed,
	sum(c_by_f) as c_by_f,
	sum(found) as found,
	sum(f_by_seed) as f_by_seed,
	sum(f_by_f) as f_by_f,
	sum(interesting) as interesting,
	sum(seed_timeout) as seed_timeout,
	sum(crashed) as crashed,
	round(avg(avg_run_min), 2) as avg_run_min,
	round(sum(cpu_days), 2) as cpu_days
from run_results_by_mut_type_and_fuzzer
group by prog;

-- ---------------------------------------------------------------------------------
-- -- afl++

-- get the last line of the plot data based on time for each mutation_id
DROP VIEW IF EXISTS aflpp_runs_last_line;
CREATE VIEW aflpp_runs_last_line
as
select * from (
	select * from aflpp_runs
	order by totals_execs
) a
group by exec_id, prog, mutation_id, run_ctr, fuzzer;

-- get runtime stats for afl++ based fuzzers
DROP VIEW IF EXISTS aflpp_runtime_stats;
CREATE VIEW aflpp_runtime_stats
as
select prog, fuzzer,
	   sum(totals_execs) / 1000000.0 as million_execs,
	   cast(count(nullif(unique_crashes, "0")) as float) / count(*) as percent_crashing_runs,
	   cast(count(nullif(unique_hangs, "0")) as float) / count(*) as percent_hanging_runs,
	   cast(sum(map_size) as float) / count(*) as average_map_size
from aflpp_runs_last_line
group by prog, fuzzer;

-- get the number of mutations only one of two fuzzers finds, this is one fuzzer compared to all other fuzzers, grouped by mutation type
-- DROP VIEW IF EXISTS unique_finds;
-- CREATE VIEW unique_finds
-- as
-- select mut_type, a.fuzzer as fuzzer, b.fuzzer as other_fuzzer, count(case when (a.found == 1 and b.found == 0) then 1 else NULL end) as finds from (
-- 	select prog,
-- 		   mut_id,
-- 		   mut_type,
-- 		   fuzzer,
-- 		   case when time_found is null then 0 else 1 end as found
-- 	from run_results
-- ) a
-- join (
-- 	select prog,
-- 	       mut_id,
-- 		   fuzzer,
-- 		   case when time_found is null then 0 else 1 end as found
-- 	from run_results
-- ) b
-- on a.prog == b.prog and a.mut_id == b.mut_id and a.fuzzer != b.fuzzer
-- group by mut_type, a.fuzzer, b.fuzzer;
-- 
-- get the overall number of mutations only one of two fuzzers finds, this is one fuzzer compared to all other fuzzers
-- DROP VIEW IF EXISTS unique_finds_overall;
-- CREATE VIEW unique_finds_overall
-- as
-- select fuzzer, other_fuzzer, sum(finds) as finds from unique_finds
-- group by fuzzer, other_fuzzer;

DROP VIEW IF EXISTS unique_finds_results;
CREATE VIEW unique_finds_results
as
select 
	   all_runs.exec_id,
	   all_runs.prog,
	   mutation_id as mut_id,
	   mut_type,
	   all_runs.run_ctr,
	   fuzzer,
	   case when ifnull(dsci.time_found, dci.time_found) is not NULL then 1 else NULL end as confirmed
from all_runs
left join distinct_seed_crashing_inputs as dsci using (exec_id, prog, mutation_id) 
left join distinct_crashing_inputs as dci using (exec_id, prog, mutation_id, run_ctr, fuzzer)
inner join mutations using (exec_id, prog, mutation_id)
inner join completed_runs on
	all_runs.exec_id = completed_runs.exec_id and
	all_runs.prog = completed_runs.prog and
	all_runs.mutation_id = completed_runs.mut_id and
	all_runs.run_ctr = completed_runs.run_ctr;

DROP VIEW IF EXISTS unique_finds;
CREATE VIEW unique_finds
as
select a.mut_type, a.fuzzer as fuzzer, b.fuzzer as other_fuzzer, case when (a.confirmed == 1 and b.confirmed is null) then 1 else 0 end as finds
from unique_finds_results as a
join unique_finds_results as b on
	a.exec_id == b.exec_id and
	a.prog == b.prog and
	a.mut_id == b.mut_id and
	a.run_ctr == b.run_ctr and
	a.fuzzer != b.fuzzer;

DROP VIEW IF EXISTS unique_finds_overall;
CREATE VIEW unique_finds_overall
as
select fuzzer, other_fuzzer, sum(finds) as finds from unique_finds
group by fuzzer, other_fuzzer;


-- needs to be fixed: add exec_id and run_ctr
-- DROP VIEW IF EXISTS unsolved_mutations;
-- CREATE VIEW unsolved_mutations
-- as
-- select a.mut_type, mut_id, mut_file_path, mut_line, mut_column, pattern_class, description, procedure, * from (
-- 	select mut_type, mut_id, sum(case WHEN covered_file_seen is null then 0 else 1 end) as covered_num, sum(case WHEN confirmed is null then 0 else 1 end) as confirmed_num from run_results
-- 	group by mut_id
-- 	having covered_num > 0 and confirmed_num = 0
-- ) a inner join runs on a.mut_id = runs.mutation_id
-- inner join mutation_types on a.mut_type = mutation_types.mut_type
-- group by mut_id
-- order by mut_type, mut_file_path, mut_line;

DROP VIEW IF EXISTS crashed_runs_overview;
CREATE VIEW crashed_runs_overview
as
select
	not (seed_crash or seed_timeout or all_seeds_crash or mut_compile_failed or sigint) as unknown_crash_reason,
	seed_crash + seed_timeout + all_seeds_crash + mut_compile_failed + sigint > 1 as multiple_reasons,
	*
from (
	select
		crash_trace like '%[-] PROGRAM ABORT : %Test case % results in a crash%' as seed_crash,
		crash_trace like '%[-] PROGRAM ABORT : %Test case % results in a timeout%' as seed_timeout,
		crash_trace like '%[-] PROGRAM ABORT : %We need at least one valid input seed that does not crash!%' as all_seeds_crash,
		crash_trace like '%error: no such file or directory: ''/dev/shm/mutated_bcs/%/fuzz_target.ll.%.mut.bc''%' as mut_compile_failed,
		crash_trace like '%Caught SIGINT signal!%' as sigint,
		* from run_crashed
)
order by unknown_crash_reason, multiple_reasons;

DROP VIEW IF EXISTS crashed_runs_summary;
CREATE VIEW crashed_runs_summary
as
select
	prog,
	fuzzer,
	sum(unknown_crash_reason) as unknown_crash_reason,
	sum(multiple_reasons) as multiple_reasons,
	sum(seed_crash) as seed_crash,
	sum(seed_timeout) as seed_timeout,
	sum(all_seeds_crash) as all_seeds_crash,
	sum(mut_compile_failed) as mut_compile_failed,
	sum(sigint) as sigint
from crashed_runs_overview
group by prog, fuzzer
order by unknown_crash_reason, multiple_reasons, prog, fuzzer;

DROP VIEW IF EXISTS base_bin_crashes;
CREATE VIEW base_bin_crashes
as
select prog, fuzzer, count(*) as amount
from (
	select prog, mutation_id, fuzzer, orig_return_code
	from crashing_inputs
	where orig_return_code != 0
	union all
	select prog, mutation_id, NULL as fuzzer, orig_return_code
	from seed_crashing_inputs
	where orig_return_code != 0
);

DROP VIEW IF EXISTS not_covered_but_found;
CREATE VIEW not_covered_but_found
as
select (covered_file_seen or covered_by_seed) as covered, (time_found or found_by_seed) as found, * from all_run_results
where covered is 0 and found is 1;


DROP VIEW IF EXISTS covered_by_seed_but_not_fuzzer;
CREATE VIEW covered_by_seed_but_not_fuzzer
as
select executed_seeds.covered_file_seen is not null as s_covered, executed_runs.covered_file_seen is not null as f_covered, *
from executed_seeds
join executed_runs using (exec_id, prog, mutation_id)
where s_covered is 1 and f_covered is 0;

DROP VIEW IF EXISTS percentage_found_over_time;
CREATE VIEW percentage_found_over_time
as
select total_until, total_until*1.0 / total_num as percentage, time_found / 60.0 as found, fuzzer, * from (
	select count(*) over (
		order by time_found
		rows BETWEEN
			unbounded preceding
			and current row
		) as total_until,
		time_found,
		*
	from all_run_results
	where found_by_seed is 0 and confirmed is 1
	order by time_found
) join (select count(*) as total_num from all_run_results where found_by_seed is 0 and confirmed is 1);

