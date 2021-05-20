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
inner join progs on all_runs.prog = progs.prog
inner join mutations on all_runs.prog = mutations.prog and all_runs.mutation_id = mutations.mutation_id;

-- results for all mut types
DROP VIEW IF EXISTS mut_types;
CREATE VIEW mut_types
as
select distinct(mut_type) as mut_type from runs
order by mut_type;

-- results for all runs
DROP VIEW IF EXISTS all_run_results;
CREATE VIEW all_run_results
as
select
	executed_runs.fuzzer,
	mut_type,
	executed_runs.mutation_id as mut_id,
	executed_runs.prog,
	covered_file_seen / 60 as covered_file_seen,
	executed_runs.covered_by_seed,
	case confirmed when 1 then time_found / 60 else NULL end as time_found,
	total_time / 60 as total_time,
	-- orig_return_code != mut_return_code or orig_stdout != mut_stdout or orig_stderr != mut_stderr as confirmed,
	confirmed,
	stage
from executed_runs
inner join runs on
	executed_runs.prog = runs.prog and
	executed_runs.mutation_id = runs.mutation_id and
	executed_runs.fuzzer = runs.fuzzer
left join (
		select orig_return_code != mut_return_code as confirmed, *
		from crashing_inputs
	) crashing_inputs on
	executed_runs.prog = crashing_inputs.prog and
	executed_runs.mutation_id = crashing_inputs.mutation_id and
	executed_runs.fuzzer = crashing_inputs.fuzzer
group by executed_runs.prog, executed_runs.fuzzer, executed_runs.mutation_id
UNION all
select
	fuzzer,
	NULL as mut_type,
	mutation_id as mut_id,
	prog,
	NULL as covered_file_seen,
	0 as covered_by_seed,
	NULL as time_found,
	NULL as total_time,
	-- orig_return_code != mut_return_code or orig_stdout != mut_stdout or orig_stderr != mut_stderr as confirmed,
	0 as confirmed,
	"crashed" as stage
from run_crashed;

-- get the prog and mut_id for all run_results that have been completed for all fuzzers
DROP VIEW IF EXISTS completed_runs;
CREATE VIEW completed_runs
as
select a.prog, a.mut_id, complete from (
	select group_concat(fuzzer) as complete, length(group_concat(fuzzer)) as len, prog, mut_id, * from (
		select * from all_run_results order by fuzzer
	) group by prog, mut_id
) a
left join (
	select max(length(complete)) as max_len from (
		select group_concat(fuzzer) as complete, prog, mut_id, * from (
			select * from all_run_results order by fuzzer
		) group by prog, mut_id
	)
) m
where a.len = m.max_len;

DROP VIEW IF EXISTS run_results;
CREATE VIEW run_results
as
select * from all_run_results
inner join completed_runs
on all_run_results.prog = completed_runs.prog and all_run_results.mut_id = completed_runs.mut_id;

-- results for all runs grouped by mut_type
DROP VIEW IF EXISTS run_results_by_mut_type_and_fuzzer;
CREATE VIEW run_results_by_mut_type_and_fuzzer
as
select
	runs_mut_type.mut_type,
	runs_mut_type.fuzzer, runs_mut_type.prog,
	total,
	ifnull(done, 0) + ifnull(crashed, 0) as done,
	covered,
	c_by_seed,
	covered - c_by_seed as c_by_f,
	found,
	f_by_seed,
	found - f_by_seed as f_by_f,
	ifnull(crashed, 0) as crashed,
	round(avg(total_time) / ifnull(done, 0) + ifnull(crashed, 0), 2) as avg_run_min,
	round(sum(total_time) / 60 / 24, 2) as cpu_days
from (
	select mut_type, fuzzer, prog, count(*) as total
	from runs
	group by mut_type, fuzzer, prog
) runs_mut_type
left join (
	select mut_type,
	       fuzzer,
		   prog,
		   count(*) as done,
		   count(covered_file_seen) as covered,
		   count(case when covered_by_seed = 1 then 1 else null end) as c_by_seed,
		   count(time_found) as found,
		   count(case when stage = "initial" and confirmed then 1 else null end) as f_by_seed,
		   sum(total_time) as total_time
    from run_results
	group by mut_type, fuzzer, prog
) res on
	runs_mut_type.mut_type = res.mut_type and
	runs_mut_type.prog = res.prog and
	runs_mut_type.fuzzer = res.fuzzer
left join (
	select runs.mut_type, run_crashed.fuzzer, run_crashed.prog, count(*) as crashed from run_crashed
	inner join runs on
		run_crashed.prog = runs.prog and
		run_crashed.mutation_id = runs.mutation_id and
		run_crashed.fuzzer = runs.fuzzer
	group by runs.mut_type, run_crashed.prog, run_crashed.fuzzer
) crashed on
	runs_mut_type.mut_type = crashed.mut_type and
	runs_mut_type.prog = crashed.prog and
	runs_mut_type.fuzzer = crashed.fuzzer
group by runs_mut_type.mut_type, runs_mut_type.prog, runs_mut_type.fuzzer;
	
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
group by prog, mutation_id, fuzzer;

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
DROP VIEW IF EXISTS unique_finds;
CREATE VIEW unique_finds
as
select mut_type, a.fuzzer as fuzzer, b.fuzzer as other_fuzzer, count(case when (a.found == 1 and b.found == 0) then 1 else NULL end) as finds from (
	select prog,
		   mut_id,
		   mut_type,
		   fuzzer,
		   case when time_found is null then 0 else 1 end as found
	from run_results
) a
join (
	select prog,
	       mut_id,
		   fuzzer,
		   case when time_found is null then 0 else 1 end as found
	from run_results
) b
on a.prog == b.prog and a.mut_id == b.mut_id and a.fuzzer != b.fuzzer
group by mut_type, a.fuzzer, b.fuzzer;

-- get the overall number of mutations only one of two fuzzers finds, this is one fuzzer compared to all other fuzzers
DROP VIEW IF EXISTS unique_finds_overall;
CREATE VIEW unique_finds_overall
as
select fuzzer, other_fuzzer, sum(finds) as finds from unique_finds
group by fuzzer, other_fuzzer;


DROP VIEW IF EXISTS unsolved_mutations;
CREATE VIEW unsolved_mutations
as
select a.mut_type, mut_id, mut_file_path, mut_line, mut_column, pattern_class, description, procedure, * from (
	select mut_type, mut_id, sum(case WHEN covered_file_seen is null then 0 else 1 end) as covered_num, sum(case WHEN confirmed is null then 0 else 1 end) as confirmed_num from run_results
	group by mut_id
	having covered_num > 0 and confirmed_num = 0
) a inner join runs on a.mut_id = runs.mutation_id
inner join mutation_types on a.mut_type = mutation_types.mut_type
group by mut_id
order by mut_type, mut_file_path, mut_line;

DROP VIEW IF EXISTS crashed_runs_overview;
CREATE VIEW crashed_runs_overview
as
select
	not (seed_crash or seed_timeout or all_seeds_crash or mut_compile_failed) as unknown_crash_reason,
	seed_crash + seed_timeout + all_seeds_crash + mut_compile_failed > 1 as multiple_reasons,
	*
from (
	select
		crash_trace like '%[-] PROGRAM ABORT : %Test case % results in a crash%' as seed_crash,
		crash_trace like '%[-] PROGRAM ABORT : %Test case % results in a timeout%' as seed_timeout,
		crash_trace like '%[-] PROGRAM ABORT : %We need at least one valid input seed that does not crash!%' as all_seeds_crash,
		crash_trace like '%error: no such file or directory: ''/dev/shm/mutated_bcs/%/fuzz_target.ll.%.mut.bc''%' as mut_compile_failed,
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
	sum(mut_compile_failed) as mut_compile_failed
from crashed_runs_overview
group by prog, fuzzer
order by unknown_crash_reason, multiple_reasons, prog, fuzzer;


-- 
-- ---------------------------------------------------------------------------------
-- -- general stats on mutation types
-- 
-- -- combines the different stats into an overview
-- DROP VIEW IF EXISTS mut_type_stats;
-- CREATE TEMP VIEW mut_type_stats
-- as
-- select
-- 	count_mut_type.mut_type,
-- 	count_mut_type.fuzzer,
-- 	amount as total_mutations,
-- 	completed,
-- 	-- count_crashed_seeds_mut_type.crashed as "afl seeds crashed",
-- 	printf("%.2f", (cast(count_crashed_seeds_mut_type.crashed as float) / cast(amount as float)) * 100, 2) as "% afl seed crashed",
-- 	-- count_crashed_seeds_mut_type.timeout as "afl seeds timeout",
-- 	printf("%.2f", (cast(count_crashed_seeds_mut_type.timeout as float) / cast(amount as float)) * 100, 2) as "% afl seed timeout",
-- 	-- count_crashing_inputs_mut_type.triggered as "mutation triggered",
-- 	printf("%.2f", (cast(count_crashing_inputs_mut_type.triggered as float) / cast(amount as float)) * 100, 2) as "% mutations triggered",
-- 	-- count_crashing_inputs_mut_type.diff_ret as "different return on check",
-- 	printf("%.2f", (cast(count_crashing_inputs_mut_type.diff_ret as float) / cast(amount as float)) * 100, 2) as "% diff ret",
-- 	printf("%.2f", 100 * cast(count_crashing_inputs_mut_type.diff_ret as float) / cast(count_crashing_inputs_mut_type.triggered as float)) as "% triggered and found",
-- 	-- (count_crashed_mut_type.amount_crashed - count_crashed_seeds_mut_type.crashed) as "run crashed",
-- 	printf("%.2f", (cast(count_crashed_mut_type.amount_crashed - count_crashed_seeds_mut_type.crashed - count_crashed_seeds_mut_type.timeout as float) / cast(amount as float)) * 100, 2) as "% runs crashed"
-- from count_mut_type
-- left join count_crashed_mut_type on count_mut_type.mut_type == count_crashed_mut_type.mut_type and count_mut_type.fuzzer == count_crashed_mut_type.fuzzer
-- left join count_crashed_seeds_mut_type on count_mut_type.mut_type == count_crashed_seeds_mut_type.mut_type and count_mut_type.fuzzer == count_crashed_seeds_mut_type.fuzzer
-- left join count_crashing_inputs_mut_type on count_mut_type.mut_type == count_crashing_inputs_mut_type.mut_type and count_mut_type.fuzzer == count_crashing_inputs_mut_type.fuzzer
-- left join (
-- 	select sum(completed) completed, fuzzer, mut_type from total_vs_completed_runs
-- 	group by fuzzer, mut_type
-- ) totals on
-- 	count_mut_type.fuzzer = totals.fuzzer and
-- 	count_mut_type.mut_type = totals.mut_type;
-- 
-- -- completed runs
-- DROP VIEW IF EXISTS completed_runs;
-- CREATE TEMP VIEW completed_runs
-- as
-- select runs.prog, runs.fuzzer, mut_type, count(*) as count from runs
-- left join aflpp_runs on
-- 	runs.mutation_id = aflpp_runs.mutation_id and
-- 	runs.fuzzer = aflpp_runs.fuzzer and
-- 	runs.prog = aflpp_runs.prog
-- left join run_crashed on
-- 	run_crashed.mutation_id = aflpp_runs.mutation_id and
-- 	run_crashed.fuzzer = aflpp_runs.fuzzer and
-- 	run_crashed.prog = aflpp_runs.prog
-- where aflpp_runs.prog not NULL or run_crashed.prog not NULL
-- group by runs.prog, runs.mut_type, runs.fuzzer;
-- 
-- 
-- -- total count of mutation types
-- DROP VIEW IF EXISTS count_mut_type;
-- CREATE TEMP VIEW count_mut_type
-- as
-- select count(*) amount, mut_type, fuzzer, prog from runs
-- group by mut_type, fuzzer, prog;
-- 
-- -- total to completed count of runs
-- DROP VIEW IF EXISTS total_vs_completed_runs;
-- CREATE TEMP VIEW total_vs_completed_runs
-- as
-- select count_mut_type.mut_type, count_mut_type.fuzzer, count_mut_type.prog, cast(sum(count_mut_type.amount) as int) total, cast(sum(completed_runs.count) as int) completed from count_mut_type
-- left join completed_runs on
-- 	count_mut_type.fuzzer = completed_runs.fuzzer and
-- 	count_mut_type.mut_type = completed_runs.mut_type and
-- 	count_mut_type.prog = completed_runs.prog
-- group by count_mut_type.mut_type, count_mut_type.fuzzer, count_mut_type.prog;
-- 
-- -- total count of mutation types that resulted in a crashed run
-- DROP VIEW IF EXISTS count_crashed_mut_type;
-- CREATE TEMP VIEW count_crashed_mut_type
-- as
-- select count(*) amount_crashed, mut_type, runs.fuzzer from runs
-- inner join (
-- 	select *
-- 	from run_crashed
-- ) run_crashed on 
-- 	runs.mutation_id = run_crashed.mutation_id and
-- 	runs.fuzzer = run_crashed.fuzzer and
-- 	runs.prog = run_crashed.prog
-- group by mut_type, runs.fuzzer;
-- 
-- -- total count of mutation types that resulted in a crashed run due to afl choking on the seeds
-- DROP VIEW IF EXISTS count_crashed_seeds_mut_type;
-- CREATE TEMP VIEW count_crashed_seeds_mut_type
-- as
-- select mut_type, runs.prog, runs.fuzzer, cast(sum(crashed) as int) crashed, cast(sum(timeout) as int) timeout, cast(count(*) - sum(crashed) - sum(timeout) as int) uncategorized from runs
-- inner join (
-- 	select *, like('%PROGRAM ABORT :% results in a crash%', crash_trace) as crashed,
-- 	          like('%PROGRAM ABORT :% results in a timeout%', crash_trace) as timeout
--     from run_crashed
-- ) run_crashed on 
-- 	runs.mutation_id = run_crashed.mutation_id and
-- 	runs.fuzzer = run_crashed.fuzzer and
-- 	runs.prog = run_crashed.prog
-- group by mut_type, runs.fuzzer;
-- 
-- -- crashing inputs stats
-- DROP VIEW IF EXISTS count_crashing_inputs_mut_type;
-- CREATE TEMP VIEW count_crashing_inputs_mut_type
-- as
-- select mut_type, runs.fuzzer, sum(diff_ret) diff_ret, count(*) total, sum(triggered) triggered from runs
-- inner join (
-- 	select max(a.diff_ret) diff_ret, max(triggered) triggered, a.prog as prog, a.mutation_id as mutation_id, fuzzer
-- 	from (
-- 		select orig_return_code != mut_return_code or orig_stdout != mut_stdout or orig_stderr != mut_stderr as diff_ret, num_triggered > 0 as triggered, prog, mutation_id, fuzzer from crashing_inputs
-- 	) a
-- 	group by mutation_id, fuzzer, prog
-- ) found_crash on 
-- 	runs.mutation_id = found_crash.mutation_id and
-- 	runs.fuzzer = found_crash.fuzzer and
-- 	runs.prog = found_crash.prog
-- group by mut_type, runs.fuzzer;
-- 
-- -- crashing inputs stats
-- DROP VIEW IF EXISTS run_results;
-- CREATE TEMP VIEW run_results
-- as
-- select runs.fuzzer, runs.prog, runs.mutation_id, runs.mut_type,
-- 	MAX(triggered) as triggered,
-- 	GROUP_CONCAT(time_found, "/////") time_found,
-- 	GROUP_CONCAT(initial_seed, "/////") initial_seed,
-- 	GROUP_CONCAT(path, "/////") paths,
-- 	GROUP_CONCAT(confirmed, "/////") confirmed from runs
-- left join (
-- 	select runs.fuzzer, runs.prog, runs.mutation_id, runs.mut_type, time_found, initial_seed, path, orig_return_code != mut_return_code or orig_stdout != mut_stdout or orig_stderr != mut_stderr as confirmed, num_triggered > 0 as triggered from runs
-- 	inner join crashing_inputs
-- 		on runs.fuzzer = crashing_inputs.fuzzer
-- 		and runs.prog = crashing_inputs.prog
-- 		and runs.mutation_id = crashing_inputs.mutation_id
-- ) a
-- 		on runs.fuzzer = a.fuzzer
-- 		and runs.prog = a.prog
-- 		and runs.mutation_id = a.mutation_id
-- group by runs.fuzzer, runs.prog, runs.mutation_id;
-- 
-- -- crashing inputs stats
-- DROP VIEW IF EXISTS mut_types;
-- CREATE TEMP VIEW mut_types
-- as
-- select distinct(mut_type) mut_type from runs
-- order by mut_type;
-- 
-- -- num run stats
-- DROP VIEW IF EXISTS num_run_stats;
-- CREATE TEMP VIEW num_run_stats
-- as
-- select 
-- 	total_vs_completed_runs.mut_type, total_vs_completed_runs.fuzzer, total_vs_completed_runs.prog,
-- 	total,
-- 	completed as done,
-- 	coalesce(completed, 0) - coalesce(crashed, 0) - coalesce(timeout, 0) - coalesce(uncategorized, 0) as successful,
-- 	coalesce(crashed, 0) as crashed,
-- 	coalesce(timeout, 0) as timeout,
-- 	coalesce(uncategorized, 0) as uncategorized
-- 	from total_vs_completed_runs
-- left join count_crashed_seeds_mut_type
-- 		on total_vs_completed_runs.fuzzer = count_crashed_seeds_mut_type.fuzzer
-- 		and total_vs_completed_runs.prog = count_crashed_seeds_mut_type.prog
-- 		and total_vs_completed_runs.mut_type = count_crashed_seeds_mut_type.mut_type;
