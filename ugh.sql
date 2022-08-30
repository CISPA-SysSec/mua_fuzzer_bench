select rr.exec_id, rr.prog, rr.cnt as num_runs, muts.cnt as num_mutations, started.cnt as num_actual_super_mutants, round(cast(rr.cnt as float) / cast(started.cnt as float), 2) as reduction
from (
		select exec_id, prog, count() as cnt
		from (select exec_id, prog, mut_id from run_results group by exec_id, prog, mut_id)
		group by exec_id, prog
) as rr
join (
	select exec_id, prog, count() as cnt
	from (
		select exec_id, prog, mutation_id
		from mutations
		group by exec_id, prog, mutation_id
	)
	group by exec_id, prog
) as muts using (exec_id, prog)
join (
	select exec_id, prog, count() as cnt
	from (
		select exec_id, prog, super_mutant_id
		from started_super_mutants
		group by exec_id, prog, super_mutant_id
	)
	group by exec_id, prog
) as started using (exec_id, prog);

--------------

-- select rr.exec_id, rr.prog, rr.cnt as num_runs, muts.cnt as num_mutations, started.cnt as num_actual_super_mutants, round(cast(rr.cnt as float) / cast(started.cnt as float), 2) as reduction
-- from (
-- 		select exec_id, prog, count() as cnt
-- 		from (select exec_id, prog, mut_id from run_results group by exec_id, prog, mut_id)
-- 		group by exec_id, prog
-- ) as rr
-- join (
-- 	select exec_id, prog, count() as cnt
-- 	from (
-- 		select exec_id, prog, mutation_id
-- 		from mutations
-- 		group by exec_id, prog, mutation_id
-- 	)
-- 	group by exec_id, prog
-- ) as muts using (exec_id, prog)
-- join (
-- 	select exec_id, prog, count() as cnt
-- 	from (
-- 		select exec_id, prog, super_mutant_id
-- 		from started_super_mutants
-- 		group by exec_id, prog, super_mutant_id
-- 	)
-- 	group by exec_id, prog
-- ) as started using (exec_id, prog);

select *
from (
	select * -- exec_id, prog, * -- count() as cnt, *
	from (
		select * from run_results
		join (
			select *, mutation_id as mut_id
			from started_super_mutants
			group by exec_id, prog, mut_id
		) as muts using (exec_id, prog, mut_id)
		group by exec_id, prog, mut_id
	) group by exec_id, prog
) as bla
-- group by exec_id, prog
