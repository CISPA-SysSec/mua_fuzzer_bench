import logging
import shlex
import sqlite3
import time
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Set, Tuple, TypeVar, ParamSpec, Concatenate, TYPE_CHECKING, cast
from data_types import CheckResultKilled, CheckResultTimeout, DoneMutation, InitialSuperMutant, Program, MutationType, Mutation, MutationRun, SuperMutant, FuzzerRun, CoveredResult

from constants import WITH_ASAN, WITH_MSAN
from helpers import mutation_locations_path, mutation_prog_source_path

logger = logging.getLogger(__name__)
T = TypeVar('T')
P = ParamSpec('P')


# A helper function to reduce load on the database and reduce typing overhead
def connection(f: Callable[Concatenate['Stats', sqlite3.Cursor, P], T]) -> Callable[Concatenate['Stats', P], Optional[T]]:
    def wrapper(self: 'Stats', /, *args: P.args, **kwargs: P.kwargs) -> Optional[T]:
        if self.conn is None:
            return None
        res = f(self, self.conn.cursor(), *args, **kwargs)
        if self._time_last_commit + 5 > time.time():
            self.conn.commit()
            self._time_last_commit = time.time()
        return res
    return wrapper


# A class to store information into a sqlite database. This expects sole access
# to the database.
class Stats:

    def __init__(self, db_path_s: Optional[str]):
        super().__init__()
        if db_path_s is None:
            logger.info(f"Didn't get db_path env, not writing history.")
            self.conn: Optional[sqlite3.Connection] = None
            return
        db_path = Path(db_path_s)
        logger.info(f"Writing history to: {db_path}")
        if db_path.is_file():
            logger.info(f"DB exists, deleting: {db_path}")
            db_path.unlink()
        # As we have sole access, we just drop all precaution needed for
        # multi-party access. This removes overhead.
        self.conn = sqlite3.connect(str(db_path), isolation_level="Exclusive")
        # Initialize the tables
        self._init_tables()
        c = self.conn.cursor()
        # Same as above, this reduces some overhead.
        c.execute('PRAGMA synchronous = 0')
        c.execute('PRAGMA journal_mode = OFF')
        # Record when we started
        self._start_time = time.time()
        # Record the last time we committed
        self._time_last_commit = time.time()
        self.supermutant_ctr = 0

    def _init_tables(self) -> None:
        assert self.conn is not None, "Directly before this, conn was initialised. It cannot be None!"
        c = self.conn.cursor()

        c.execute('''
        CREATE TABLE execution (
            exec_id,
            hostname,
            git_status,
            rerun,
            start_time,
            total_time,
            with_asan,
            with_msan,
            args,
            env
        )
        ''')

        c.execute('''
        CREATE TABLE mutation_types (
            pattern_name,
            mut_type,
            pattern_location,
            pattern_class,
            description,
            procedure
        )''')

        c.execute('''
        CREATE TABLE all_runs (
            exec_id,
            prog,
            mutation_id INTEGER,
            run_ctr,
            fuzzer
        )''')

        c.execute('''
        CREATE TABLE done_runs (
            exec_id,
            prog,
            mutation_id INTEGER,
            run_ctr,
            fuzzer,
            reason
        )''')

        c.execute('''
        CREATE TABLE initial_super_mutants (
            exec_id,
            prog,
            super_mutant_id,
            mutation_id INTEGER
        )''')

        c.execute('''
        CREATE TABLE started_super_mutants (
            exec_id,
            prog,
            super_mutant_id,
            run_ctr,
            fuzzer,
            mutation_id INTEGER
        )''')

        c.execute('''
        CREATE TABLE super_mutants_multi (
            exec_id,
            prog,
            run_ctr,
            fuzzer,
            super_mutant_id,
            group_id,
            multi_ids,
            description
        )''')

        c.execute('''
        CREATE TABLE mutations (
            exec_id,
            prog,
            mutation_id INTEGER,
            mut_type,
            directory,
            file_path,
            line,
            column,
            instr,
            funname,
            additional_info
        )''')

        c.execute('''
        CREATE TABLE locator_seed_covered (
            exec_id,
            prog,
            mutation_id INTEGER,
            fuzzer,
            locator_seed_covered
        )''')

        c.execute('''
        CREATE TABLE progs (
            exec_id,
            prog,
            bc_compile_args,
            bin_compile_args,
            dict,
            orig_bin,
            orig_bc_file_data,
            prog_source_file_data,
            mutation_locations_data,
            supermutant_graph_info
        )''')

        c.execute('''
        CREATE TABLE executed_runs (
            exec_id,
            prog,
            mutation_id INTEGER,
            run_ctr,
            fuzzer,
            covered_file_seen,
            total_time
        )''')

        c.execute('''
        CREATE TABLE executed_seeds (
            exec_id,
            prog,
            mutation_id INTEGER,
            run_ctr,
            fuzzer,
            covered_file_seen,
            timed_out,
            total_time
        )''')

        c.execute('''
        CREATE TABLE seed_crashing_inputs (
            exec_id,
            prog,
            mutation_id INTEGER,
            fuzzer,
            time_found,
            stage,
            path,
            crashing_input,
            orig_return_code,
            mut_return_code,
            orig_cmd,
            mut_cmd,
            orig_output,
            mut_output,
            num_triggered
        )''')

        c.execute('''
        CREATE TABLE crashing_inputs (
            exec_id,
            prog,
            mutation_id INTEGER,
            run_ctr,
            fuzzer,
            time_found,
            stage,
            path,
            crashing_input,
            orig_return_code,
            mut_return_code,
            orig_cmd,
            mut_cmd,
            orig_output,
            mut_output,
            orig_timeout,
            mut_timeout,
            num_triggered
        )''')

        c.execute('''
        CREATE TABLE crashing_supermutation_preparation (
            exec_id,
            prog,
            supermutant_id INTEGER,
            crash_trace
        )''')

        c.execute('''
        CREATE TABLE crashing_mutation_preparation (
            exec_id,
            prog,
            supermutant_id INTEGER,
            mutation_id INTEGER
        )''')

        c.execute('''
        CREATE TABLE run_crashed (
            exec_id,
            prog,
            mutation_id INTEGER,
            run_ctr,
            fuzzer,
            crash_trace
        )''')

        self.conn.commit()

    def next_supermutant_id(self) -> int:
        cur = self.supermutant_ctr
        self.supermutant_ctr += 1
        return cur

    # def commit(self):
    #     self.conn.commit()

    @connection
    def new_execution(self, c: sqlite3.Cursor, exec_id: str, hostname: str, git_status: str, rerun: Optional[Path], start_time:float, args: str, env: str) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        c.execute('INSERT INTO execution VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                exec_id,
                hostname,
                git_status,
                rerun,
                start_time,
                None,
                WITH_ASAN,
                WITH_MSAN,
                args,
                env
            )
        )
        self.conn.commit()

    @connection
    def execution_done(self, c: sqlite3.Cursor, exec_id: str, total_time: float) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        c.execute('UPDATE execution SET total_time = ? where exec_id = ?',
            (
                total_time,
                exec_id,
            )
        )
        self.conn.commit()

    @connection
    def new_mutation_type(self, c: sqlite3.Cursor, mutation_type: MutationType) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        c.execute('INSERT INTO mutation_types VALUES (?, ?, ?, ?, ?, ?)',
            (
                mutation_type.pattern_name,
                mutation_type.type_id,
                mutation_type.pattern_location,
                mutation_type.pattern_class,
                mutation_type.description,
                mutation_type.procedure,
            )
        )
        self.conn.commit()

    @connection
    def new_run(self, c: sqlite3.Cursor, exec_id: str, data: FuzzerRun) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        mut_data = data.mut_data
        for m_id in mut_data.mutation_ids:
            c.execute('INSERT INTO all_runs VALUES (?, ?, ?, ?, ?)',
                (
                    exec_id,
                    mut_data.prog.name,
                    m_id,
                    data.run_ctr,
                    data.fuzzer.name,
                )
            )
        self.conn.commit()

    @connection
    def done_run(self, c: sqlite3.Cursor, reason: str, exec_id: str, prog: str, mut_id: int, run_ctr: int, fuzzer: str) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        logger.debug(f"! mut done: {reason} :: {prog} {fuzzer} {run_ctr} {mut_id}")
        c.execute('INSERT INTO done_runs VALUES (?, ?, ?, ?, ?, ?)',
            (
                exec_id,
                prog,
                mut_id,
                run_ctr,
                fuzzer,
                reason,
            )
        )
        self.conn.commit()

    @connection
    def new_initial_supermutant(self, c: sqlite3.Cursor, exec_id: str, prog: str, sm_id: int, mut_ids: List[int]) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        for m_id in mut_ids:
            c.execute('INSERT INTO initial_super_mutants VALUES (?, ?, ?, ?)',
                (
                    exec_id,
                    prog,
                    sm_id,
                    m_id,
                )
            )
        self.conn.commit()

    @connection
    def new_supermutant(self, c: sqlite3.Cursor, exec_id: str, mut_data: MutationRun) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        for m_id in mut_data.mut_data.mutation_ids:
            c.execute('INSERT INTO started_super_mutants VALUES (?, ?, ?, ?, ?, ?)',
                (
                    exec_id,
                    mut_data.mut_data.prog.name,
                    mut_data.mut_data.supermutant_id,
                    None,
                    None,
                    m_id,
                )
            )
        self.conn.commit()

    @connection
    def new_supermutant_multi(
        self,
        c: sqlite3.Cursor,
        exec_id: str,
        mut_data: SuperMutant,
        multi_groups: Set[Tuple[int, ...]],
        fuzzer: str,
        run_ctr: int,
        description: str
    ) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        for group_id, multi in enumerate(multi_groups):
            for m_id in multi:
                c.execute('INSERT INTO super_mutants_multi VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                    (
                        exec_id,
                        mut_data.prog.name,
                        run_ctr,
                        fuzzer,
                        mut_data.supermutant_id,
                        group_id,
                        m_id,
                        description
                    )
                )
        self.conn.commit()

    @connection
    def new_mutation(self, c: sqlite3.Cursor, exec_id: str, data: Mutation) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"

        c.execute('INSERT INTO mutations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                exec_id,
                data.prog.name,
                data.mutation_id,
                data.type_id,
                data.directory,
                data.filePath,
                data.line,
                data.column,
                data.instr,
                data.funname,
                data.additional_info,
            )
        )
        self.conn.commit()

    @connection
    def new_prog(self, c: sqlite3.Cursor, exec_id: str, prog: str, data: Program) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        with open(data.orig_bc, 'rb') as f:
            bc_file_data = f.read()
        with open(mutation_prog_source_path(data), 'rt') as f:
            prog_source_data = f.read()
        with open(mutation_locations_path(data), 'rt') as f:
            ml_data = f.read()
        c.execute('INSERT INTO progs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                exec_id,
                prog,
                json.dumps(data.bc_compile_args, default=lambda o: o.__dict__), # type: ignore[misc]
                json.dumps(data.bin_compile_args, default=lambda o: o.__dict__), # type: ignore[misc]
                str(data.dict_path),
                str(data.orig_bin),
                bc_file_data,
                prog_source_data,
                ml_data,
                None
            )
        )
        self.conn.commit()

    @connection
    def new_supermutant_graph_info(self, c: sqlite3.Cursor, exec_id: str, prog: str, graph_info: CoveredResult) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        # c.execute('UPDATE execution SET total_time = ? where exec_id = ?',
        graph_info_dict = {
            'covered': graph_info.covered_mutations,
            'covered_supermutants': graph_info.covered_supermutants,
            'not_covered': graph_info.not_covered,
            'not_covered_supermutants': graph_info.not_covered_supermutants,
        }

        c.execute('UPDATE progs SET supermutant_graph_info = ? where exec_id = ? and prog = ?',
            (
                json.dumps(graph_info_dict, default=lambda o: o.__dict__), # type: ignore[misc]
                exec_id,
                prog,
            )
        )
        self.conn.commit()

    @connection
    def new_run_executed(
        self,
        c: sqlite3.Cursor,
        exec_id: str,
        run_ctr: int,
        prog: str,
        mutation_id: int,
        fuzzer: str,
        cf_seen: Optional[float],
        total_time: float
    ) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        c.execute('INSERT INTO executed_runs VALUES (?, ?, ?, ?, ?, ?, ?)',
            (
                exec_id,
                prog,
                mutation_id,
                run_ctr,
                fuzzer,
                cf_seen,
                total_time,
            )
        )
        self.conn.commit()

    @connection
    def new_seeds_executed(
        self,
        c: sqlite3.Cursor,
        exec_id: str,
        prog: str,
        mutation_id: int,
        run_ctr: int,
        fuzzer: str,
        cf_seen: Optional[float],
        timed_out: Optional[int],
        total_time: Optional[float]
    ) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        c.execute('INSERT INTO executed_seeds VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (
                exec_id,
                prog,
                mutation_id,
                run_ctr,
                fuzzer,
                cf_seen,
                timed_out,
                total_time,
            )
        )
        self.conn.commit()

    @connection
    def new_crashing_inputs(
        self, c: sqlite3.Cursor, crashing_inputs: List[CheckResultKilled],
        exec_id: str, prog: str, mutation_id: int, run_ctr: int, fuzzer: str
    ) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        for data in crashing_inputs:
            if data.orig_returncode != 0 or data.orig_returncode != data.mut_returncode:
                c.execute('INSERT INTO crashing_inputs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (
                        exec_id,
                        prog,
                        mutation_id,
                        run_ctr,
                        fuzzer,
                        data.time,
                        "run",
                        str(data.path),
                        None,
                        data.orig_returncode,
                        data.mut_returncode,
                        ' '.join((str(v) for v in data.orig_cmd)),
                        ' '.join((str(v) for v in data.mut_cmd)),
                        str(data.orig_res),
                        str(data.mut_res),
                        None,
                        None,
                        None
                    )
                )
        self.conn.commit()

    @connection
    def new_crashing_timout_inputs(
        self, c: sqlite3.Cursor, crashing_inputs: List[CheckResultTimeout],
        exec_id: str, prog: str, mutation_id: int, run_ctr: int, fuzzer: str
    ) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        for data in crashing_inputs:
            c.execute('INSERT INTO crashing_inputs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    exec_id,
                    prog,
                    mutation_id,
                    run_ctr,
                    fuzzer,
                    data.time,
                    "run",
                    str(data.path),
                    None,
                    None,
                    None,
                    None,
                    " ".join(map(shlex.quote, data.args)),
                    None,
                    None,
                    None,
                    1,
                    None
                )
            )
        self.conn.commit()

    @connection
    def new_seed_crashing_inputs(
        self, c: sqlite3.Cursor, exec_id: str, prog: str, mutation_id: int,
        fuzzer: str, crashing_inputs: List[CheckResultKilled]
    ) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        for data in crashing_inputs:
            if data.orig_returncode != 0 or data.orig_returncode != data.mut_returncode:
                c.execute('INSERT INTO seed_crashing_inputs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (
                        exec_id,
                        prog,
                        mutation_id,
                        fuzzer,
                        data.time,
                        "seeds",
                        str(data.path),
                        None,
                        data.orig_returncode,
                        data.mut_returncode,
                        ' '.join((str(v) for v in data.orig_cmd)),
                        ' '.join((str(v) for v in data.mut_cmd)),
                        data.orig_res,
                        data.mut_res,
                        data.num_triggered
                    )
                )
        self.conn.commit()

    @connection
    def run_crashed(self, c: sqlite3.Cursor, exec_id: str, prog: str, mutation_id: int, run_ctr: int, fuzzer: str, trace: str) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        c.execute('INSERT INTO run_crashed VALUES (?, ?, ?, ?, ?, ?)',
            (
                exec_id,
                prog,
                mutation_id,
                run_ctr,
                fuzzer,
                trace,
            )
        )
        self.conn.commit()

    @connection
    def supermutation_preparation_crashed(self, c: sqlite3.Cursor, exec_id: str, prog: str, supermutant_id: int, trace: str) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        c.execute('INSERT INTO crashing_supermutation_preparation VALUES (?, ?, ?, ?)',
            (
                exec_id,
                prog,
                supermutant_id,
                trace,
            )
        )
        self.conn.commit()

    @connection
    def mutation_preparation_crashed(self, c: sqlite3.Cursor, exec_id: str, prog: str, supermutant_id: int, mutation_id: int) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        c.execute('INSERT INTO crashing_mutation_preparation VALUES (?, ?, ?, ?)',
            (
                exec_id,
                prog,
                supermutant_id,
                mutation_id,
            )
        )
        self.conn.commit()

    @connection
    def locator_seed_covered(self, c: sqlite3.Cursor, exec_id: str, prog: str, fuzzer: str, mutation_ids: List[int]) -> None:
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        for mm in mutation_ids:
            c.execute('INSERT INTO locator_seed_covered VALUES (?, ?, ?, ?, ?)',
                (
                    exec_id,
                    prog,
                    mm,
                    fuzzer,
                    True
                )
            )
        self.conn.commit()


class ReadStatsDb():
    def __init__(self, db_path: Path):
        super().__init__()
        self.db = sqlite3.connect(db_path)

    def execute_eval_sql(self) -> None:
        c = self.db.cursor()
        with open('eval.sql', 'r') as f:
            c.executescript(f.read())

    def get_bc_file_content(self, prog: str) -> bytes:
        c = self.db.cursor()
        res_cur = c.execute('select orig_bc_file_data from progs where prog = ?', (prog,))
        res: List[List[bytes]] = [r for r in res_cur] # type: ignore[misc]
        assert len(res) == 1
        return res[0][0]

    def get_mutation_locations_content(self, prog: str) -> str:
        c = self.db.cursor()
        res_cur = c.execute('select mutation_locations_data from progs where prog = ?', (prog,))
        res: List[List[str]] = [r for r in res_cur] # type: ignore[misc]
        assert len(res) == 1
        return res[0][0]

    def get_prog_source_content(self, prog: str) -> str:
        c = self.db.cursor()
        res_cur = c.execute('select prog_source_file_data from progs where prog = ?', (prog,))
        res: List[List[str]] = [r for r in res_cur] # type: ignore[misc]
        assert len(res) == 1
        return res[0][0]

    def get_initial_super_mutants(self, prog: str) -> List[InitialSuperMutant]:
        c = self.db.cursor()
        res_cur = c.execute('select * from initial_super_mutants where prog = ?', (prog,))
        res: List[List[str]] = [r for r in res_cur] # type: ignore[misc]
        return [
            InitialSuperMutant(
                exec_id=str(r[0]),
                prog=str(r[1]),
                super_mutant_id=int(r[2]),
                mutation_id=int(r[3]),
            )
            for r in res
        ]

    def get_all_progs(self) -> List[str]:
        c = self.db.cursor()
        progs_c = c.execute('select prog from progs')
        progs: List[str] = list(set([r[0] for r in progs_c])) # type: ignore[misc]
        return progs


    def get_all_mutants(self, prog: str) -> List[DoneMutation]:
        c = self.db.cursor()

        mutation_ids_c = c.execute('select mutation_id from mutations where prog = ?', (prog,))
        mutation_ids = set([int(r[0]) for r in mutation_ids_c]) # type: ignore[misc]

        done_runs_c = c.execute('select mutation_id, covered_file_seen from executed_runs where prog = ?', (prog,))
        done_runs = {int(r[0]): r[1] is not None for r in done_runs_c} # type: ignore[misc]

        crashed_c = c.execute('select mutation_id from run_crashed where prog = ?', (prog,))
        crashed = set([int(r[0]) for r in crashed_c]) # type: ignore[misc]

        killed_c = c.execute('select mutation_id from crashing_inputs where prog = ?', (prog,))
        killed = set([int(r[0]) for r in killed_c]) # type: ignore[misc]

        killed_by_seed_c = c.execute('select mutation_id from seed_crashing_inputs where prog = ?', (prog,))
        killed_by_seed = set([int(r[0]) for r in killed_by_seed_c]) # type: ignore[misc]

        timeout_c = c.execute('select mutation_id, timed_out from executed_seeds where prog = ?', (prog,))
        timeout = {int(r[0]): r[1] is not None for r in timeout_c} # type: ignore[misc]

        mutations = []

        for mm in mutation_ids:
            mutations.append(
                DoneMutation(
                    mut_id=mm,
                    untried=mm not in done_runs,
                    covered=done_runs[mm] if mm in done_runs else False,
                    timeout=timeout[mm] if mm in timeout else False,
                    crashed=mm in crashed,
                    killed=mm in killed or mm in killed_by_seed,
                )
            )

        return mutations


