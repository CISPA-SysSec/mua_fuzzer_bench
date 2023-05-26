import logging
import sqlite3
import time
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from constants import WITH_ASAN, WITH_MSAN
from helpers import Program, mutation_locations_path, mutation_prog_source_path

logger = logging.getLogger(__name__)

# A helper function to reduce load on the database and reduce typing overhead
def connection(f):
    def wrapper(self, *args, **kwargs):
        if self.conn is None:
            return
        res = f(self, self.conn.cursor(), *args, **kwargs)
        if self._time_last_commit + 5 > time.time():
            self.conn.commit()
            self._time_last_commit = time.time()
        return res
    return wrapper

# A class to store information into a sqlite database. This expects sole access
# to the database.
class Stats():

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

    def _init_tables(self):
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
            result,
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
            additional_info,
            rest
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
    def new_execution(self, c, exec_id, hostname, git_status, rerun, start_time, args, env):
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
    def execution_done(self, c, exec_id, total_time):
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        c.execute('UPDATE execution SET total_time = ? where exec_id = ?',
            (
                total_time,
                exec_id,
            )
        )
        self.conn.commit()

    @connection
    def new_mutation_type(self, c, mutation_type):
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        c.execute('INSERT INTO mutation_types VALUES (?, ?, ?, ?, ?, ?)',
            (
                mutation_type['pattern_name'],
                mutation_type['typeID'],
                mutation_type['pattern_location'],
                mutation_type['pattern_class'],
                mutation_type['description'],
                mutation_type['procedure'],
            )
        )
        self.conn.commit()

    @connection
    def new_run(self, c, exec_id, data):
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        mut_data = data['mut_data']
        for m_id in mut_data['mutation_ids']:
            c.execute('INSERT INTO all_runs VALUES (?, ?, ?, ?, ?)',
                (
                    exec_id,
                    mut_data['prog'],
                    m_id,
                    data['run_ctr'],
                    data['fuzzer'],
                )
            )
        self.conn.commit()

    @connection
    def done_run(self, c, reason, exec_id, prog, mut_id, run_ctr, fuzzer):
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        logger.info(f"! mut done: {reason} :: {prog} {fuzzer} {run_ctr} {mut_id}")
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
    def new_initial_supermutant(self, c, exec_id, prog, sm_id, mut_ids):
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
    def new_supermutant(self, c, exec_id, mut_data):
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        for m_id in mut_data['mutation_ids']:
            c.execute('INSERT INTO started_super_mutants VALUES (?, ?, ?, ?, ?, ?)',
                (
                    exec_id,
                    mut_data['prog'],
                    mut_data['supermutant_id'],
                    None,
                    None,
                    m_id,
                )
            )
        self.conn.commit()

    @connection
    def new_supermutant_multi(self, c, exec_id, mut_data, multi_groups, fuzzer, run_ctr, description):
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        for group_id, (result, multi) in enumerate(multi_groups):
            for m_id in multi:
                c.execute('INSERT INTO super_mutants_multi VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (
                        exec_id,
                        mut_data['prog'],
                        run_ctr,
                        fuzzer,
                        mut_data['supermutant_id'],
                        result,
                        group_id,
                        m_id,
                        description
                    )
                )
        self.conn.commit()

    @connection
    def new_mutation(self, c, exec_id, data):
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        import copy
        mut_data = copy.deepcopy(data['mutation_data'])
        mut_id = mut_data.pop('UID')
        assert int(data['mutation_id']) == int(mut_id), f"{data['mutation_id']} != {mut_id}"

        mut_additional = mut_data.pop('additionalInfo', None)
        if mut_additional is not None:
            # Remove redundant fields
            mut_additional.pop('funname', None)
            mut_additional.pop('instr', None)
            # None if no data is left else json of the data
            mut_additional = None if len(mut_additional) == 0 else json.dumps(mut_additional) 

        c.execute('INSERT INTO mutations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                exec_id,
                data['prog'],
                data['mutation_id'],
                mut_data.pop('type', None),
                mut_data.pop('directory', None),
                mut_data.pop('filePath', None),
                mut_data.pop('line', None),
                mut_data.pop('column', None),
                mut_data.pop('instr', None),
                mut_data.pop('funname', None),
                mut_additional,
                json.dumps(mut_data) if len(mut_data) > 0 else None,
            )
        )
        self.conn.commit()

    @connection
    def new_prog(self, c, exec_id, prog, data: Program):
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
                json.dumps(data.bc_compile_args),
                json.dumps(data.bin_compile_args),
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
    def new_supermutant_graph_info(self, c, exec_id, prog, graph_info):
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        # c.execute('UPDATE execution SET total_time = ? where exec_id = ?',
        c.execute('UPDATE progs SET supermutant_graph_info = ? where exec_id = ? and prog = ?',
            (
                json.dumps(graph_info),
                exec_id,
                prog,
            )
        )
        self.conn.commit()

    @connection
    def new_run_executed(self, c, exec_id, run_ctr, prog, mutation_id, fuzzer, cf_seen, total_time):
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
    def new_seeds_executed(self, c, exec_id, prog, mutation_id, run_ctr, fuzzer, cf_seen, timed_out, total_time):
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
    def new_crashing_inputs(self, c, crashing_inputs, exec_id, prog, mutation_id, run_ctr, fuzzer):
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        for data in crashing_inputs:
            if data['orig_returncode'] != 0 or data['orig_returncode'] != data['mut_returncode']:
                c.execute('INSERT INTO crashing_inputs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (
                        exec_id,
                        prog,
                        mutation_id,
                        run_ctr,
                        fuzzer,
                        data['time'],
                        "run",
                        str(data['path']),
                        None,
                        data['orig_returncode'],
                        data['mut_returncode'],
                        ' '.join((str(v) for v in data['orig_cmd'])),
                        ' '.join((str(v) for v in data['mut_cmd'])),
                        str(data['orig_res']),
                        str(data['mut_res']),
                        data['orig_timeout'],
                        data['timeout'],
                        None
                    )
                )
        self.conn.commit()

    @connection
    def new_seed_crashing_inputs(self, c, exec_id, prog, mutation_id, fuzzer, crashing_inputs):
        assert self.conn is not None, "connection wrapper returns early if conn is None"
        for data in crashing_inputs:
            if data['orig_returncode'] != 0 or data['orig_returncode'] != data['mut_returncode']:
                c.execute('INSERT INTO seed_crashing_inputs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (
                        exec_id,
                        prog,
                        mutation_id,
                        fuzzer,
                        data['time'],
                        "seeds",
                        str(data['path']),
                        None,
                        data['orig_returncode'],
                        data['mut_returncode'],
                        ' '.join((str(v) for v in data['orig_cmd'])),
                        ' '.join((str(v) for v in data['mut_cmd'])),
                        data['orig_res'],
                        data['mut_res'],
                        data['num_triggered']
                    )
                )
        self.conn.commit()

    @connection
    def run_crashed(self, c, exec_id, prog, mutation_id, run_ctr, fuzzer, trace):
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
    def supermutation_preparation_crashed(self, c, exec_id, prog, supermutant_id, trace):
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
    def mutation_preparation_crashed(self, c, exec_id, prog, supermutant_id, mutation_id):
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
    def locator_seed_covered(self, c, exec_id, prog, fuzzer, mutation_ids):
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
    def __init__(self, db_path):
        super().__init__()
        self.db = sqlite3.connect(str(db_path))

    def get_bc_file_content(self, prog: str) -> str:
        c = self.db.cursor()
        res_cur = c.execute('select orig_bc_file_data from progs where prog = ?', (prog,))
        res = [r for r in res_cur]
        assert len(res) == 1
        return res[0][0]

    def get_mutation_locations_content(self, prog: str) -> str:
        c = self.db.cursor()
        res_cur = c.execute('select mutation_locations_data from progs where prog = ?', (prog,))
        res = [r for r in res_cur]
        assert len(res) == 1
        return res[0][0]

    def get_prog_source_content(self, prog: str) -> str:
        c = self.db.cursor()
        res_cur = c.execute('select prog_source_file_data from progs where prog = ?', (prog,))
        res = [r for r in res_cur]
        assert len(res) == 1
        return res[0][0]

    def get_supermutations(self, prog: str) -> List[Dict[str, Any]]:
        c = self.db.cursor()
        res_cur = c.execute('select * from initial_super_mutants where prog = ?', (prog,))
        res = [
            {
                'exec_id': r[0],
                'prog': r[1],
                'super_mutant_id': r[2],
                'mutation_id': r[3],
            }
            for r in res_cur
        ]
        return res
