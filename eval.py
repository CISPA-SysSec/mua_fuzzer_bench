#!/usr/bin/env python3
from collections import defaultdict
import sys
import os
import time
import subprocess
import csv
import sqlite3
import traceback
import signal
import threading
import queue
import json
import shutil
import random
import re
from typing import Union, List, Tuple, Set
import psutil
import contextlib
import concurrent.futures
import shlex
import uuid
import platform
import tempfile
import hashlib
import multiprocessing
from itertools import product
from pathlib import Path

import docker

EXEC_ID = str(uuid.uuid4())

# If no fuzzing should happen and only the seed files should be run once.
JUST_CHECK_SEED_CRASHES = os.getenv("MUT_JUST_SEED_CRASHES", "0") == "1"

if JUST_CHECK_SEED_CRASHES:
    # no fuzzing is done use all resources available
    logical_cores = True
else:
    # only use physical cores to avoid runs influencing each other
    logical_cores = False

# set the number of concurrent runs
NUM_CPUS = int(os.getenv("MUT_NUM_CPUS", psutil.cpu_count(logical=logical_cores)))

# If container logs should be shown
SHOW_CONTAINER_LOGS = "MUT_LOGS" in os.environ

# Remove the working directory after a run
RM_WORKDIR = os.getenv("MUT_RM_WORKDIR", "1") == "1"

# Timeout for the fuzzers in seconds
TIMEOUT = int(os.getenv("MUT_TIMEOUT", 30 * 60))  # default half hour

# Maximum uptime for containers, they are not always stopped cleanly,
# this sets an upper bound on containers alive at once.
MAX_CONTAINER_TIME = 60*60 + TIMEOUT  # one hour plus fuzzing timeout should hopefully be enough

# Timeout for the fuzzers during seed gathering in seconds
SEED_TIMEOUT = 60 * 60 * 24  # 24 hours

# If true do filtering of mutations
FILTER_MUTATIONS = os.getenv("MUT_FILTER_MUTS", "0") == "1"

# Flag if the fuzzed seeds should be used
USE_GATHERED_SEEDS = False

# Time interval in seconds in which to check the results of a fuzzer
CHECK_INTERVAL = 5

# The path where eval data is stored outside of the docker container
HOST_TMP_PATH = Path(".").resolve()/"tmp/"

# Directy where unsolved mutants are collected
UNSOLVED_MUTANTS_DIR = HOST_TMP_PATH/"unsolved_mutants"

# The location where the eval data is mapped to inside the docker container
IN_DOCKER_WORKDIR = "/workdir/"

TRIGGERED_STR = "Triggered!\r\n"

MAX_RUN_EXEC_IN_CONTAINER_TIME = 60*15

# The directory used for seed files for all fuzzers
SEED_BASE_DIR = Path(os.getenv("MUT_SEED_DIR", "tmp/active_seeds/"))

# The programs that can be evaluated
PROGRAMS = {
    # "objdump": {
    #     "include": "",
    #     "path": "binutil/binutil/",
    #     "args": "--dwarf-check -C -g -f -dwarf -x @@",
    # },
    "re2": {
        "bc_compile_args": [
            {'val': "-std=c++11", 'action': None},
        ],
        "bin_compile_args": [
            {'val': "tmp/samples/re2_harness/harness.cc", 'action': 'prefix_workdir'},
            {'val': "-lpthread", 'action': None},
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/re2-code/re2_fuzzer")),
        "orig_bc": str(Path("tmp/samples/re2-code/re2_fuzzer.bc")),
        "name": "re2",
        "path": "samples/re2-code",
        "dict": "tmp/samples/re2_harness/re2.dict",
        "args": "@@",
    },
    "cares_parse_reply": {
        "bc_compile_args": [
            {'val': "-I", 'action': None},
            {'val': "tmp/samples/c-ares/include", 'action': 'prefix_workdir'},
            {'val': "-I", 'action': None},
            {'val': "tmp/samples/c-ares/src/lib", 'action': 'prefix_workdir'},
        ],
        "bin_compile_args": [
            {'val': "tmp/samples/c-ares/out/ares-test-fuzz.o", 'action': 'prefix_workdir'},
            {'val': "tmp/samples/common/main.cc", 'action': 'prefix_workdir'},
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/c-ares/out/ares_parse_reply_fuzzer")),
        "orig_bc": str(Path("tmp/samples/c-ares/out/libcares.bc")),
        "name": "cares",
        "path": "samples/c-ares",
        "dict": None,
        "args": "@@",
    },
    "cares_name": {
        "bc_compile_args": [
            {'val': "-I", 'action': None},
            {'val': "tmp/samples/c-ares/include", 'action': 'prefix_workdir'},
            {'val': "-I", 'action': None},
            {'val': "tmp/samples/c-ares/src/lib", 'action': 'prefix_workdir'},
        ],
        "bin_compile_args": [
            {'val': "tmp/samples/c-ares/out/ares-test-fuzz-name.o", 'action': 'prefix_workdir'},
            {'val': "tmp/samples/common/main.cc", 'action': 'prefix_workdir'},
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/c-ares/out/ares_create_query_fuzzer")),
        "orig_bc": str(Path("tmp/samples/c-ares/out/libcares.bc")),
        "name": "cares",
        "path": "samples/c-ares",
        "dict": None,
        "args": "@@",
    },
    #  "freetype": {
    #      "bc_compile_args": [
    #      ],
    #      "bin_compile_args": [
    #      ],
    #      "is_cpp": True,
    #      "orig_bin": str(Path("tmp/samples/freetype/out/ftfuzzer")),
    #      "orig_bc": str(Path("tmp/samples/freetype/out/ftfuzzer.bc")),
    #      "name": "freetype",
    #      "path": "samples/ftfuzzer",
    #      "dict": None,
    #      "args": "@@",
    #  },
    "woff2_base": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
            {'val': "tmp/samples/common/main.cc", 'action': 'prefix_workdir'},
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/woff2/out/convert_woff2ttf_fuzzer/convert_woff2ttf_fuzzer")),
        "orig_bc": str(Path("tmp/samples/woff2/out/convert_woff2ttf_fuzzer/convert_woff2ttf_fuzzer.bc")),
        "name": "woff2",
        "path": "samples/woff2/out/convert_woff2ttf_fuzzer",
        "dict": None,
        "args": "@@",
    },
    "woff2_new": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
            {'val': "tmp/samples/common/main.cc", 'action': 'prefix_workdir'},
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/woff2/out/convert_woff2ttf_fuzzer_new_entry/convert_woff2ttf_fuzzer_new_entry")),
        "orig_bc": str(Path("tmp/samples/woff2/out/convert_woff2ttf_fuzzer_new_entry/convert_woff2ttf_fuzzer_new_entry.bc")),
        "name": "woff2",
        "path": "samples/woff2/out/convert_woff2ttf_fuzzer_new_entry",
        "dict": None,
        "args": "@@",
    },
    "aspell": {
        "bc_compile_args": [
            {'val': "-lpthread", 'action': None},
            {'val': "-ldl", 'action': None},
        ],
        "bin_compile_args": [
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/aspell/out/aspell_fuzzer")),
        "orig_bc": str(Path("tmp/samples/aspell/out/aspell_fuzzer.bc")),
        "name": "aspell",
        "path": "samples/aspell/",
        "dict": None,
        "args": "@@",
    },
    #  "bloaty": {
    #      "bc_compile_args": [
    #      ],
    #      "bin_compile_args": [
    #      ],
    #      "is_cpp": True,
    #      "orig_bin": str(Path("tmp/samples/bloaty/out/fuzz_target")),
    #      "orig_bc": str(Path("tmp/samples/bloaty/out/fuzz_target.bc")),
    #      "name": "bloaty",
    #      "path": "samples/bloaty/",
    #      "dict": None,
    #      "args": "@@",
    #  },
    #  "curl": {
    #      "bc_compile_args": [
    #          {'val': "-L", 'action': None},
    #          {'val': "tmp/samples/curl/out/lib", 'action': 'prefix_workdir'},
    #          {'val': "-lpthread", 'action': None},
    #          {'val': "-lidn2", 'action': None},
    #          {'val': "-lz", 'action': None},
    #          {'val': "-lnghttp2", 'action': None},
    #      ],
    #      "bin_compile_args": [
    #      ],
    #      "is_cpp": True,
    #      "orig_bin": str(Path("tmp/samples/curl/out/curl_fuzzer")),
    #      "orig_bc": str(Path("tmp/samples/curl/out/curl_fuzzer.bc")),
    #      "name": "curl",
    #      "path": "samples/curl/",
    #      "dict": None,
    #      "args": "@@",
    #  },
    "guetzli": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/guetzli/fuzz_target")),
        "orig_bc": str(Path("tmp/samples/guetzli/fuzz_target.bc")),
        "name": "guetzli",
        "path": "samples/guetzli/",
        "dict": "tmp/samples/guetzli_harness/guetzli.dict",
        "args": "@@",
    },
    #  "mjs": {
    #      "bc_compile_args": [
    #      ],
    #      "bin_compile_args": [
    #          {'val': "-ldl", 'action': None},
    #      ],
    #      "is_cpp": False,
    #      "orig_bin": str(Path("tmp/samples/mjs/mjs/mjs")),
    #      "orig_bc": str(Path("tmp/samples/mjs/mjs/mjs.bc")),
    #      "name": "mjs",
    #      "path": "samples/mjs/",
    #      "dict": None,
    #      "args": "@@",
    #  },
    "vorbis": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/vorbis/out/decode_fuzzer")),
        "orig_bc": str(Path("tmp/samples/vorbis/out/decode_fuzzer.bc")),
        "name": "vorbis",
        "path": "samples/vorbis/",
        "dict": "tmp/samples/vorbis_harness/vorbis.dict",
        "args": "@@",
    },
    #  "harfbuzz": {
    #      "bc_compile_args": [
    #      ],
    #      "bin_compile_args": [
    #      ],
    #      "is_cpp": True,
    #      "orig_bin": str(Path("tmp/samples/harfbuzz/hb-subset-fuzzer")),
    #      "orig_bc": str(Path("tmp/samples/harfbuzz/hb-subset-fuzzer.bc")),
    #      "name": "harfbuzz",
    #      "path": "samples/harfbuzz/",
    #      "dict": None,
    #      "args": "@@",
    #  },
    #  "file": {
    #      "bc_compile_args": [
    #      ],
    #      "bin_compile_args": [
    #          {'val': "-lz", 'action': None},
    #      ],
    #      "is_cpp": False,
    #      "orig_bin": str(Path("tmp/samples/file/magic_fuzzer")),
    #      "orig_bc": str(Path("tmp/samples/file/magic_fuzzer.bc")),
    #      "name": "file",
    #      "path": "samples/file/",
    #      "dict": None,
    #      "args": "<WORK>/samples/file_harness/magic.mgc @@",
    #  },
    "libjpeg": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/libjpeg-turbo/libjpeg_turbo_fuzzer")),
        "orig_bc": str(Path("tmp/samples/libjpeg-turbo/libjpeg_turbo_fuzzer.bc")),
        "name": "libjpeg",
        "path": "samples/libjpeg-turbo/",
        "dict": "tmp/samples/libjpeg-turbo_harness/libjpeg.dict",
        "args": "@@",
    },
    #  "sqlite3": {
    #      "bc_compile_args": [
    #      ],
    #      "bin_compile_args": [
    #          {'val': "-lpthread", 'action': None},
    #          {'val': "-ldl", 'action': None},
    #      ],
    #      "is_cpp": False,
    #      "orig_bin": str(Path("tmp/samples/sqlite3/sqlite3_ossfuzz")),
    #      "orig_bc": str(Path("tmp/samples/sqlite3/sqlite3_ossfuzz.bc")),
    #      "name": "sqlite",
    #      "path": "samples/sqlite3/",
    #      "dict": None,
    #      "args": "@@",
    #  },
}

def fuzzer_container_tag(name):
    return f"mutation-testing-fuzzer-{name}"

def subject_container_tag(name):
    return f"mutation-testing-subject-{name}"

# Indicates if the evaluation should continue, is mainly used to shut down
# after a keyboard interrupt by the user.
# Global variable that is only written in the sigint_handler, as such it is safe
# to use in a read only fashion by the threads.
should_run = True

# Handler for a keyboard interrupt only sets `should_run` to False.
def sigint_handler(signum, frame):
    global should_run
    print("Got stop signal, stopping", signum)
    should_run = False

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

# A class to store information into a sqlite database. This ecpects sole access
# to the database.
class Stats():

    def __init__(self, db_path):
        super().__init__()
        if db_path is None:
            print(f"Didn't get db_path env, not writing history.")
            self.conn = None
            return
        db_path = Path(db_path)
        print(f"Writing history to: {db_path}")
        if db_path.is_file():
            print(f"DB exists, deleting: {db_path}")
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

    def _init_tables(self):
        c = self.conn.cursor()

        c.execute('''
        CREATE TABLE execution (
            exec_id,
            hostname,
            git_status,
            start_time,
            total_time
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
        CREATE TABLE progs (
            exec_id,
            prog,
            bc_compile_args,
            bin_compile_args,
            args,
            dict,
            orig_bin
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
            covered_file_seen,
            timed_out,
            total_time
        )''')

        c.execute('''
        CREATE TABLE aflpp_runs (
            exec_id,
            prog,
            mutation_id INTEGER,
            run_ctr,
            fuzzer,
            time,
            cycles_done,
            cur_path,
            paths_total,
            pending_total,
            pending_favs,
            map_size,
            unique_crashes,
            unique_hangs,
            max_depth,
            execs_per_sec,
            totals_execs
        )''')

        c.execute('''
        CREATE TABLE seed_crashing_inputs (
            exec_id,
            prog,
            mutation_id INTEGER,
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
        CREATE TABLE crashing_mutation_preparation (
            exec_id,
            prog,
            mutation_id INTEGER,
            crash_trace
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

    def commit(self):
        self.conn.commit()

    @connection
    def new_execution(self, c, exec_id, hostname, git_status, start_time):
        c.execute('INSERT INTO execution VALUES (?, ?, ?, ?, ?)',
            (
                exec_id,
                hostname,
                git_status,
                start_time,
                None
            )
        )
        self.conn.commit()

    @connection
    def execution_done(self, c, exec_id, total_time):
        c.execute('UPDATE execution SET total_time = ? where exec_id = ?',
            (
                total_time,
                exec_id,
            )
        )
        self.conn.commit()

    @connection
    def new_mutation_type(self, c, mutation_type):
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
        mut_data = data['mut_data']
        c.execute('INSERT INTO all_runs VALUES (?, ?, ?, ?, ?)',
            (
                exec_id,
                mut_data['prog'],
                mut_data['mutation_id'],
                data['run_ctr'],
                data['fuzzer'],
            )
        )
        self.conn.commit()

    @connection
    def new_mutation(self, c, exec_id, data):
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
    def new_prog(self, c, exec_id, prog, data):
        print(data)
        c.execute('INSERT INTO progs VALUES (?, ?, ?, ?, ?, ?, ?)',
            (
                exec_id,
                prog,
                json.dumps(data['bc_compile_args']),
                json.dumps(data['bin_compile_args']),
                data['args'],
                str(data['dict']),
                str(data['orig_bin']),
            )
        )
        self.conn.commit()

    @connection
    def new_run_executed(self, c, plot_data, exec_id, run_ctr, prog, mutation_id, fuzzer, cf_seen, total_time):
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
        start_time = None
        if plot_data is not None:
            for row in plot_data:
                cur_time = int(row['# unix_time'].strip())
                if start_time is None:
                    start_time = cur_time
                cur_time -= start_time
                try:
                    rest = row[None][0].strip()
                except:
                    rest = None
                c.execute('INSERT INTO aflpp_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (
                        exec_id,
                        prog,
                        mutation_id,
                        run_ctr,
                        fuzzer,
                        cur_time,
                        row[' cycles_done'].strip(),
                        row[' cur_path'].strip(),
                        row[' paths_total'].strip(),
                        row[' pending_total'].strip(),
                        row[' pending_favs'].strip(),
                        row[' map_size'].strip(),
                        row[' unique_crashes'].strip(),
                        row[' unique_hangs'].strip(),
                        row[' max_depth'].strip(),
                        row[' execs_per_sec'].strip(),
                        rest,
                    )
                )
        self.conn.commit()

    @connection
    def new_seeds_executed(self, c, exec_id, prog, mutation_id, cf_seen, timed_out, total_time):
        c.execute('INSERT INTO executed_seeds VALUES (?, ?, ?, ?, ?, ?)',
            (
                exec_id,
                prog,
                mutation_id,
                cf_seen,
                timed_out,
                total_time,
            )
        )
        self.conn.commit()

    @connection
    def new_crashing_inputs(self, c, crashing_inputs, exec_id, prog, mutation_id, run_ctr, fuzzer):
        for path, data in crashing_inputs.items():
            if data['orig_returncode'] != 0 or data['orig_returncode'] != data['mut_returncode']:
                c.execute('INSERT INTO crashing_inputs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (
                        exec_id,
                        prog,
                        mutation_id,
                        run_ctr,
                        fuzzer,
                        data['time_found'],
                        data['stage'],
                        path,
                        data['data'],
                        data['orig_returncode'],
                        data['mut_returncode'],
                        ' '.join((str(v) for v in data['orig_cmd'])),
                        ' '.join((str(v) for v in data['mut_cmd'])),
                        data['orig_res'],
                        data['mut_res'],
                        data['orig_timeout'],
                        data['mut_timeout'],
                        data['num_triggered']
                    )
                )
        self.conn.commit()

    @connection
    def new_seed_crashing_inputs(self, c, exec_id, prog, mutation_id, crashing_inputs):
        for path, data in crashing_inputs.items():
            if data['orig_returncode'] != 0 or data['orig_returncode'] != data['mut_returncode']:
                c.execute('INSERT INTO seed_crashing_inputs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (
                        exec_id,
                        prog,
                        mutation_id,
                        data['time_found'],
                        data['stage'],
                        path,
                        data['data'],
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
    def mutation_preparation_crashed(self, c, exec_id, prog, mutation_id, trace):
        c.execute('INSERT INTO crashing_mutation_preparation VALUES (?, ?, ?, ?)',
            (
                exec_id,
                prog,
                mutation_id,
                trace,
            )
        )
        self.conn.commit()

class DockerLogStreamer(threading.Thread):
    def __init__(self, q, container, *args, **kwargs):
        self.q = q
        self.container = container
        super().__init__(*args, **kwargs)

    def run(self):
        global should_run
        try:
            for line in self.container.logs(stream=True):
                line = line.decode()
                if SHOW_CONTAINER_LOGS:
                    print(line.rstrip())
                if "Fuzzing test case #" in line:
                    continue
                self.q.put(line)
        except Exception as exc:
            error_message = traceback.format_exc()
            for line in error_message.splitlines():
                self.q.put(line)
        self.q.put(None)


class CoveredFile:
    def __init__(self, workdir, start_time) -> None:
        super().__init__()
        self.found = None
        self.path = Path(workdir)/"covered"
        self.start_time = start_time

        if self.path.is_file():
            self.path.unlink()

    def check(self):
        if self.found is None and self.path.exists():
            self.found = time.time() - self.start_time

    def file_path(self):
        return self.path


@contextlib.contextmanager
def start_testing_container(core_to_use, trigger_file: CoveredFile):
    # get access to the docker client to start the container
    docker_client = docker.from_env()

    # Start and run the container
    container = docker_client.containers.run(
        "mutator_testing", # the image
        ["sleep", str(MAX_CONTAINER_TIME)], # the arguments, give a max uptime for containers
        init=True,
        ipc_mode="host",
        auto_remove=True,
        user=os.getuid(),
        environment={
            'LD_LIBRARY_PATH': "/workdir/tmp/lib/",
            'TRIGGERED_FOLDER': str(trigger_file.path),
        },
        volumes={str(HOST_TMP_PATH): {'bind': str(IN_DOCKER_WORKDIR)+"/tmp/",
                                      'mode': 'ro'}},
        working_dir=str(IN_DOCKER_WORKDIR),
        cpuset_cpus=str(core_to_use),
        mem_limit="1g",
        mem_swappiness=0,
        log_config=docker.types.LogConfig(type=docker.types.LogConfig.types.JSON,
            config={'max-size': '10m'}),
        detach=True
    )
    try:
        yield container
    except Exception as exc:
        raise exc
    finally: # This will stop the container if there is an exception or not.
        container.stop()


@contextlib.contextmanager
def start_mutation_container(core_to_use, docker_run_kwargs=None):
    # get access to the docker client to start the container
    docker_client = docker.from_env()

    # Start and run the container
    container = docker_client.containers.run(
        "mutator_mutator", # the image
        ["sleep", str(MAX_CONTAINER_TIME)], # the arguments, give a max uptime for containers
        init=True,
        ipc_mode="host",
        auto_remove=True,
        user=os.getuid(),
        volumes={str(HOST_TMP_PATH): {'bind': "/home/mutator/tmp/",
                                      'mode': 'rw'}},
        mem_limit="10g",
        mem_swappiness=0,
        cpuset_cpus=str(core_to_use) if core_to_use is not None else None,
        log_config=docker.types.LogConfig(type=docker.types.LogConfig.types.JSON,
            config={'max-size': '10m'}),
        detach=True,
        **(docker_run_kwargs if docker_run_kwargs is not None else {})
    )
    try:
        yield container
    except Exception as exc:
        raise exc
    finally: # This will stop the container if there is an exception or not.
        container.stop()


def run_exec_in_container(container, raise_on_error, cmd, exec_args=None, timeout=None):
    """
    Start a short running command in the given container,
    sigint is ignored for this command.
    If return_code is not 0, raise a ValueError containing the run result.
    """
    container_name = None
    if isinstance(container, str):
        container_name = container
    else:
        container_name = container.name

    sub_cmd = ["docker", "exec", *(exec_args if exec_args is not None else []), container_name, *cmd]
    proc = subprocess.run(sub_cmd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=MAX_RUN_EXEC_IN_CONTAINER_TIME if timeout is None else timeout,
            close_fds=True,
            preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN))
    if raise_on_error and proc.returncode != 0:
        print("process error: =======================",
                proc.args,
                proc.stdout.decode(),
                sep="\n")
        raise ValueError(proc)
    return {'returncode': proc.returncode, 'out': proc.stdout.decode()}
        ##################
        # alternative version using docker lib, this errors with lots of docker containers
        # https://github.com/docker/docker-py/issues/2278
        # 
        #  if exec_args is not None:
        #      raise ValueError("Exec args not supported for container exec_run.")
        #  proc = container.exec_run(cmd)
        #  if raise_on_error and proc[0] != 0:
        #      print("process error: =======================",
        #              cmd,
        #              proc[1],
        #              sep="\n")
        #      raise ValueError(proc)
        #  return {'returncode': proc[0], 'out': proc[1]}


def get_mut_base_dir(mut_data: dict) -> Path:
    "Get the path to the directory containing all files related to a mutation."
    return Path("/dev/shm/mut_base/")/mut_data['prog']/mut_data['mutation_id']


def get_mut_base_bin(mut_data: dict) -> Path:
    "Get the path to the bin that is the mutated base binary."
    return get_mut_base_dir(mut_data)/"mut_base"


def get_seed_dir(prog, fuzzer):
    """
    Gets the seed dir inside of SEED_BASE_DIR based on the program name.
    Further if there is a directory inside with the name of the fuzzer, that dir is used as the seed dir.
    Example:
    As a sanity check if SEED_BASE_DIR/<prog> contains files and directories then an error is thrown.
    SEED_BASE_DIR/<prog>/<fuzzer> exists then this dir is taken as the seed dir.
    SEED_BASE_DIR/<prog> contains only files, then this dir is the seed dir.
    """
    prog_seed_dir = SEED_BASE_DIR/prog
    seed_paths = list(prog_seed_dir.glob("*"))
    if any(sp.is_file() for sp in seed_paths) and any(sp.is_file() for sp in seed_paths):
        print(f"There are files and directories in {prog_seed_dir}, either the dir only contains files, "
              f"in which case all files are used as seeds for every fuzzer, or it contains only directories. "
              f"In the second case the content of each fuzzer directory is used as the seeds for the respective fuzzer.")
    # If the fuzzer specific seed dir exists, return it.
    prog_fuzzer_seed_dir = prog_seed_dir/fuzzer
    if prog_fuzzer_seed_dir.is_dir():
        return prog_fuzzer_seed_dir
    # Else just return the prog seed dir.
    return prog_seed_dir


# returns true if a crashing input is found that only triggers for the
# mutated binary
def check_crashing_inputs(testing_container, crashing_inputs, crash_dir,
                          orig_bin, mut_bin, args, start_time, covered, stage):
    if not crash_dir.is_dir():
        return False

    for path in list(str(pp) for pp in crash_dir.glob("**/*")):
        path = Path(path)
        if path.is_file() and path.name != "README.txt":
            if str(path) not in crashing_inputs:
                input_args = args.replace("<WORK>/", IN_DOCKER_WORKDIR
                        ).replace("@@", str(path)
                        ).replace("___FILE___", str(path))
                # Run input on original binary
                orig_cmd = ["/run_bin.sh", str(orig_bin)] + shlex.split(input_args)
                try:
                    proc = run_exec_in_container(testing_container.name, False, orig_cmd, timeout=10)
                except subprocess.TimeoutExpired:
                    orig_timed_out = True
                    orig_res = 0
                    orig_returncode = 0
                else:
                    orig_timed_out = False
                    orig_res = proc['out']
                    orig_returncode = proc['returncode']
                    if orig_returncode != 0:
                        print("orig bin returncode != 0, crashing base bin:")
                        print("args:", orig_cmd, "returncode:", orig_returncode)
                        print(orig_res)

                # Run input on mutated binary
                mut_cmd = ["/run_bin.sh", str(mut_bin)] + shlex.split(input_args)
                try:
                    proc = run_exec_in_container(testing_container.name, False, mut_cmd, timeout=10)
                except subprocess.TimeoutExpired:
                    mut_timed_out = True
                    num_triggered = 0
                    mut_res = 0
                    mut_returncode = 0
                else:
                    mut_timed_out = False
                    mut_res = proc['out']
                    num_triggered = len(mut_res.split(TRIGGERED_STR)) - 1
                    mut_res = mut_res.replace(TRIGGERED_STR, "")
                    mut_res = mut_res
                    mut_returncode = proc['returncode']

                covered.check()

                try:
                    crash_file_data = path.read_bytes()
                except Exception as exc:
                    crash_file_data = "{}".format(exc)

                crashing_inputs[str(path)] = {
                    'time_found': time.time() - start_time,
                    'stage': stage,
                    'data': crash_file_data,
                    'orig_returncode': orig_returncode,
                    'mut_returncode': mut_returncode,
                    'orig_cmd': orig_cmd,
                    'mut_cmd': mut_cmd,
                    'orig_res': orig_res,
                    'mut_res': mut_res,
                    'num_triggered': num_triggered,
                    'orig_timeout': orig_timed_out,
                    'mut_timeout': mut_timed_out,
                }

                if (orig_returncode != mut_returncode):  # or orig_res != mut_res):
                    return True
    return False


# Eval function for the afl plus plus fuzzer, compiles the mutated program
# and fuzzes it. Finally various eval data is returned
def base_eval(run_data, docker_image):
    # get start time for the eval
    start_time = time.time()

    global should_run
    # extract used values
    mut_data = run_data['mut_data']
    workdir = run_data['workdir']
    crash_dir = workdir/run_data['crash_dir']
    prog_bc = mut_data['prog_bc']
    compile_args = mut_data['compile_args']
    args = run_data['fuzzer_args']
    seeds = get_seed_dir(mut_data['prog'], run_data['fuzzer'])
    dictionary = mut_data['dict']
    orig_bin = Path(IN_DOCKER_WORKDIR)/"tmp"/Path(mut_data['orig_bin']).relative_to(HOST_TMP_PATH)
    core_to_use = run_data['used_core']
    docker_mut_bin = get_mut_base_bin(mut_data)

    workdir.mkdir(parents=True, exist_ok=True)

    # get path for covered file and rm the file if it exists
    covered = CoveredFile(workdir, start_time)

    # start testing container
    with start_testing_container(core_to_use, covered) as testing_container:

        # set up data for crashing inputs
        crashing_inputs = {}

        # get access to the docker client to start the container
        docker_client = docker.from_env()
        # Start and run the container
        container = docker_client.containers.run(
            docker_image, # the image
            [
                "/home/user/eval.sh",
                str(compile_args),
                str(prog_bc),
                str(IN_DOCKER_WORKDIR/seeds),
                str(args)
            ], # the arguments
            environment={
                'TRIGGERED_OUTPUT': str(""),
                'TRIGGERED_FOLDER': str(covered.path),
                **({'DICT_PATH': str(Path(IN_DOCKER_WORKDIR)/dictionary)} if dictionary is not None else {}),
            },
            init=True,
            cpuset_cpus=str(core_to_use),
            auto_remove=True,
            volumes={
                str(HOST_TMP_PATH): {'bind': str(IN_DOCKER_WORKDIR)+"/tmp/", 'mode': 'ro'},
                "/dev/shm": {'bind': "/dev/shm", 'mode': 'rw'},
            },
            working_dir=str(workdir),
            mem_limit="10g",
            mem_swappiness=0,
            log_config=docker.types.LogConfig(type=docker.types.LogConfig.types.JSON,
                config={'max-size': '10m'}),
            detach=True
        )

        logs_queue = queue.Queue()
        DockerLogStreamer(logs_queue, container).start()

        fuzz_time = time.time()
        while time.time() < fuzz_time + TIMEOUT and should_run:
            # check if the process stopped, this should only happen in an
            # error case
            try:
                container.reload()
            except docker.errors.NotFound:
                # container is dead stop waiting
                break
            if container.status not in ["running", "created"]:
                break

            # Check if covered file is seen
            covered.check()

            # Check if a crashing input has already been found
            if check_crashing_inputs(testing_container, crashing_inputs,
                                     crash_dir, orig_bin, docker_mut_bin, args,
                                     start_time, covered, "runtime"):
                break

            # Sleep so we only check sometimes and do not busy loop
            time.sleep(CHECK_INTERVAL)

        # Check if container is still running
        try:
            container.reload()
            if container.status in ["running", "created"]:

                # Send sigint to the process
                container.kill(2)

                # Wait up to 10 seconds then send sigkill
                container.stop()
        except docker.errors.NotFound:
            # container is dead just continue maybe it worked
            pass


        # Also collect all crashing outputs
        check_crashing_inputs(testing_container, crashing_inputs, crash_dir,
                                orig_bin, docker_mut_bin, args, start_time,
                                covered, "final")

        all_logs = []
        while True:
            line = logs_queue.get()
            if line == None:
                break
            all_logs.append(line)

        return {
            'total_time': time.time() - start_time,
            'covered_file_seen': covered.found,
            'crashing_inputs': crashing_inputs,
            'all_logs': all_logs,
        }

def get_aflpp_logs(workdir, all_logs):
    try:
        plot_path = list(Path(workdir).glob("**/plot_data"))
        if len(plot_path) == 1:
            # Get the final stats and report them
            with open(plot_path[0]) as csvfile:
                plot_data = list(csv.DictReader(csvfile))
                # only get last row, to reduce memory usage
                # The very last row sometimes has wrong data, try second to last first.
                try:
                    return [plot_data[-2]]
                except IndexError:
                    pass
                # Second to last row not found, there is probably only one row, get it.
                try:
                    return [plot_data[-1]]
                except IndexError:
                    pass
                # No data found, return nothing
                return []
        else:
            # Did not find a plot
            return []

    except Exception as exc:
        raise ValueError(''.join(all_logs)) from exc


def aflpp_rec_eval(run_data, run_func):
    run_data['crash_dir'] = "output/default/crashes"
    run_data['fuzzer_args'] = run_data['mut_data']['args']
    result = run_func(run_data, fuzzer_container_tag("aflpp_rec"))
    result['plot_data'] = get_aflpp_logs(run_data['workdir'], result['all_logs'])
    return result

def aflpp_det_eval(run_data, run_func):
    run_data['crash_dir'] = "output/default/crashes"
    run_data['fuzzer_args'] = run_data['mut_data']['args']
    result = run_func(run_data, fuzzer_container_tag("aflpp_det"))
    result['plot_data'] = get_aflpp_logs(run_data['workdir'], result['all_logs'])
    return result

def afl_eval(run_data, run_func):
    run_data['crash_dir'] = "output/crashes"
    run_data['fuzzer_args'] = run_data['mut_data']['args']
    result = run_func(run_data, fuzzer_container_tag("afl"))
    result['plot_data'] = get_aflpp_logs(run_data['workdir'], result['all_logs'])
    return result

def aflppfastexploit_eval(run_data, run_func):
    run_data['crash_dir'] = "output/default/crashes"
    run_data['fuzzer_args'] = run_data['mut_data']['args']
    result = run_func(run_data, fuzzer_container_tag("aflpp_fast_exploit"))
    result['plot_data'] = get_aflpp_logs(run_data['workdir'], result['all_logs'])
    return result

def aflppmopt_eval(run_data, run_func):
    run_data['crash_dir'] = "output/default/crashes"
    run_data['fuzzer_args'] = run_data['mut_data']['args']
    result = run_func(run_data, fuzzer_container_tag("aflpp_mopt"))
    result['plot_data'] = get_aflpp_logs(run_data['workdir'], result['all_logs'])
    return result

def fairfuzz_eval(run_data, run_func):
    run_data['crash_dir'] = "output/crashes"
    run_data['fuzzer_args'] = run_data['mut_data']['args']
    result = run_func(run_data, fuzzer_container_tag("fairfuzz"))
    result['plot_data'] = get_aflpp_logs(run_data['workdir'], result['all_logs'])
    return result

def honggfuzz_eval(run_data, run_func):
    run_data['crash_dir'] = "crashes"
    run_data['fuzzer_args'] = run_data['mut_data']['args'].replace("@@", "___FILE___")
    result = run_func(run_data, fuzzer_container_tag("honggfuzz"))
    result['plot_data'] = []
    return result

def libfuzzer_eval(run_data, run_func):
    result = run_func(run_data, fuzzer_container_tag("libfuzzer"))
    return result


def resolve_compile_args(args, workdir):
    resolved = []
    for arg in args:
        if arg['action'] is None:
            resolved.append(arg['val'])
        elif arg['action'] == 'prefix_workdir':
            resolved.append(str(Path(workdir)/arg['val']))
        else:
            raise ValueError("Unknown action: {}", arg)
    return resolved

def build_compile_args(args, workdir):
    args = resolve_compile_args(args, workdir)
    return " ".join(map(shlex.quote, args))

# The fuzzers that can be evaluated, value is the function used to start an
# evaluation run
# A evaluation function should do following steps:
    # execute the fuzzer while monitoring if the crash was found
    # this includes running the crashing input in the uninstrumented
    # binary to see if it still crashes, as well as running it in the
    # original unmutated binary to see that it does not crash
    # once the crash is found update the stats (executions, time) but
    # also store the crashing input and path to the corresponding
    # mutated binary
FUZZERS = {
    #  "libfuzzer": libfuzzer_eval,
    "afl": afl_eval,
    "aflpp_rec": aflpp_rec_eval,
    "aflpp_det": aflpp_det_eval,
    "aflpp_fast_exploit": aflppfastexploit_eval,
    "aflpp_mopt": aflppmopt_eval,
    "fairfuzz": fairfuzz_eval,
    "honggfuzz": honggfuzz_eval,
}


def instrument_prog(container, prog_info):
    # Compile the mutation location detector for the prog.
    args = ["./run_mutation.py",
            "-bc", prog_info['orig_bc'],
            *(["-cpp"] if prog_info['is_cpp'] else []),  # conditionally add cpp flag
            "--bc-args=" + build_compile_args(prog_info['bc_compile_args'], IN_DOCKER_WORKDIR),
            "--bin-args=" + build_compile_args(prog_info['bin_compile_args'], IN_DOCKER_WORKDIR)]

    run_exec_in_container(container.name, True, args)


def build_detector_binary(container, prog_info, detector_path, workdir):
    print(run_exec_in_container(container.name, True, [
            "./run_mutation.py",
            str(prog_info['orig_bc']),
            *(['-cpp'] if prog_info['is_cpp'] else []),
            "-bn",
            "--bc-args=" + build_compile_args(prog_info['bc_compile_args'], workdir),
            "--bin-args=" + build_compile_args(prog_info['bin_compile_args'], workdir),
            "--out-dir", str(detector_path.parent)
            ]
    )['out'])


def get_all_mutations(stats, mutator, progs):
    all_mutations = []
    # For all programs that can be done by our evaluation
    for prog in progs:
        try:
            prog_info = PROGRAMS[prog]
        except Exception as err:
            print(err)
            print(f"Prog: {prog} is not known, known progs are: {PROGRAMS.keys()}")
            sys.exit(1)
        stats.new_prog(EXEC_ID, prog, prog_info)
        start = time.time()
        print(f"Compiling base and locating mutations for {prog}")

        # Run the seeds through the mutation detector
        mutation_list_dir = Path("/dev/shm/mutation_detection")/prog
        seeds = Path(SEED_BASE_DIR/prog)

        instrument_prog(mutator, prog_info)

        if FILTER_MUTATIONS:
            mutation_container_name = mutator.name
            SIGNAL_FOLDER_NAME = Path("trigger_signal")
            mutator_home = Path("/home/mutator")
            detector_bin = mutator_home/Path(prog_info['orig_bc']).with_suffix(".ll.opt_mutate")
            mutator_tmp_path = mutator_home/"tmp"
            prog_path = mutator_home/detector_bin

            detector_bin = Path(prog_info['orig_bc']).with_suffix(".ll.opt_mutate")
            print("Building detector binary...")
            build_detector_binary(mutator, prog_info, detector_bin, ".")
            print("Filtering mutations, running all seed files.")

            filtered_mutations = set()

            for counter, seed in enumerate(list(seeds.glob("**/*"))):
                _, found_mutations = eval_seed(counter, seed, mutator_home, SIGNAL_FOLDER_NAME, prog_info,
                          mutation_container_name, mutator_home, prog_path)
                filtered_mutations |= found_mutations

        # get additional info on mutations
        mut_data_path = list(Path(HOST_TMP_PATH/prog_info['path'])
                                .glob('**/*.ll.mutationlocations'))
        assert len(mut_data_path) == 1, f"found: {mut_data_path}"
        mut_data_path = mut_data_path[0]
        with open(mut_data_path, 'rt') as f:
            mutation_data = json.load(f)

        # Get all mutations that are possible with that program, they are identified by the file names
        # in the mutation_list_dir
        if FILTER_MUTATIONS:
            print("Filtering mutations, checking the found mutations.")
            mutations = list((str(mut_id), prog, prog_info, mutation_data) for mut_id in filtered_mutations)
        else:
            mutations = list((str(p['UID']), prog, prog_info, mutation_data) for p in mutation_data)

        print(f"Found {len(mutations)} mutations for {prog}")

        for mut in mutations:
            stats.new_mutation(EXEC_ID, {
                'prog': mut[1],
                'mutation_id': mut[0],
                'mutation_data': mut[3][int(mut[0])],
            })

        all_mutations.extend(mutations)
        print(f"Preparations for {prog} took: {time.time() - start:.2f} seconds")

    return all_mutations

def sequence_mutations(all_mutations):
    """
    Randomize order mutations in a way to get the most diverse mutations first.
    Diverse as in the mutations are from different progs and different types.
    """
    random.shuffle(all_mutations)
    grouped_mutations = defaultdict(list)
    for mut in all_mutations:
        prog = mut[1]
        mutation_id = mut[0]
        mutation_type = mut[3][int(mutation_id)]['type']
        grouped_mutations[(prog, mutation_type)].append(mut)

    sequenced_mutations = []

    while len(grouped_mutations) > 0:
        empty_lists = []
        for key, mut_list in grouped_mutations.items():
            sequenced_mutations.append(mut_list.pop())
            if len(mut_list) == 0:
                empty_lists.append(key)
        for empty in empty_lists:
            del grouped_mutations[empty]

    return sequenced_mutations

# Generator that first collects all possible runs and adds them to stats.
# Then yields all information needed to start a eval run
def get_all_runs(stats, fuzzers, progs, num_repeats):
    with start_mutation_container(None) as mutator:
        all_mutations = get_all_mutations(stats, mutator, progs)

        all_mutations = sequence_mutations(all_mutations)

        all_runs = []

        # Go through the mutations
        for (mutation_id, prog, prog_info, mutation_data) in all_mutations:
            # Gather all data for a mutation
            # Get the path to the file that should be included during compilation
            compile_args = build_compile_args(prog_info['bc_compile_args'] + prog_info['bin_compile_args'], IN_DOCKER_WORKDIR)
            # Arguments on how to execute the binary
            args = prog_info['args']
            # Original binary to check if crashing inputs also crash on
            # unmodified version
            orig_bin = str(Path(prog_info['orig_bin']).absolute())

            mut_data = {
                'orig_bc': prog_info['orig_bc'],
                'compile_args': compile_args,
                'is_cpp': prog_info['is_cpp'],
                'args': args,
                'prog': prog,
                'dict': prog_info['dict'],
                'orig_bin': orig_bin,
                'mutation_id': mutation_id,
                'mutation_data': mutation_data[int(mutation_id)],
            }

            # Also add the bc file that should be fuzzed (and instrumented).
            prog_bc_base = get_mut_base_dir(mut_data)
            prog_bc_name = (Path(prog_info['orig_bc']).with_suffix(f".ll.{mutation_id}.mut.bc").name)
            prog_bc = prog_bc_base/prog_bc_name
            mut_data['prog_bc'] = prog_bc

            # For each fuzzer gather all information needed to start a eval run
            fuzzer_runs = []
            for fuzzer in fuzzers:
                try:
                    eval_func = FUZZERS[fuzzer]
                except Exception as err:
                    print(err)
                    print(f"Fuzzer: {fuzzer} is not known, known fuzzers are: {FUZZERS.keys()}")
                    sys.exit(1)
                # Get the working directory based on program and mutation id and
                # fuzzer, which is a unique path for each run
                for run_ctr in range(num_repeats):
                    workdir = Path("/dev/shm/mutator/")/prog/mutation_id/fuzzer/str(run_ctr)
                    # gather all info
                    run_data = {
                        'run_ctr': run_ctr,
                        'fuzzer': fuzzer,
                        'eval_func': eval_func,
                        'workdir': workdir,
                        'mut_data': mut_data,
                    }
                    # Add that run to the database, so that we know it is possible
                    stats.new_run(EXEC_ID, run_data)
                    fuzzer_runs.append(run_data)
            # Build our list of runs
            all_runs.append((mut_data, fuzzer_runs))

    return all_runs


def clean_up_mut_base_dir(mut_data):
    # Remove mut base dir.
    mut_base_dir = get_mut_base_dir(mut_data)
    try:
        shutil.rmtree(mut_base_dir)
    except OSError:
        traceback.print_exc()


# Helper function to wait for the next eval run to complete.
# Also updates the stats and which cores are currently used.
# If `break_after_one` is true, return after a single run finishes.
def handle_run_result(stats, active_mutants, run_future, data):
    mut_data = data['mut_data']
    prog_bc = mut_data['prog_bc']
    try:
        # if there was no exception get the data
        run_result = run_future.result()
    except Exception:
        # if there was an exception record it
        trace = traceback.format_exc()
        stats.run_crashed(EXEC_ID, mut_data['prog'], mut_data['mutation_id'], data['run_ctr'], data['fuzzer'], trace)
        print(f"= run ###:      {mut_data['prog']}:{mut_data['mutation_id']}:{data['fuzzer']}")
    else:
        # if successful log the run
        stats.new_run_executed(
            run_result['plot_data'],
            EXEC_ID,
            data['run_ctr'],
            mut_data['prog'],
            mut_data['mutation_id'],
            data['fuzzer'],
            run_result['covered_file_seen'],
            run_result['total_time'])
        stats.new_crashing_inputs(
            run_result['crashing_inputs'],
            EXEC_ID,
            mut_data['prog'],
            mut_data['mutation_id'],
            data['run_ctr'],
            data['fuzzer'])
        # Update if the mutant has at least been killed once
        if active_mutants[prog_bc]['killed'] is False:
            for ci in run_result['crashing_inputs'].values():
                if ci['orig_returncode'] != ci['mut_returncode']:
                    active_mutants[prog_bc]['killed'] = True
        print(f"= run [+]:      {mut_data['prog']}:{mut_data['mutation_id']}:{data['fuzzer']}")

    # Update mutant reference count and remove mutant data if no more references
    active_mutants[prog_bc]['ref_cnt'] -= 1
    if active_mutants[prog_bc]['ref_cnt'] == 0:
        # If mutant was never killed, we want to keep a copy for inspection.
        if not active_mutants[prog_bc]['killed']:
            if prog_bc.is_file():
                shutil.copy(str(prog_bc), UNSOLVED_MUTANTS_DIR)

        clean_up_mut_base_dir(mut_data)
    elif active_mutants[prog_bc]['ref_cnt'] < 0:
        print("error negative mutant reference count")

    # Delete the working directory as it is not needed anymore
    if RM_WORKDIR:
        workdir = Path(data['workdir'])
        if workdir.is_dir():
            try:
                shutil.rmtree(workdir)
            except OSError:
                traceback.print_exc()
        try:
            # Also remove parent if it doesn't contain anything anymore.
            # That is all runs for this mutation are done.
            workdir.parent.rmdir()
        except Exception:
            pass


def handle_mutation_result(stats, prepared_runs, active_mutants, task_future, data):
    os.system("docker ps | wc -l")
    _, mut_data, fuzzer_runs = data
    prog = mut_data['prog']
    mutation_id = mut_data['mutation_id']

    try:
        # If there was no exception get the data.
        task_result = task_future.result()
    except Exception:
        # If there was an exception record it.
        trace = traceback.format_exc()
        stats.mutation_preparation_crashed(EXEC_ID, prog, mutation_id, trace)
        print(f"= mutation ###: crashed {prog}:{mutation_id}")

        # Nothing more to do.
        return

    stats.new_seeds_executed(EXEC_ID, prog, mutation_id,
            task_result['covered_file_seen'], task_result['timed_out'], task_result['total_time'])

    # Record if seeds timed out, if so, do not add to prepared runs.
    if task_result['timed_out']:
        print(f"= mutation [+]: (timeout) {prog}:{mutation_id}")
        clean_up_mut_base_dir(mut_data)
        return

    # Record if seeds found the mutant, if so, do not add to prepared runs.
    if task_result['found_by_seeds']:
        print(f"= mutation [+]: (seed found) {prog}:{mutation_id}")
        stats.new_seed_crashing_inputs(EXEC_ID, prog, mutation_id, task_result['crashing_inputs'])
        clean_up_mut_base_dir(mut_data)
        return

    print(f"= mutation [+]: {prog}:{mutation_id}")

    # If we just want to check if the seeds find a mutation, do not start any fuzzer runs.
    if JUST_CHECK_SEED_CRASHES:
        clean_up_mut_base_dir(mut_data)
        return

    # Otherwise add all possible runs to prepared runs.
    for fr in fuzzer_runs:
        prepared_runs.put_nowait(fr)

    # Update reference count for this mutant
    active_mutants[mut_data['prog_bc']]['ref_cnt'] += len(fuzzer_runs)


def wait_for_task(stats, tasks, cores, prepared_runs, active_mutants):
    "Wait for a task to complete and process the result."
    assert len(tasks) > 0, "Trying to wait for a task but there are none."

    # wait for a task to complete
    completed_task = next(concurrent.futures.as_completed(tasks))
    # get the data associated with the task and remove the task from the list
    (task_type, core, data) = tasks[completed_task]
    del tasks[completed_task]

    # handle the task result
    if task_type == "run":
        handle_run_result(stats, active_mutants, completed_task, data)
    elif task_type == "mutation":
        handle_mutation_result(stats, prepared_runs, active_mutants, completed_task, data)
    else:
        raise ValueError("Unknown task type.")

    # free the core for future use
    cores.release_core(core)


def check_seeds_crashing(testing_container, seed_dir, orig_bin, mut_bin, args, covered):
    if not seed_dir.is_dir():
        raise ValueError(f"Given seed dir path is not a directory: {seed_dir}")

    proc = run_exec_in_container(testing_container.name, False,
            ['/iterate_seeds.py',
                '--seeds', seed_dir,
                '--args', args,
                '--orig', orig_bin,
                '--mut', mut_bin,
                '--workdir', IN_DOCKER_WORKDIR],
            ['--env', f"TRIGGERED_FOLDER={covered.path}"], timeout=60*5)
    returncode = proc['returncode']
    if returncode == 0:
        return (False, "")
    elif returncode == 1:
        return (True, proc['out'])
    else:
        raise ValueError(f"Failed to execute seed files: {proc}")


def prepare_mutation(core_to_use, data):
    start_time = time.time()

    prog_bc = data['prog_bc']
    compile_args = data['compile_args']
    mut_base_dir = get_mut_base_dir(data)
    mut_base_dir.mkdir(parents=True, exist_ok=True)
    prog_bc.parent.mkdir(parents=True, exist_ok=True)

    # get path for covered file and rm the file if it exists
    covered = CoveredFile(mut_base_dir, time.time())

    with start_mutation_container(core_to_use) as mutator, \
         start_testing_container(core_to_use, covered) as testing:

        run_mut_res = None
        clang_res = None
        try:
            run_mut_res = run_exec_in_container(mutator.name, True, [
                    "./run_mutation.py",
                    "-bc",
                    *(["-cpp"] if data['is_cpp'] else []),  # conditionally add cpp flag
                    "-m", data['mutation_id'],
                    "--out-dir", str(mut_base_dir),
                    data['orig_bc']
            ])

            # compile the compare version of the mutated binary
            clang_res = run_exec_in_container(testing, True, [
                    "/usr/bin/clang++-11",
                    "-v",
                    "-o", str(mut_base_dir/"mut_base"),
                    *shlex.split(compile_args),
                    "/workdir/tmp/lib/libdynamiclibrary.so",
                    str(prog_bc)
            ] )
        except Exception as exc:
            raise RuntimeError(f"Failed to compile mutation:\nrun_mutation output:\n{run_mut_res}\nclang output:\n{clang_res}\n") from exc

        seeds = SEED_BASE_DIR/data['prog']
        orig_bin = Path(IN_DOCKER_WORKDIR)/"tmp"/Path(data['orig_bin']).relative_to(HOST_TMP_PATH)
        args = data['args']
        docker_mut_bin = get_mut_base_bin(data)

        # check if seeds are already crashing
        checked_seeds = {}

        # do an initial check to see if the seed files are already crashing
        try:
            (found_by_seeds, seeds_out) = check_seeds_crashing(testing, seeds,
                    orig_bin, docker_mut_bin, args, covered)
        except subprocess.TimeoutExpired:
            return {
                'total_time': time.time() - start_time,
                'covered_file_seen': None,
                'crashing_inputs': checked_seeds,
                'found_by_seeds': None,
                'timed_out': True,
                'all_logs': []
            }
        if found_by_seeds:
            checked_seeds['bulk'] = {
                    'time_found': 0,
                    'stage': 'initial',
                    'data': None,
                    'orig_returncode': 0,
                    'mut_returncode': 1,
                    'orig_cmd': [],
                    'mut_cmd': [],
                    'orig_res': None,
                    'mut_res': seeds_out,
                    'num_triggered': None,
            }

        covered.check()

        return {
            'total_time': time.time() - start_time,
            'covered_file_seen': covered.found,
            'crashing_inputs': checked_seeds,
            'found_by_seeds': found_by_seeds,
            'timed_out': False,
            'all_logs': [seeds_out]
        }


class CpuCores():
    def __init__(self, num_cores):
        self.cores: list[bool] =  [False]*num_cores

    def try_reserve_core(self) -> Union[int, None]:
        try:
            idx = self.cores.index(False)
            self.cores[idx] = True
            return idx
        except ValueError:
            return None

    def release_core(self, idx):
        assert self.cores[idx] == True, "Trying to release a already free core"
        self.cores[idx] = False


def print_run_start_msg(run_data):
    prog = run_data['mut_data']['prog']
    mutation_id = run_data['mut_data']['mutation_id']
    fuzzer = run_data['fuzzer']
    run_ctr = run_data['run_ctr']
    print(f"> run:          {prog}:{mutation_id}:{fuzzer}:{run_ctr}")



def print_mutation_prepare_start_msg(ii, mut_data, fuzzer_runs, start_time, num_mutations):
    cur_time = (time.time() - start_time)/(60*60)
    percentage_done = ii/num_mutations
    try:
        time_total = cur_time / percentage_done
        time_left = time_total - cur_time
    except ZeroDivisionError:
        time_total = 0
        time_left = 0
    fuzzers = " ".join(set(ff['fuzzer'] for ff in fuzzer_runs))
    num_repeats = max(ff['run_ctr'] for ff in fuzzer_runs) + 1
    print(f"> mutation:     {ii}/{num_mutations} ({percentage_done*100:05.2f}%) @ "
          f"{cur_time:.2f}|{time_left:.2f}|{time_total:.2f} hours: "
          f"{mut_data['prog']}:{mut_data['mutation_id']} - {num_repeats} - {fuzzers}")

def get_git_status():
    proc_rev = subprocess.run(['git', 'rev-parse', 'HEAD'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc_rev.returncode != 0:
        print("Could not get git rev.", proc_rev)
        sys.exit(1)
    proc_status = subprocess.run(['git', 'status'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc_status.returncode != 0:
        print("Could not get git status.", proc_status)
        sys.exit(1)

    return proc_rev.stdout.decode() + '\n' + proc_status.stdout.decode()


def build_subject_docker_images(progs):
    # build the subject docker images
    known_programs = list(PROGRAMS.keys())

    for prog in progs:
        if prog not in known_programs:
            print(f"Unknown program: {prog}, known programs are: {' '.join(known_programs)}")
            sys.exit(1)

    for name in set(PROGRAMS[prog]['name'] for prog in progs):
        tag = subject_container_tag(name)
        print(f"Building docker image for {tag} ({name})")
        proc = subprocess.run([
            "docker", "build",
            "--build-arg", f"CUSTOM_USER_ID={os.getuid()}",
            "--tag", tag,
            "-f", f"subjects/Dockerfile.{name}",
            "."], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if proc.returncode != 0:
            print(f"Could not build {tag} image.", proc)
            sys.exit(1)
        # extract sample files
        proc = subprocess.run(f"""
            docker rm dummy || true
            docker create -ti --name dummy {tag} bash
            docker cp dummy:/home/mutator/samples tmp/
            docker rm -f dummy""", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if proc.returncode != 0:
            print(f"Could not extract {tag} image sample files.", proc)
            sys.exit(1)


def build_docker_images(fuzzers, progs):
    # build testing image
    proc = subprocess.run([
            "docker", "build",
            "-t", "mutator_testing",
            "--build-arg", f"CUSTOM_USER_ID={os.getuid()}",
            "-f", "eval/Dockerfile.testing",
            "."
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode != 0:
        print("Could not build testing image.", proc)
        sys.exit(1)

    # build the fuzzer docker images
    for name in ["system"] + fuzzers:
        if name != 'system' and name not in FUZZERS.keys():
            print(f"Unknown fuzzer: {name}, known fuzzers are: {' '.join(list(FUZZERS.keys()))}")
            sys.exit(1)
        tag = fuzzer_container_tag(name)
        print(f"Building docker image for {tag} ({name})")
        proc = subprocess.run([
            "docker", "build",
            "--build-arg", f"CUSTOM_USER_ID={os.getuid()}",
            "--tag", tag,
            "-f", f"eval/{name}/Dockerfile",
            "."], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if proc.returncode != 0:
            print(f"Could not build {tag} image.", proc)
            sys.exit(1)

    build_subject_docker_images(progs)


def run_eval(progs, fuzzers, num_repeats):
    global should_run

    execution_start_time = time.time()

    # prepare environment
    base_shm_dir = Path("/dev/shm/mutator")
    base_shm_dir.mkdir(parents=True, exist_ok=True)

    # Initialize the stats object
    stats = Stats("/dev/shm/mutator/stats.db")

    # Record current eval execution data
    # Get the current git status
    git_status = get_git_status()
    stats.new_execution(EXEC_ID, platform.uname()[1], git_status, execution_start_time)

    # Get a record of all mutation types.
    with open("mutation_doc.json", "rt") as f:
        mutation_types = json.load(f)
        for mt in mutation_types:
            stats.new_mutation_type(mt)

    build_docker_images(fuzzers, progs)

    UNSOLVED_MUTANTS_DIR.mkdir(exist_ok=True, parents=True)

    # Keep a list of which cores can be used
    cores = CpuCores(NUM_CPUS)

    # mutants in use
    active_mutants = defaultdict(lambda: {'ref_cnt': 0, 'killed': False})

    # for each mutation and for each fuzzer do a run
    with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_CPUS) as executor:
        # keep a list of all tasks
        tasks = {}
        # a list of currently prepared but not yet started runs
        prepared_runs = queue.Queue()
        # start time
        start_time = time.time()
        # Get each run
        all_runs = get_all_runs(stats, fuzzers, progs, num_repeats)
        num_runs = len(all_runs)
        all_runs = enumerate(all_runs)

        while True:
            # If we should stop, do so now to not create any new run.
            if not should_run:
                break

            # Check if a core is free
            core = cores.try_reserve_core()

            if core is not None:
                # A core is free, start a new task.

                # Check if any runs are prepared
                if not prepared_runs.empty():
                    # A run is ready, get it and start the run.
                    run_data = prepared_runs.get_nowait()

                    # update core, print message and submit task
                    run_data['used_core'] = core
                    print_run_start_msg(run_data)
                    tasks[executor.submit(run_data['eval_func'], run_data, base_eval)] = ("run", core, run_data)
                else:
                    # No runs are ready, prepare a mutation and all corresponding runs.
                    try:
                        # Get the next mutant
                        ii, (mut_data, fuzzer_runs) = next(all_runs)

                        # update core, print message and submit task
                        mut_data['used_core'] = core
                        print_mutation_prepare_start_msg(ii, mut_data, fuzzer_runs, start_time, num_runs)
                        tasks[executor.submit(prepare_mutation, core, mut_data)] = \
                            ("mutation", core, (ii, mut_data, fuzzer_runs))

                    except StopIteration:
                        # Done with all mutations and runs, break out of this loop and finish eval.
                        break

            else:
                # No core is free wait for a task to complete.
                wait_for_task(stats, tasks, cores, prepared_runs, active_mutants)

        # Wait for remaining tasks to complete
        print(f"Waiting for remaining tasks to complete, {len(tasks)} to go..")
        while len(tasks) > 0:
            print(f"{len(tasks)}")
            wait_for_task(stats, tasks, cores, prepared_runs, active_mutants)

    # Record total time for this execution.
    stats.execution_done(EXEC_ID, time.time() - execution_start_time)

    print("eval done :)")


def get_seed_gathering_runs(fuzzers, progs, num_repeats):
    all_runs = []

    for prog in progs:
        try:
            prog_info = PROGRAMS[prog]
        except Exception as err:
            print(err)
            print(f"Prog: {prog} is not known, known progs are: {PROGRAMS.keys()}")
            sys.exit(1)

        fuzzer_runs = []
        for fuzzer in fuzzers:
            try:
                eval_func = FUZZERS[fuzzer]
            except Exception as err:
                print(err)
                print(f"Fuzzer: {fuzzer} is not known, known fuzzers are: {FUZZERS.keys()}")
                sys.exit(1)

            # Gather all data to start a seed gathering run

            # Compile arguments
            compile_args = build_compile_args(prog_info['bc_compile_args'] + prog_info['bin_compile_args'], IN_DOCKER_WORKDIR)
            # Arguments on how to execute the binary
            args = prog_info['args']

            mut_data = {
                'orig_bc': Path(IN_DOCKER_WORKDIR)/prog_info['orig_bc'],
                'compile_args': compile_args,
                'is_cpp': prog_info['is_cpp'],
                'args': args,
                'prog': prog,
                'dict': prog_info['dict'],
            }

            for _ in range(num_repeats):

                workdir = Path(tempfile.mkdtemp(prefix=f"{prog}__{fuzzer}__", dir="/dev/shm/mutator_seed_gathering/"))

                run_data = {
                    'fuzzer': fuzzer,
                    'eval_func': eval_func,
                    'workdir': workdir,
                    'mut_data': mut_data,
                }

                # Add this new run
                all_runs.append(run_data)

    return all_runs


def wait_for_seed_run(tasks, cores, all_runs):
    "Wait for a task to complete and process the result."
    assert len(tasks) > 0, "Trying to wait for a task but there are none."

    # wait for a task to complete
    completed_task = next(concurrent.futures.as_completed(tasks))
    # get the data associated with the task and remove the task from the list
    (task_type, core, run_data) = tasks[completed_task]
    del tasks[completed_task]

    # handle the task result
    if task_type == "seed":
        handle_seed_run_result(completed_task, run_data, all_runs)
    else:
        raise ValueError("Unknown task type.")

    # free the core for future use
    cores.release_core(core)


def print_seed_run_start_msg(run_data):
    prog = run_data['mut_data']['prog']
    fuzzer = run_data['fuzzer']
    print(f"> run:     {prog}:{fuzzer}")


def handle_seed_run_result(run_future, run_data, all_runs):
    workdir = run_data['workdir']
    try:
        # if there was no exception get the data
        run_result = run_future.result()
    except Exception:
        # if there was an exception record it
        trace = traceback.format_exc()
        print(trace)
        print(f"= run ###: Failed for {workdir}")
    else:
        errored_file = run_result.get('file_error')
        should_restart = run_result.get('restart')
        if errored_file:
            seed_dir = run_data['seed_dir']
            errored_file = seed_dir/errored_file
            print(f"Removing errored file: {errored_file}")
            try:
                errored_file.unlink()
            except FileNotFoundError:
                print("Already deleted!")
            should_restart = True
        if should_restart:
            print(f"Restarting run")
            shutil.rmtree(workdir)
            all_runs.append(run_data)

        print(f"= run    : {workdir}")


def seed_gathering_run(run_data, docker_image):
    global should_run
    start_time = time.time()
    # extract used values
    mut_data = run_data['mut_data']
    workdir = run_data['workdir']
    orig_bc = mut_data['orig_bc']
    compile_args = mut_data['compile_args']
    args = run_data['fuzzer_args']
    seeds = get_seed_dir(mut_data['prog'], run_data['fuzzer'])
    dictionary = mut_data['dict']
    core_to_use = run_data['used_core']

    workdir.mkdir(parents=True, exist_ok=True)

    # get access to the docker client to start the container
    docker_client = docker.from_env()
    # Start and run the container
    container = docker_client.containers.run(
        docker_image, # the image
        [
            "/home/user/eval.sh",
            str(compile_args),
            str(orig_bc),
            str(IN_DOCKER_WORKDIR/seeds),
            str(args)
        ], # the arguments
        environment={
            **({'DICT_PATH': str(Path(IN_DOCKER_WORKDIR)/dictionary)} if dictionary is not None else {}),
        },
        init=True,
        cpuset_cpus=str(core_to_use),
        auto_remove=True,
        volumes={
            str(HOST_TMP_PATH): {'bind': str(IN_DOCKER_WORKDIR)+"/tmp/", 'mode': 'ro'},
            "/dev/shm": {'bind': "/dev/shm", 'mode': 'rw'},
        },
        working_dir=str(workdir),
        mem_limit="10g",
        mem_swappiness=0,
        log_config=docker.types.LogConfig(type=docker.types.LogConfig.types.JSON,
            config={'max-size': '10m'}),
        detach=True
    )

    logs_queue = queue.Queue()
    DockerLogStreamer(logs_queue, container).start()

    fuzz_time = time.time()
    while time.time() < fuzz_time + TIMEOUT and should_run:
        # check if the process stopped, this should only happen in an
        # error case
        try:
            container.reload()
        except docker.errors.NotFound:
            # container is dead stop waiting
            break
        if container.status not in ["running", "created"]:
            break

        # Sleep so we only check sometimes and do not busy loop
        time.sleep(CHECK_INTERVAL)

    # Check if container is still running
    try:
        container.reload()
        if container.status in ["running", "created"]:

            # Send sigint to the process
            container.kill(2)

            # Wait up to 10 seconds then send sigkill
            container.stop()
    except docker.errors.NotFound:
        # container is dead just continue maybe it worked
        pass

    all_logs = []
    while True:
        line = logs_queue.get()
        if line == None:
            break
        all_logs.append(line)

    if should_run and time.time() - TIMEOUT < start_time:
        # The runtime is less than the timeout, something went wrong.
        raise RuntimeError(''.join(all_logs))

    return {
        'all_logs': all_logs,
    }


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def split_seed_dir(prog, num_splits, base_dir):
    split_size = 256*4
    seed_dir = SEED_BASE_DIR/prog
    assert seed_dir.is_dir(), f"Seed dir does not exist {seed_dir}"
    seed_files = [sf for sf in seed_dir.glob('**/*') if sf.is_file()]
    split_base_dir = base_dir/prog
    shutil.rmtree(split_base_dir, ignore_errors=True)

    split_dirs = []
    for ii, chunk_files in enumerate(chunks(seed_files, split_size)):
        target_dir = split_base_dir/str(ii)
        target_dir.mkdir(parents=True)
        for ff in chunk_files:
            shutil.copy2(ff, target_dir)
        split_dirs.append(target_dir)
    print(f"Seed files have been split into {len(split_dirs)} dirs, each with ~{split_size} seeds.")

    return split_dirs


def get_seed_checking_runs(fuzzers, progs, num_splits, base_dir):
    print(fuzzers, progs)
    all_split_dirs = []
    all_runs = []

    for prog in progs:
        try:
            prog_info = PROGRAMS[prog]
        except Exception as err:
            print(err)
            print(f"Prog: {prog} is not known, known progs are: {PROGRAMS.keys()}")
            sys.exit(1)

        split_dirs = split_seed_dir(prog, num_splits, base_dir)
        print(f"num split_dirs {len(split_dirs)}")

        for fuzzer in fuzzers:
            try:
                eval_func = FUZZERS[fuzzer]
            except Exception as err:
                print(err)
                print(f"Fuzzer: {fuzzer} is not known, known fuzzers are: {FUZZERS.keys()}")
                sys.exit(1)

            # Gather all data to start a seed checking run

            # Compile arguments
            compile_args = build_compile_args(prog_info['bc_compile_args'] + prog_info['bin_compile_args'], IN_DOCKER_WORKDIR)
            # Arguments on how to execute the binary
            args = prog_info['args']

            mut_data = {
                'orig_bc': Path(IN_DOCKER_WORKDIR)/prog_info['orig_bc'],
                'compile_args': compile_args,
                'is_cpp': prog_info['is_cpp'],
                'args': args,
                'prog': prog,
                'dict': prog_info['dict'],
            }

            for split_dir in split_dirs:

                workdir = Path(tempfile.mkdtemp(prefix=f"{prog}__{fuzzer}__", dir=base_dir))

                run_data = {
                    'fuzzer': fuzzer,
                    'eval_func': eval_func,
                    'workdir': workdir,
                    'seed_dir': split_dir,
                    'mut_data': mut_data,
                }

                # Add this new run
                all_runs.append(run_data)

        all_split_dirs.append((prog, split_dirs))

    return all_runs, all_split_dirs


def seed_checking_run(run_data, docker_image):
    global should_run
    start_time = time.time()
    # extract used values
    mut_data = run_data['mut_data']
    workdir = run_data['workdir']
    orig_bc = mut_data['orig_bc']
    compile_args = mut_data['compile_args']
    args = run_data['fuzzer_args']
    seeds = run_data['seed_dir']
    dictionary = mut_data['dict']
    core_to_use = run_data['used_core']

    workdir.mkdir(parents=True, exist_ok=True)

    # get access to the docker client to start the container
    docker_client = docker.from_env()
    # Start and run the container
    container = docker_client.containers.run(
        docker_image, # the image
        [
            "/home/user/eval.sh",
            str(compile_args),
            str(orig_bc),
            str(IN_DOCKER_WORKDIR/seeds),
            str(args)
        ], # the arguments
        environment={
            **({'DICT_PATH': str(Path(IN_DOCKER_WORKDIR)/dictionary)} if dictionary is not None else {}),
        },
        init=True,
        cpuset_cpus=str(core_to_use),
        auto_remove=True,
        volumes={
            str(HOST_TMP_PATH): {'bind': str(IN_DOCKER_WORKDIR)+"/tmp/", 'mode': 'ro'},
            "/dev/shm": {'bind': "/dev/shm", 'mode': 'rw'},
        },
        working_dir=str(workdir),
        mem_limit="10g",
        mem_swappiness=0,
        log_config=docker.types.LogConfig(type=docker.types.LogConfig.types.JSON,
            config={'max-size': '10m'}),
        detach=True
    )

    logs_queue = queue.Queue()
    DockerLogStreamer(logs_queue, container).start()

    fuzz_time = time.time()
    while time.time() < fuzz_time + TIMEOUT and should_run:
        # check if the process stopped, this should only happen in an
        # error case
        try:
            container.reload()
        except docker.errors.NotFound:
            # container is dead stop waiting
            break
        if container.status not in ["running", "created"]:
            break

        # Sleep so we only check sometimes and do not busy loop
        time.sleep(CHECK_INTERVAL)

    # Check if container is still running
    try:
        container.reload()
        if container.status in ["running", "created"]:

            # Send sigint to the process
            container.kill(2)

            # Wait up to 10 seconds then send sigkill
            container.stop()
    except docker.errors.NotFound:
        # container is dead just continue maybe it worked
        pass

    all_logs = []
    while True:
        line = logs_queue.get()
        if line == None:
            break
        all_logs.append(line)

    if should_run and time.time() - TIMEOUT < start_time:
        # The runtime is less than the timeout, something went wrong.
        for line in all_logs:
            if "PROGRAM ABORT" in line:
                matched = re.search("orig:(.*?)[,']", line)
                if matched:
                    errored_file = matched.group(1)
                    return {
                        'all_logs': all_logs,
                        'file_error': errored_file
                    }
        raise RuntimeError(''.join(all_logs))

    return {
        'all_logs': all_logs,
    }


def check_seeds(progs, fuzzers):
    global should_run

    # prepare environment
    base_shm_dir = Path("/dev/shm/mutator_check_seeds")
    shutil.rmtree(base_shm_dir, ignore_errors=True, onerror=lambda *x: print(x))
    base_shm_dir.mkdir(parents=True, exist_ok=True)

    build_docker_images(fuzzers, progs)

    # Keep a list of which cores can be used
    cores = CpuCores(NUM_CPUS)

    # for each mutation and for each fuzzer do a run
    with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_CPUS) as executor:
        # keep a list of all tasks
        tasks = {}
        # Get each seed checking run
        all_runs, all_split_dirs = get_seed_checking_runs(fuzzers, progs, NUM_CPUS, base_shm_dir)

        while True:
            # Check if a core is free
            core = cores.try_reserve_core()

            if should_run and core is not None and len(all_runs) > 0:
                # A core is free and there are still runs to do and we want to continue running, start a new task.

                run_data = all_runs.pop()
                run_data['used_core'] = core

                print_seed_run_start_msg(run_data)

                tasks[executor.submit(run_data['eval_func'], run_data, seed_checking_run)] = ("seed", core, run_data)

            else:
                # Wait for a task to complete.
                if len(tasks) == 0:
                    # all tasks done exit loop
                    break
                print(f"Waiting for one of {len(tasks)} tasks.")
                wait_for_seed_run(tasks, cores, all_runs)

        assert len(all_runs) == 0 or should_run is False

    print("Moving seeds back to where they belong...")
    for prog, split_dirs in all_split_dirs:
        seed_dir = SEED_BASE_DIR/prog
        # backup currently active seeds as they will be replaces
        seed_backup_dir = Path('tmp/seed_backup')/prog
        print(f"Backing up seed files for prog: {prog} from {seed_dir} to {seed_backup_dir}.")
        shutil.rmtree(seed_backup_dir, ignore_errors=True)
        seed_backup_dir.parent.mkdir(exist_ok=True, parents=True)
        seed_dir.rename(seed_backup_dir)

        # copy the checked seeds into active seeds
        seed_dir.mkdir(parents=True)
        for sd in split_dirs:
            for ff in sd.glob("*"):
                if ff.is_dir():
                    print("Did not expect any directories in the seed dirs, something is wrong.")
                shutil.copy2(ff, seed_dir)

    print("seed checking done :)")


BLOCK_SIZE = 1024*4

# Based on: https://stackoverflow.com/a/44873382
def hash_file(file_path):
    h = hashlib.sha512()
    b  = bytearray(BLOCK_SIZE)
    mv = memoryview(b)
    with open(file_path, 'rb', buffering=0) as f:
        for n in iter(lambda : f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()


def collect_honggfuzz(path):
    found = path.glob("output/*")
    return list(found)


def collect_afl(path):
    found = [pp for pp in path.glob("**/queue/*") if pp.name != '.state']
    return list(found)


SEED_HANDLERS = {
        'honggfuzz': collect_honggfuzz,
        'fairfuzz': collect_afl,
        'aflpp_rec': collect_afl,
        'aflpp_det': collect_afl,
        'afl': collect_afl,
}


def gather_seeds(progs, fuzzers, num_repeats, destination_dir):
    global should_run

    destination_dir = Path(destination_dir)
    destination_dir.mkdir(parents=True, exist_ok=True)

    # prepare environment
    base_shm_dir = Path("/dev/shm/mutator_seed_gathering")
    shutil.rmtree(base_shm_dir, ignore_errors=True)
    base_shm_dir.mkdir(parents=True, exist_ok=True)

    build_docker_images(fuzzers, progs)

    # Keep a list of which cores can be used
    cores = CpuCores(NUM_CPUS)

    # for each mutation and for each fuzzer do a run
    with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_CPUS) as executor:
        # keep a list of all tasks
        tasks = {}
        # Get each seed gathering runs
        all_runs = get_seed_gathering_runs(fuzzers, progs, num_repeats)

        while True:
            # Check if a core is free
            core = cores.try_reserve_core()

            if should_run and core is not None and len(all_runs) > 0:
                # A core is free and there are still runs to do and we want to continue running, start a new task.

                run_data = all_runs.pop()
                run_data['used_core'] = core

                print_seed_run_start_msg(run_data)

                tasks[executor.submit(run_data['eval_func'], run_data, seed_gathering_run)] = ("seed", core, run_data)

            else:
                # Wait for a task to complete.
                if len(tasks) == 0:
                    # all tasks done exit loop
                    break
                print(f"Waiting for one of {len(tasks)} tasks.")
                wait_for_seed_run(tasks, cores, all_runs)

        assert len(all_runs) == 0 or should_run is False

    print("Copying seeds to target dir...")
    for seed_source in base_shm_dir.glob("*"):
        if not seed_source.is_dir():
            continue

        seed_base_dir_parts = str(seed_source.name).split('__')
        prog = seed_base_dir_parts[0]
        fuzzer = seed_base_dir_parts[1]
        prog_dir = destination_dir/prog
        prog_dir.mkdir(parents=True, exist_ok=True)

        collector = SEED_HANDLERS[fuzzer]

        found_seeds = collector(seed_source)
        print(prog, fuzzer, len(found_seeds))
        for fs in found_seeds:
            file_hash = hash_file(fs)
            dest_path = prog_dir/file_hash
            shutil.copyfile(fs, dest_path)

    print("seed gathering done :)")


def import_seeds(source_dir):
    source_dir = Path(source_dir)
    for seed_source in source_dir.glob("*"):
        print()
        if not seed_source.is_dir():
            print(f"Warning: Expected only directories but this path is not a directory: {seed_source}")
            continue

        if seed_source.name not in PROGRAMS:
            print(f"Warning: Directory does not match any program name, files in this directory will not be imported: {seed_source}")
            continue

        seed_files = [sf for sf in seed_source.glob("**/*") if sf.is_file()]
        dest_dir = SEED_BASE_DIR/seed_source.name
        dest_dir.mkdir(parents=True, exist_ok=True)

        print(f"Copying seed files from {seed_source} to {dest_dir} ...")

        num_already_exist = 0
        num_copied = 0
        num_too_big = 0

        for sf in seed_files:
            file_hash = hash_file(sf)
            dest_path = dest_dir/file_hash
            if dest_path.is_file():
                num_already_exist += 1
                continue
            if sf.stat().st_size >= 1_000_000:
                num_too_big += 1
                continue
            shutil.copyfile(sf, dest_path)
            num_copied += 1

        print(f"Copied {num_copied} and ignored: {num_already_exist} (same hash) + {num_too_big} (size too large).")


def parse_afl_paths(paths):
    if paths is None:
        return []
    paths = paths.split('/////')
    paths_elements = []
    for path in paths:
        elements = {}
        split_path = path.split(',')
        elements['path'] = split_path[0]
        for elem in split_path[1:]:
            parts = elem.split(":")
            if len(parts) == 2:
                elements[parts[0]] = parts[1]
            else:
                raise ValueError("Unexpected afl path format: ", path)
        paths_elements.append(elements)
    return paths_elements

TOTAL_FUZZER = 'total'
ALL_PROG = 'all'

def header():
    import altair as alt
    alt.data_transformers.disable_max_rows()

    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Mutation testing eval</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.0/jquery.min.js"></script>
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>

        <script src="https://cdn.jsdelivr.net/npm/vega@{vega_version}"></script>
        <script src="https://cdn.jsdelivr.net/npm/vega-lite@{vegalite_version}"></script>
        <script src="https://cdn.jsdelivr.net/npm/vega-embed@{vegaembed_version}"></script>
    <style>
    body {{
        margin-left:10px
    }}
    table {{
        border-collapse: collapse;
    }}
    th, td {{
        text-align: left;
        padding: 7px;
        border: none;
    }}
        tr:nth-child(even){{background-color: lightgray}}
    th {{
    }}
    </style>
    </head>
    <body>\n""".format(
        vega_version=alt.VEGA_VERSION,
        vegalite_version=alt.VEGALITE_VERSION,
        vegaembed_version=alt.VEGAEMBED_VERSION,
    )

def error_stats(con):
    import pandas as pd

    crashes = pd.read_sql_query("""
        select *
        from crashed_runs_summary
    """, con)
    res = ""
    if len(crashes) > 0:
        print("Crashed runs:")
        print(crashes)
        res += "<h2>Crashes</h2>"
        res += crashes.to_html()

    crashes = pd.read_sql_query("""
        select *
        from base_bin_crashes
    """, con)
    res = ""
    if len(crashes) > 0:
        print("Base bin crashes:")
        print(crashes)
        res += "<h2>Base Bin Crashes</h2>"
        res += crashes.to_html()

    crashes = pd.read_sql_query("""
        select *
        from not_covered_but_found
    """, con)
    res = ""
    if len(crashes) > 0:
        print("Not Covered but Found:")
        print(crashes)
        res += "<h2>Not Covered but Found</h2>"
        res += crashes.to_html()

    crashes = pd.read_sql_query("""
        select *
        from covered_by_seed_but_not_fuzzer
    """, con)
    res = ""
    if len(crashes) > 0:
        print("Covered By Seed but Not Fuzzer:")
        print(crashes)
        res += "<h2>Covered By Seed but Not Fuzzer</h2>"
        res += crashes.to_html()
    return res

def fuzzer_stats(con):
    import pandas as pd
    stats = pd.read_sql_query("SELECT * from run_results_by_fuzzer", con)
    print(stats)
    # print(stats[['fuzzer', 'total', 'done', 'found', 'f_by_f', 'avg_run_min', 'cpu_days']].to_latex())
    res = "<h2>Fuzzer Stats</h2>"
    res += stats.to_html()
    return res

def mut_stats(con):
    import pandas as pd
    stats = pd.read_sql_query("SELECT * from run_results_by_mut_type", con)
    res = "<h2>Mutation Stats</h2>"
    res += stats.to_html()
    return res

def prog_stats(con):
    import pandas as pd
    stats = pd.read_sql_query("SELECT * from run_results_by_prog", con)
    res = "<h2>Program Stats</h2>"
    res += stats.to_html()
    return res

def aflpp_stats(con):
    import pandas as pd
    stats = pd.read_sql_query("SELECT * from aflpp_runtime_stats", con)
    res = "<h2>AFL style fuzzers -- Stats</h2>"
    res += stats.to_html()
    return res

def plot(plot_dir, title, mut_type, data, num_mutations, absolute):
    import inspect
    import types
    from typing import cast
    import altair as alt
    alt.data_transformers.disable_max_rows()
    all_fuzzers = set(run.fuzzer for run in data.itertuples())
    func_name = cast(types.FrameType, inspect.currentframe()).f_code.co_name
    selection = alt.selection_multi(fields=['fuzzer', 'prog'], bind='legend',
        init=[{'fuzzer': fuzzer, 'prog': ALL_PROG} for fuzzer in all_fuzzers])
    color = alt.condition(selection,
                      alt.Color('fuzzer:O', legend=None),
                      alt.value('lightgray'))
    base = alt.Chart(data)

    if absolute:
        plot = base.mark_line(
            interpolate='step-after',
        ).encode(
            alt.Y('value', title="Killed Mutants"),
            x=alt.X('time', title="Time (Minutes)"), #, scale=alt.Scale(type='symlog')),
            color='fuzzer',
            tooltip=['time', 'confirmed', 'value', 'covered', 'total', 'fuzzer', 'prog'],
        )
        plot = plot.mark_point(size=5, opacity=1, tooltip=alt.TooltipContent("encoding")) + plot
        #  plot2 = base.mark_line(strokeDash=[4,2]).encode(
        #      y=alt.Y('total', title="Killed Mutants"),
        #      x=alt.X('time', title="Time (Minutes)"), #, scale=alt.Scale(type='symlog')),
        #      color='fuzzer',
        #      tooltip=['time', 'confirmed', 'value', 'covered', 'total', 'fuzzer', 'prog'])
        #  plot = plot + plot2
    else:
        plot = base.mark_line(
            interpolate='step-after',
        ).encode(
            x=alt.X('time', title="Time (Minutes)"), #, scale=alt.Scale(type='symlog')),
            y=alt.Y('value', title="Percentage Killed Mutants"),
            color='fuzzer',
            tooltip=['time', 'confirmed', 'value', 'covered', 'total', 'fuzzer', 'prog'])
        plot = plot.mark_point(size=5, opacity=1, tooltip=alt.TooltipContent("encoding")) + plot
    plot = plot.properties(
        title=title,
        width=600,
        height=400,
    )

    plot = plot.add_selection(
        alt.selection_interval(bind='scales', encodings=['x'])
    ).transform_filter(
        selection
    )

    counts = [f"{prog}: {val[0]} / {val[1]}" for prog, val in num_mutations.items()]

    all_selection = alt.Chart(data).mark_rect().encode(
        x=alt.X('prog', axis=alt.Axis(orient='bottom')),
        y=alt.Y('fuzzer', axis=alt.Axis(orient='right')),
        color=color
    ).properties(
        title=alt.TitleParams(
            ['', '#Analyzed Mutations:'] + counts,
            baseline='top',
            orient='bottom',
            anchor='end',
            fontWeight='normal',
            fontSize=10
        )
    )

    plot = (plot | all_selection).add_selection(
        selection
    )
    slug_title = title.replace(" ", "").replace(":", "")
    res = f'<div id="{slug_title}{func_name}{mut_type}"></div>'
    res += '''<script type="text/javascript">
                vegaEmbed('#{slug_title}{func_name}{mut_id}', {spec1}).catch(console.error);
              </script>'''.format(slug_title=slug_title, func_name=func_name, mut_id=mut_type,
                                  spec1=plot.to_json(indent=None))
    if plot_dir is not None:
        plot_path_svg = plot_dir.joinpath(f"{slug_title}.svg")
        plot_path_pdf = plot_path_svg.with_suffix(".pdf")
        plot.save(f"{plot_path_svg}")
        proc = subprocess.run(f'cat {plot_path_svg} | inkscape --pipe --export-filename="{plot_path_pdf}"',
                shell=True, capture_output=True)
        if proc.returncode != 0:
            print("Error during conversion from svg to pdf:")
            print(proc.stdout.decode())
            print(proc.stderr.decode())
    return res

def split_vals(val):
    if val is None:
        return []
    return [float(v) for v in val.split("/////")]

def gather_plot_data(runs, run_results):
    from collections import defaultdict
    import pandas as pd

    if len(run_results) == 0:
        return None

    totals_set = defaultdict(set)
    max_time = 0
    all_progs = set(run.prog for run in runs.itertuples())
    all_fuzzers = set(run.fuzzer for run in runs.itertuples())

    absolute_num_mutations = defaultdict(lambda: [0, 0])

    for run in runs.itertuples():
        if run.fuzzer != list(all_fuzzers)[0]:
            continue
        absolute_num_mutations[run.prog][1] += run.total
        absolute_num_mutations[ALL_PROG][1] += run.total

    cnt_prog_runs = defaultdict(set)
    cnt_fuzzer_runs = defaultdict(set)
    cnt_fuzzer_prog_runs = defaultdict(set)
    cnt_runs = set()

    for event in run_results.itertuples():
        cnt_prog_runs[event.prog].add(event.mut_id)
        cnt_fuzzer_runs[event.fuzzer].add((event.prog, event.mut_id))
        cnt_fuzzer_prog_runs[(event.fuzzer, event.prog)].add(event.mut_id)
        cnt_runs.add((event.prog, event.mut_id))

    total_runs = defaultdict(lambda: 0)
    for prog, max_total in cnt_prog_runs.items():
        total_runs[(TOTAL_FUZZER, prog)] = len(max_total)
        absolute_num_mutations[prog][0] = len(max_total)
    for fuzzer, max_total in cnt_fuzzer_runs.items():
        total_runs[(fuzzer, ALL_PROG)] = len(max_total)
    for (fuzzer, prog), max_total in cnt_fuzzer_prog_runs.items():
        total_runs[(fuzzer, prog)] = len(max_total)
    total_runs[(TOTAL_FUZZER, ALL_PROG)] = len(cnt_runs)
    absolute_num_mutations[ALL_PROG][0] = len(cnt_runs)

    data = defaultdict(list)
    unique_events = []

    for event in run_results.itertuples():
        import math
        if event.covered_file_seen is None or math.isnan(event.covered_file_seen):
            continue
        unique_events.append({
            'fuzzer': event.fuzzer,
            'prog': event.prog,
            'id': event.mut_id,
            'type': 'covered',
            'stage': 'initial' if event.covered_by_seed else event.stage,
            'time': event.covered_file_seen,
        })

    for event in run_results.itertuples():
        if event.confirmed != 1:
            continue
        unique_events.append({
            'fuzzer': event.fuzzer,
            'prog': event.prog,
            'id': event.mut_id,
            'type': 'confirmed',
            'stage': event.stage,
            'time': event.time_found,
        })

    counter = defaultdict(lambda: {
        'covered': 0,
        'confirmed': 0,
    })

    def inc_counter(fuzzer, prog, id, counter_type):
        counter[(fuzzer, prog)][counter_type] += 1
        counter[(fuzzer, ALL_PROG)][counter_type] += 1
        if id not in totals_set[(prog, counter_type)]:
            totals_set[(prog, counter_type)].add(id)
            counter[(TOTAL_FUZZER, prog)][counter_type] += 1
            counter[(TOTAL_FUZZER, ALL_PROG)][counter_type] += 1
            return True
        return False

    def add_datapoint(fuzzer, prog, time):
        counts = counter[(fuzzer, prog)]
        total = total_runs[(fuzzer, prog)]
        try:
            total_percentage = (counts['confirmed'] / total) * 100
        except ZeroDivisionError:
            total_percentage = 0

        try:
            confirmed_percentage = (counts['confirmed'] / counts['covered']) * 100
        except ZeroDivisionError:
            confirmed_percentage = 0

        try:
            absolute = counts['confirmed']
        except ZeroDivisionError:
            absolute = 0

        for name, val in [
                ('total', total_percentage),
                ('covered', confirmed_percentage),
                ('absolute', absolute),
        ]:
            data[name].append({
                'fuzzer': fuzzer,
                'prog': prog,
                'time': time,
                'confirmed': counts['confirmed'],
                'covered': counts['covered'],
                'total': total,
                'value': val,
            })

    for event in unique_events:
        if event['stage'] == 'initial':
            inc_counter(event['fuzzer'], event['prog'], event['id'], event['type'])

    # add initial points
    for run in runs.itertuples():
        add_datapoint(run.fuzzer, run.prog, 0)
    for fuzzer in all_fuzzers:
        add_datapoint(fuzzer, ALL_PROG, 0)
    for prog in all_progs:
        add_datapoint(TOTAL_FUZZER, prog, 0)
    add_datapoint(TOTAL_FUZZER, ALL_PROG, 0)

    # add the data points
    for event in sorted(unique_events, key=lambda x: x['time']):
        if event['stage'] == 'initial':
            continue

        if event['time'] > max_time:
            max_time = event['time']

        total_inc = inc_counter(event['fuzzer'], event['prog'], event['id'], event['type'])
        add_datapoint(event['fuzzer'], event['prog'], event['time'])
        add_datapoint(event['fuzzer'], ALL_PROG, event['time'])
        if total_inc:
            add_datapoint(TOTAL_FUZZER, event['prog'], event['time'])
            add_datapoint(TOTAL_FUZZER, ALL_PROG, event['time'])

    # add final points
    for fuzzer, prog in counter.keys():
        add_datapoint(fuzzer, prog, max_time)

    return {
        'num_mutations': absolute_num_mutations,
        'total': pd.DataFrame(data['total']),
        'covered': pd.DataFrame(data['covered']),
        'absolute': pd.DataFrame(data['absolute']),
    }

def matrix_unique_finds(unique_finds):
    from collections import defaultdict
    import pandas as pd
    import numpy as np

    matrix = defaultdict(dict)
    for row in unique_finds.itertuples():
        matrix[row.other_fuzzer][row.fuzzer] = row.finds

    matrix = pd.DataFrame(matrix).fillna(-1).astype(int).replace({-1: ""})
    matrix = matrix.reindex(sorted(matrix.columns), axis=0)
    matrix = matrix.reindex(sorted(matrix.columns), axis=1)

    return matrix

def create_mut_type_plot(plot_dir, mut_type, runs, run_results, unique_finds, mutation_info):
    plot_data = gather_plot_data(runs, run_results)

    # print(mutation_info)
    pattern_name = mutation_info['pattern_name'].iat[0]
    pattern_class = mutation_info['pattern_class'].iat[0]
    description = mutation_info['description'].iat[0]
    procedure = mutation_info['procedure'].iat[0]

    res = f'<h3>Mutation {mut_type}: {pattern_name}</h3>'
    res += f'<p>Class: {pattern_class}</p>'
    res += f'<p>Description: {description}</p>'
    res += f'<p>Procedure: {procedure}</p>'
    res += '<h4>Overview</h4>'
    res += runs.to_html()
    if plot_data is not None:
        res += plot(None, f"Killed Covered Mutants of type: {mut_type}", mut_type, plot_data['covered'], plot_data['num_mutations'], False)
        res += plot(None, f"Killed Mutants of type: {mut_type}", mut_type, plot_data['total'], plot_data['num_mutations'], False)
        res += plot(None, f"Absolute Killed Mutants of type: {mut_type}", mut_type, plot_data['absolute'], plot_data['num_mutations'], True)
    res += '<h4>Unique Finds</h4>'
    res += 'Left finds what upper does not.'
    res += matrix_unique_finds(unique_finds).to_html(na_rep="")
    return res

def footer():
    return """
    </body>
    </html>
    """

def generate_plots(db_path):
    import pandas as pd

    plot_dir = Path("plots").joinpath(Path(db_path).stem)
    # shutil.rmtree(plot_dir)
    plot_dir.mkdir(parents=True, exist_ok=True)

    con = sqlite3.connect(db_path)
    con.isolation_level = None
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    with open("eval.sql", "rt") as f:
        cur.executescript(f.read())

    res = header()
    print("crashes")
    res += error_stats(con)
    print("fuzzer stats")
    res += fuzzer_stats(con)
    print("mut stats")
    res += mut_stats(con)
    print("prog stats")
    res += prog_stats(con)
    print("afl stats")
    res += aflpp_stats(con)

    print("select mut_types")
    mut_types = pd.read_sql_query("SELECT * from mut_types", con)
    print("select runs")
    runs = pd.read_sql_query("select * from run_results_by_mut_type_and_fuzzer", con)
    print("select run_results")
    run_results = pd.read_sql_query("select * from run_results", con)
    print("select unique_finds")
    unique_finds = pd.read_sql_query("select * from unique_finds", con)
    #  print("select unique_finds_overall")
    #  unique_finds_overall = pd.read_sql_query("select * from unique_finds_overall", con)
    print("select mutation_types")
    mutation_info = pd.read_sql_query("select * from mutation_types", con)

    res += "<h2>Plots</h2>"
    res += "<h3>Overall Plots</h3>"
    print("overall")
    total_plot_data = gather_plot_data(runs, run_results)
    if total_plot_data is not None:
        res += plot(plot_dir, f"Killed Covered Mutants Overall", "overall", total_plot_data['covered'], total_plot_data['num_mutations'], False)
        res += plot(plot_dir, f"Killed Mutants Overall", "overall", total_plot_data['total'], total_plot_data['num_mutations'], False)
        res += plot(plot_dir, f"Absolute Killed Mutants Overall", "overall", total_plot_data['absolute'], total_plot_data['num_mutations'], True)
    #  res += '<h4>Unique Finds</h4>'
    #  res += 'Left finds what upper does not.'
    #  res += matrix_unique_finds(unique_finds_overall).to_html(na_rep="")

    for mut_type in mut_types['mut_type']:
        print(mut_type)
        res += create_mut_type_plot(plot_dir, mut_type,
            runs[runs.mut_type == mut_type],
            run_results[run_results.mut_type == mut_type],
            unique_finds[unique_finds.mut_type == mut_type],
            mutation_info[mutation_info.mut_type == mut_type],
        )
    res += footer()

    out_path = Path(db_path).with_suffix(".html").resolve()
    print(f"Writing plots to: {out_path}")
    with open(out_path, 'w') as f:
        f.write(res)
    print(f"Open: file://{out_path}")


def merge_dbs(out_path, in_paths):
    assert len(in_paths) >= 2, f"Need at least two dbs to merge but got: {in_paths}"
    print(out_path, in_paths)

    out_db_path = Path(out_path)
    if out_db_path.is_file():
        print(f"Removing file: {out_db_path}")
        out_db_path.unlink()

    # copy the first database
    proc = subprocess.run(f'sqlite3 {in_paths[0]} ".dump" | sqlite3 {out_path}',
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode != 0:
        print("Failed to copy the first db.", proc)
        sys.exit(1)

    # TODO check that the other database come from the same commit and git state?

    # copy all data
    for in_db in in_paths[1:]:
        inserts = "\n".join((
                f"insert into {table} select * from to_merge.{table};"
                for table in ['execution', 'all_runs', 'mutations', 'progs', 'executed_runs', 'executed_seeds', 'aflpp_runs',
                'seed_crashing_inputs', 'crashing_inputs', 'crashing_mutation_preparation', 'run_crashed']))
        command = f'''sqlite3 {out_db_path} "
attach '{in_db}' as to_merge;
BEGIN;
{inserts}
COMMIT;
detach to_merge;"'''
        print(command)
        proc = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if proc.returncode != 0:
            print("Failed to copy the first db.", proc)
            sys.exit(1)


def update_signal_list(signal_list, to_delete: Set[int]):
    """
    Takes a list of signal tuples and updates the set s.t. all
    :param signal_list:
    :param to_delete:
    :return:
    """
    result = list()
    for val in signal_list:
        new_set = val[1] - to_delete
        # do a diff on the value and then check if there are still unseen signals, if so put the value
        # with the updated set back into the return list
        if new_set:
            result.append((val[0], new_set))
    return result


def eval_seed(active_containers, counter, seed, mutator_tmp_path, SIGNAL_FOLDER_NAME, prog_info, mutator_home, prog_path):
    global worker_container
    if worker_container is None:
        worker_container = start_mutation_container(
                None, {'environment': {'TRIGGERED_FOLDER': str(SIGNAL_FOLDER_NAME)}}).__enter__()
        worker_id = id(multiprocessing.current_process())
        active_containers[worker_id] = worker_container.name

    mutation_container_name = worker_container.name

    seed_abs = mutator_tmp_path/seed
    workdir = Path(f"/tmp/seed_abs/{counter}/")
    signal_folder = workdir/SIGNAL_FOLDER_NAME

    run_exec_in_container(mutation_container_name, True,
        ['mkdir', '-p', str(signal_folder)])
    args = prog_info['args'].replace("<WORK>/", str(mutator_home)).replace("@@", str(seed_abs))
    args = " ".join(shlex.split(args))
    run_exec_in_container(mutation_container_name, True,
        ['bash', '-c', f"TRIGGERED_FOLDER={signal_folder} {prog_path} {args}"],
        exec_args=["-w", str(workdir)])
    found_mutations = run_exec_in_container(mutation_container_name, True,
        ['find', str(workdir/signal_folder), '-printf', '%f\n'])
    found_mutations = set((
        int(mut_id)
        for mut_id
        in found_mutations['out'].strip().splitlines()
        if mut_id.isdecimal()
    ))
    run_exec_in_container(mutation_container_name, True,
        ['rm', '-r', workdir])
    return seed, found_mutations


def seed_minimization_run(run_data, docker_image):
    global should_run
    start_time = time.time()
    # extract used values
    mut_data = run_data['mut_data']
    workdir = run_data['workdir']
    orig_bc = mut_data['orig_bc']
    compile_args = mut_data['compile_args']
    args = run_data['fuzzer_args']
    seeds_in = run_data['seed_in_dir']
    seeds_out = run_data['seed_out_dir']
    dictionary = mut_data['dict']

    workdir.mkdir(parents=True, exist_ok=True)

    # get access to the docker client to start the container
    docker_client = docker.from_env()
    # Start and run the container
    container = docker_client.containers.run(
        docker_image, # the image
        [
            "/home/user/minimize.sh",
            str(compile_args),
            str(orig_bc),
            str(seeds_in),
            str(seeds_out),
            str(args)
        ], # the arguments
        environment={
            **({'DICT_PATH': str(Path(IN_DOCKER_WORKDIR)/dictionary)} if dictionary is not None else {}),
        },
        init=True,
        auto_remove=True,
        volumes={
            str(HOST_TMP_PATH): {'bind': str(IN_DOCKER_WORKDIR)+"/tmp/", 'mode': 'ro'},
            "/dev/shm": {'bind': "/dev/shm", 'mode': 'rw'},
        },
        working_dir=str(workdir),
        mem_swappiness=0,
        log_config=docker.types.LogConfig(type=docker.types.LogConfig.types.JSON,
            config={'max-size': '10m'}),
        detach=True
    )

    logs_queue = queue.Queue()
    DockerLogStreamer(logs_queue, container).start()

    while should_run:
        # check if the process stopped, this should only happen in an
        # error case
        try:
            container.reload()
        except docker.errors.NotFound:
            # container is dead stop waiting
            break
        if container.status not in ["running", "created"]:
            break

        # Sleep so we only check sometimes and do not busy loop
        time.sleep(CHECK_INTERVAL)

    # Check if container is still running
    try:
        container.reload()
        if container.status in ["running", "created"]:

            # Send sigint to the process
            container.kill(2)

            # Wait up to 10 seconds then send sigkill
            container.stop()
    except docker.errors.NotFound:
        # container is dead just continue maybe it worked
        pass

    all_logs = []
    while True:
        line = logs_queue.get()
        if line == None:
            break
        all_logs.append(line)

    return {
        'all_logs': all_logs,
    }


def minimize_seeds(seed_path_base, res_path_base, fuzzers, progs):
    global should_run
    seed_path_base = Path(seed_path_base)
    res_path_base = Path(res_path_base)

    if res_path_base.exists():
        print(f"Result path already exists, to avoid data loss, it is required that this path does not exist: {res_path_base}")
        sys.exit(1)

    # prepare environment
    base_shm_dir = Path("/dev/shm/minimize_seeds")
    shutil.rmtree(base_shm_dir, ignore_errors=True, onerror=lambda *x: print(x))
    base_shm_dir.mkdir(parents=True, exist_ok=True)

    build_docker_images(fuzzers, progs)

    for prog, fuzzer in product(progs, fuzzers):
        if not should_run:
            break

        # Gather all data to start a seed minimization run
        try:
            prog_info = PROGRAMS[prog]
        except Exception as err:
            print(err)
            print(f"Prog: {prog} is not known, known progs are: {PROGRAMS.keys()}")
            sys.exit(1)
        try:
            eval_func = FUZZERS[fuzzer]
        except Exception as err:
            print(err)
            print(f"Fuzzer: {fuzzer} is not known, known fuzzers are: {FUZZERS.keys()}")
            sys.exit(1)

        prog_seed_path = seed_path_base/prog
        if not prog_seed_path.is_dir():
            print(f"There is no seed directory for prog: {prog}, seed files need to be here: {prog_seed_path}")
            sys.exit(1)
        prog_fuzzer_res_path = res_path_base/prog/fuzzer
        prog_fuzzer_res_path.mkdir(parents=True)

        active_dir = base_shm_dir/f"{prog}__{fuzzer}"
        active_dir.mkdir()

        # copy seed_path dir into a tmp dir to make sure to not disturb the original seeds
        seed_in_tmp_dir = active_dir/"seeds_in"
        seed_in_tmp_dir.mkdir()
        seed_out_tmp_dir = active_dir/"seeds_out"
        seed_out_tmp_dir.mkdir()
        for ff in prog_seed_path.glob("*"):
            if ff.is_dir():
                print("Did not expect any directories in the seed path, something is wrong.")
            shutil.copy2(ff, seed_in_tmp_dir)

        # Compile arguments
        compile_args = build_compile_args(prog_info['bc_compile_args'] + prog_info['bin_compile_args'], IN_DOCKER_WORKDIR)
        # Arguments on how to execute the binary
        args = prog_info['args']

        mut_data = {
            'orig_bc': Path(IN_DOCKER_WORKDIR)/prog_info['orig_bc'],
            'compile_args': compile_args,
            'is_cpp': prog_info['is_cpp'],
            'args': args,
            'prog': prog,
            'dict': prog_info['dict'],
        }

        workdir = active_dir/"workdir"
        workdir.mkdir()

        run_data = {
            'fuzzer': fuzzer,
            'eval_func': eval_func,
            'workdir': workdir,
            'seed_in_dir': seed_in_tmp_dir,
            'seed_out_dir': seed_out_tmp_dir,
            'mut_data': mut_data,
        }

        # start the fuzzer in seed minimization mode on the prog
        eval_func(run_data, seed_minimization_run)

        print(f"copying results to: {seed_out_tmp_dir}")

        # move minimized seeds to result path
        for ff in seed_out_tmp_dir.glob("*"):
            if ff.is_dir():
                print("Did not expect any directories in the seed path, something is wrong.")
            shutil.copy2(ff, prog_fuzzer_res_path)

        # clean up tmp dirs (everything should have happened inside the active dir)
        # shutil.rmtree(active_dir)

    print("seed minimization done :)")


def main():
    import sys
    import argparse

    # set signal handler for keyboard interrupt
    signal.signal(signal.SIGINT, sigint_handler)

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='cmd', help="These are the possible actions for the eval, "
            "see their individual descriptions.")

    # CMD: eval 
    parser_eval = subparsers.add_parser('eval', help="Run the evaluation executing the requested fuzzers (--fuzzers) on "
            "the requested programs (--progs) and gather the resulting data.")
    parser_eval.add_argument("--fuzzers", nargs='+', required=True,
            help='The fuzzers to evaluate, will fail if the name is not known.')
    parser_eval.add_argument("--progs", nargs='+', required=True,
            help='The programs to evaluate on, will fail if the name is not known.')
    parser_eval.add_argument("--num-repeats", type=int, default=1, help="How often to repeat each mutation for each fuzzer.")

    # CMD: check_seeds 
    parser_eval = subparsers.add_parser('check_seeds', help="Execute the seeds once with every fuzzer to check that they do not "
            " cause any errors, if they cause an error the seed files are deleted.")
    parser_eval.add_argument("--fuzzers", nargs='+', required=True,
            help='The fuzzers to use check with.')
    parser_eval.add_argument("--progs", nargs='+', required=True,
            help='The programs to check for.')

    # CMD: gather_seeds 
    parser_gather_seeds = subparsers.add_parser('gather_seeds', help="Run the fuzzers on the unmutated binary to find inputs. "
            "Check the resulting fuzzing working directories for their individual results, this is not done by the framework.")
    parser_gather_seeds.add_argument("--fuzzers", nargs='+', required=True,
            help='The fuzzers to run, will fail if the name is not known.')
    parser_gather_seeds.add_argument("--progs", nargs='+', required=True,
            help='The programs to fuzz, will fail if the name is not known.')
    parser_gather_seeds.add_argument("--num-repeats", type=int, default=1,
            help="How often to repeat each seed collection for each fuzzer.")
    parser_gather_seeds.add_argument("--dest-dir",
            help="The directory where to put the found seeds.")

    # CMD: import_seeds 
    parser_seed = subparsers.add_parser('import_seeds', help="Copy the seed files from the directory into the used seed directory. "
            "Note that the used seed directory can be specified using the MUT_SEED_DIR environment variable.")
    parser_seed.add_argument("source_seed_dir", help="The source seed directory.")

    # CMD: plot 
    parser_seed = subparsers.add_parser('plot', help="Generate plots for the gathered data")
    parser_seed.add_argument("db_path", help="The sqlite database to plot.")

    # CMD: merge 
    parser_eval = subparsers.add_parser('merge', help="Merge result databases.")
    parser_eval.add_argument("out_db_path",
        help='The path where the database that contains all other databases will be stored. '
             'If this file exists it will be deleted!')
    parser_eval.add_argument("in_db_paths", nargs='+',
        help='Paths of the databases that will be merged, these dbs will not be modified.')

    # CMD: minimize_seeds 
    parser_eval = subparsers.add_parser('minimize_seeds',
            help="Minimize the seeds by finding the minimum set (greedily) "
            "that covers all mutations reached by the full set of seeds.")
    parser_eval.add_argument("--seed_path", required=True,
            help=f'The base dir for the seed files. Needs to be inside: {HOST_TMP_PATH}')
    parser_eval.add_argument("--res_path", required=True,
            help=f'The path where the minimized seeds will be written to. Needs to be inside: {HOST_TMP_PATH}')
    parser_eval.add_argument("--progs", nargs='+', required=True,
        help='The program on which to minimize the seeds.')
    parser_eval.add_argument("--fuzzers", nargs='+', required=True,
        help='The fuzzer on which is used to minimize the seeds.')

    args = parser.parse_args()

    if args.cmd == 'eval':
        run_eval(args.progs, args.fuzzers, args.num_repeats)
    elif args.cmd == 'check_seeds':
        check_seeds(args.progs, args.fuzzers)
    elif args.cmd == 'gather_seeds':
        gather_seeds(args.progs, args.fuzzers, args.num_repeats, args.dest_dir)
    elif args.cmd == 'import_seeds':
        import_seeds(args.source_seed_dir)
    elif args.cmd == 'plot':
        generate_plots(args.db_path)
    elif args.cmd == 'merge':
        merge_dbs(args.out_db_path, args.in_db_paths)
    elif args.cmd == 'minimize_seeds':
        minimize_seeds(args.seed_path, args.res_path, args.fuzzers, args.progs)
    else:
        parser.print_help(sys.stderr)

if __name__ == "__main__":
    main()
