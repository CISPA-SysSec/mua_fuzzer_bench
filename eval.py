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
from typing import Union
import psutil
import contextlib
import concurrent.futures
import shlex
import uuid
import platform
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

# Timeout for the fuzzers during seed gathering in seconds
SEED_TIMEOUT = 60 * 60 * 24  # 24 hours

# If true do filtering of mutations
FILTER_MUTATIONS = os.getenv("MUT_FILTER_MUTS", "0") == "1"

# If true redetect which mutations are used
DETECT_MUTATIONS = True

# Flag if the fuzzed seeds should be used
USE_GATHERED_SEEDS = False

# Time interval in seconds in which to check the results of a fuzzer
CHECK_INTERVAL = 5

# The path where eval data is stored outside of the docker container
HOST_TMP_PATH = Path(".").resolve()/"tmp/"

# Directy where unsolved mutants are collected
UNSOLVED_MUTANTS_DIR = HOST_TMP_PATH/"unsolved_mutants"

# The path where all seed files are collected
SEED_BASE_DIR = Path("/dev/shm/seeds/")

# The location where the eval data is mapped to inside the docker container
IN_DOCKER_WORKDIR = "/workdir/"

TRIGGERED_STR = b"Triggered!\r\n"

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
        "path": "samples/re2-code",
        "seeds": "tmp/samples/re2_harness/seeds",
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
        "path": "samples/c-ares",
        "seeds": "tmp/samples/c-ares_harness/seeds",
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
        "path": "samples/c-ares",
        "seeds": "tmp/samples/c-ares_harness/seeds",
        "args": "@@",
    },
    "freetype": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/freetype/out/ftfuzzer")),
        "orig_bc": str(Path("tmp/samples/freetype/out/ftfuzzer.bc")),
        "path": "samples/ftfuzzer",
        "seeds": "tmp/samples/freetype_harness/seeds",
        "args": "@@",
    },
    "woff2_base": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
            {'val': "tmp/samples/common/main.cc", 'action': 'prefix_workdir'},
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/woff2/out/convert_woff2ttf_fuzzer/convert_woff2ttf_fuzzer")),
        "orig_bc": str(Path("tmp/samples/woff2/out/convert_woff2ttf_fuzzer/convert_woff2ttf_fuzzer.bc")),
        "path": "samples/woff2/out/convert_woff2ttf_fuzzer",
        "seeds": "tmp/samples/woff2_harness/seeds",
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
        "path": "samples/woff2/out/convert_woff2ttf_fuzzer_new_entry",
        "seeds": "tmp/samples/woff2_harness/seeds",
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
        "path": "samples/aspell/",
        "seeds": "tmp/samples/aspell_harness/seeds",
        "args": "@@",
    },
    "bloaty": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/bloaty/out/fuzz_target")),
        "orig_bc": str(Path("tmp/samples/bloaty/out/fuzz_target.bc")),
        "path": "samples/bloaty/",
        "seeds": "tmp/samples/bloaty_harness/seeds",
        "args": "@@",
    },
    "curl": {
        "bc_compile_args": [
            {'val': "-L", 'action': None},
            {'val': "tmp/samples/curl/out/lib", 'action': 'prefix_workdir'},
            {'val': "-lpthread", 'action': None},
            {'val': "-lidn2", 'action': None},
            {'val': "-lz", 'action': None},
            {'val': "-lnghttp2", 'action': None},
        ],
        "bin_compile_args": [
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/curl/out/curl_fuzzer")),
        "orig_bc": str(Path("tmp/samples/curl/out/curl_fuzzer.bc")),
        "path": "samples/curl/",
        "seeds": "tmp/samples/curl_harness/seeds",
        "args": "@@",
    },
    "guetzli": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/guetzli/fuzz_target")),
        "orig_bc": str(Path("tmp/samples/guetzli/fuzz_target.bc")),
        "path": "samples/guetzli/",
        "seeds": "tmp/samples/guetzli_harness/seeds/",
        "args": "@@",
    },
    "mjs": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
            {'val': "-ldl", 'action': None},
        ],
        "is_cpp": False,
        "orig_bin": str(Path("tmp/samples/mjs/mjs/mjs")),
        "orig_bc": str(Path("tmp/samples/mjs/mjs/mjs.bc")),
        "path": "samples/mjs/",
        "seeds": "tmp/samples/mjs_harness/seeds/",
        "args": "@@",
    },
    "vorbis": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/vorbis/out/decode_fuzzer")),
        "orig_bc": str(Path("tmp/samples/vorbis/out/decode_fuzzer.bc")),
        "path": "samples/vorbis/",
        "seeds": "tmp/samples/vorbis_harness/seeds/",
        "args": "@@",
    },
    "harfbuzz": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/harfbuzz/hb-subset-fuzzer")),
        "orig_bc": str(Path("tmp/samples/harfbuzz/hb-subset-fuzzer.bc")),
        "path": "samples/harfbuzz/",
        "seeds": "tmp/samples/harfbuzz/test/fuzzing/fonts/",
        "args": "@@",
    },
    "file": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
            {'val': "-lz", 'action': None},
        ],
        "is_cpp": False,
        "orig_bin": str(Path("tmp/samples/file/magic_fuzzer")),
        "orig_bc": str(Path("tmp/samples/file/magic_fuzzer.bc")),
        "path": "samples/file/",
        "seeds": "tmp/samples/file_harness/seeds/",
        "args": "<WORK>/samples/file_harness/magic.mgc @@",
    },
    "libjpeg": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/libjpeg-turbo/libjpeg_turbo_fuzzer")),
        "orig_bc": str(Path("tmp/samples/libjpeg-turbo/libjpeg_turbo_fuzzer.bc")),
        "path": "samples/libjpeg-turbo/",
        "seeds": "tmp/samples/libjpeg-turbo_harness/seeds/",
        "args": "@@",
    },
    "sqlite3": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
            {'val': "-lpthread", 'action': None},
            {'val': "-ldl", 'action': None},
        ],
        "is_cpp": False,
        "orig_bin": str(Path("tmp/samples/sqlite3/sqlite3_ossfuzz")),
        "orig_bc": str(Path("tmp/samples/sqlite3/sqlite3_ossfuzz.bc")),
        "path": "samples/sqlite3/",
        "seeds": "tmp/samples/sqlite3_harness/seeds/",
        "args": "@@",
    },
}

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
            mut_additional_info,
            mut_column,
            mut_directory,
            mut_file_path,
            mut_line,
            mut_type
        )''')

        c.execute('''
        CREATE TABLE progs (
            exec_id,
            prog,
            bc_compile_args,
            bin_compile_args,
            args,
            seeds,
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
        c.execute('INSERT INTO mutations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                exec_id,
                data['prog'],
                data['mutation_id'],
                json.dumps(data['mutation_data']['additionalInfo']),
                data['mutation_data']['column'],
                data['mutation_data']['directory'],
                data['mutation_data']['filePath'],
                data['mutation_data']['line'],
                data['mutation_data']['type'],
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
                str(data['seeds']),
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
    def new_seeds_executed(self, c, exec_id, prog, mutation_id, cf_seen, total_time):
        c.execute('INSERT INTO executed_seeds VALUES (?, ?, ?, ?, ?)',
            (
                exec_id,
                prog,
                mutation_id,
                cf_seen,
                total_time,
            )
        )
        self.conn.commit()

    @connection
    def new_crashing_inputs(self, c, crashing_inputs, exec_id, prog, mutation_id, run_ctr, fuzzer):
        for path, data in crashing_inputs.items():
            if data['orig_returncode'] != 0 or data['orig_returncode'] != data['mut_returncode']:
                c.execute('INSERT INTO crashing_inputs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
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
        ["sleep", "infinity"], # the arguments
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
        log_config=docker.types.LogConfig(type=docker.types.LogConfig.types.JSON,
            config={'max-size': '10m'}),
        detach=True
    )
    yield container
    container.stop()


@contextlib.contextmanager
def start_mutation_container(core_to_use):
    # get access to the docker client to start the container
    docker_client = docker.from_env()

    # Start and run the container
    container = docker_client.containers.run(
        "mutator_mutator", # the image
        ["sleep", "infinity"], # the arguments
        init=True,
        ipc_mode="host",
        auto_remove=True,
        user=os.getuid(),
        volumes={str(HOST_TMP_PATH): {'bind': "/home/mutator/tmp/",
                                      'mode': 'rw'}},
        mem_limit="10g",
        cpuset_cpus=str(core_to_use) if core_to_use is not None else None,
        log_config=docker.types.LogConfig(type=docker.types.LogConfig.types.JSON,
            config={'max-size': '10m'}),
        detach=True
    )
    yield container
    container.stop()


def run_exec_in_container(container, raise_on_error, cmd):
    """
    Start a short running command in the given container,
    sigint is ignored for this command.
    If return_code is not 0, raise a ValueError containing the run result.
    """
    sub_cmd = ["docker", "exec", container.name, *cmd]
    proc = subprocess.run(sub_cmd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN))
    if raise_on_error and proc.returncode != 0:
        print("process error: =======================",
                proc.args,
                proc.stdout.decode(),
                sep="\n")
        raise ValueError(proc)
    return proc


def get_mut_base_dir(mut_data: dict) -> Path:
    "Get the path to the directory containing all files related to a mutation."
    return Path("/dev/shm/mut_base/")/mut_data['prog']/mut_data['mutation_id']


def get_mut_base_bin(mut_data: dict) -> Path:
    "Get the path to the bin that is the mutated base binary."
    return get_mut_base_dir(mut_data)/"mut_base"


# Seed gathering function for the afl plus plus fuzzer, instruments the target
# program and fuzzes it.
def seed_func_aflpp(run_data):
    global should_run
    # extract used values
    workdir = run_data['workdir']
    prog_bc = Path(IN_DOCKER_WORKDIR)/"tmp"/Path(run_data['prog_bc']).relative_to(HOST_TMP_PATH)
    compile_args = run_data['compile_args']
    aflpp_args = run_data['fuzzer_args']
    args = run_data['args']
    environment = run_data['env']
    seeds = run_data['seeds']
    core_to_use = run_data['used_core']

    # get start time for the seed gathering
    start_time = time.time()

    # get access to the docker client to start the container
    docker_client = docker.from_env()
    # Start and run the container
    container = docker_client.containers.run(
        "mutator_seed_aflpp", # the image
        [
            "/home/eval/start_aflpp_seed.sh",
            str(compile_args),
            str(prog_bc),
            str(IN_DOCKER_WORKDIR/seeds),
            str(aflpp_args),
            str(args)
        ], # the arguments
        environment=environment,
        init=True,
        cpuset_cpus=str(core_to_use),
        ipc_mode="host",
        auto_remove=True,
        volumes={str(HOST_TMP_PATH): {'bind': str(IN_DOCKER_WORKDIR),
                                      'mode': 'ro'}},
        working_dir=str(workdir),
        mem_limit="1g",
        log_config=docker.types.LogConfig(type=docker.types.LogConfig.types.JSON,
            config={'max-size': '10m'}),
        detach=True
    )

    logs_queue = queue.Queue()
    DockerLogStreamer(logs_queue, container).start()

    while time.time() < start_time + SEED_TIMEOUT and should_run:
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

    # Check if container is still running, if it is, kill it.
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

    return '\n'.join(all_logs)

SEED_FUZZERS = {
    "aflpp_main": {
        'seed_func': seed_func_aflpp,
        'fuzzer_args': "-M main",
        'env': {},
    },
    "aflpp_cmplog": {
        'seed_func': seed_func_aflpp,
        'fuzzer_args': "-S cmplog",
        'env': {'CMPLOG:': '1'},
    },
    "aflpp_asan": {
        'seed_func': seed_func_aflpp,
        'fuzzer_args': "-S asan",
        'env': {'AFL_USE_ASAN:': '1'},
    },
    "aflpp_ubsan": {
        'seed_func': seed_func_aflpp,
        'fuzzer_args': "-S ubsan",
        'env': {'AFL_USE_UBSAN:': '1'},
    },
    "aflpp_cfisan": {
        'seed_func': seed_func_aflpp,
        'fuzzer_args': "-S cfisan",
        'env': {'AFL_USE_CFISAN:': '1'},
    },
    "aflpp_msan": {
        'seed_func': seed_func_aflpp,
        'fuzzer_args': "-S msan",
        'env': {'AFL_USE_MSAN:': '1'},
    },
}

POWER_SCHEDULES = ["fast", "coe", "lin", "quad", "exploit", "mmopt", "rare", "seek"]

for ii in range(17):
    ps = POWER_SCHEDULES[ii % len(POWER_SCHEDULES)]
    SEED_FUZZERS[f"aflpp_vanilla_{ii}"] = {
        'seed_func': seed_func_aflpp,
        'fuzzer_args': f"-S vanilla_{ii} -p {ps}",
        'env': {},
    }

for ii in range(17):
    ps = POWER_SCHEDULES[ii % len(POWER_SCHEDULES)]
    SEED_FUZZERS[f"aflpp_mopt_{ii}"] = {
        'seed_func': seed_func_aflpp,
        'fuzzer_args': f"-S mopt_{ii} -L 0 -p {ps}",
        'env': {},
    }

# get all fuzzer instances to run for the prog
def get_seed_runs(prog_name, prog_info):
    shutil.rmtree(SEED_BASE_DIR/prog_name)
    for fuzzer, fuzzer_info in SEED_FUZZERS.items():
        # Get the working directory based on program and mutation id and
        # fuzzer, which is a unique path for each run
        workdir = SEED_BASE_DIR/prog_name/fuzzer
        # Get the bc file that should be fuzzed (and probably
        # instrumented).
        prog_bc = prog_info['orig_bc'].absolute()
        # Get the path to the file that should be included during compilation
        compile_args = build_compile_args(prog_info['bc_compile_args'] + prog_info['bin_compile_args'], IN_DOCKER_WORKDIR)
        # Arguments on how to execute the binary
        args = prog_info['args']
        # Prepare seeds
        seeds = Path(prog_info['seeds'])
        # seed function
        # gather all info
        run_data = {
            'fuzzer': fuzzer,
            'seed_func': fuzzer_info['seed_func'],
            'fuzzer_args': fuzzer_info['fuzzer_args'],
            'env': fuzzer_info['env'],
            'workdir': workdir,
            'prog_bc': prog_bc,
            'compile_args': compile_args,
            'args': args,
            'seeds': seeds,
        }
        yield run_data


# wait for a run to complete
def wait_for_seed_runs(runs, cores_in_use, break_after_one):
    # wait for the futures to complete
    for future in concurrent.futures.as_completed(runs):
        # get the associated data for that future
        data = runs[future]
        # we are not interested in this run anymore
        del runs[future]
        try:
            # if there was no exception get the data
            run_result = future.result()
            print(f"run_result: {run_result}")
        except Exception:
            # if there was an exception print it
            trace = traceback.format_exc()
            print('='*50,
                '\n%r generated an exception: %s\n' %
                    (data, trace), # exc
                '='*50)
        print(runs)
        # Set the core for this run to unused
        cores_in_use[data['used_core']] = False
        print(cores_in_use)
        # If we only wanted to wait for one run, break here to return
        if break_after_one:
            break


# run a multi-core fuzzing campaign to get a large set of interesting seed files
# for each program
def gather_seeds():
    # build docker images
    proc = subprocess.run([
        "docker", "build",
        "-t", "mutator_testing",
        "-f", "eval/Dockerfile.testing",
        "."])
    if proc.returncode != 0:
        print("Could not build testing image.", proc)
        sys.exit(1)

    proc = subprocess.run([
        "docker", "build",
        "-t", "mutator_seed_aflpp",
        "-f", "eval/Dockerfile.seed",
        "."])
    if proc.returncode != 0:
        print("Could not build mutator_seed_aflpp image.", proc)
        sys.exit(1)

    # for each program gather the seeds
    with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_CPUS) as executor:
        for prog_name, prog_vals in PROGRAMS.items():
            # keep a list of all runs
            runs = {}
            # start each fuzzing instance in a container, for each core
            # Keep a list of which cores can be used
            cores_in_use = [False]*NUM_CPUS
            # Get each run
            for ii, run_data in enumerate(get_seed_runs(prog_name, prog_vals)):
                # If we should stop, do so now to not create any new run.
                if not should_run:
                    break
                # Get a free core, this will throw an exception if there is none
                used_core = cores_in_use.index(False)
                # Set the core as used
                cores_in_use[used_core] = True
                print(cores_in_use)
                # Unpack the run_data
                # Add the run to the executor, this starts execution of the eval
                # function. Also associate some information with that run, this
                # is later used to record needed information.
                run_data['used_core'] = used_core
                runs[executor.submit(run_data['seed_func'], run_data)] = run_data
                # Do not wait for a run, if we can start more runs do so first and
                # only wait when all cores are in use.
                if False in cores_in_use:
                    continue
                # Wait for a single run to complete, after which we can start another
                wait_for_seed_runs(runs, cores_in_use, True)

            # wait for all containers to be done
            wait_for_seed_runs(runs, cores_in_use, False)

            # only continue with next program if we should continue running
            if not should_run:
                break

            # collect the resulting seeds into one folder
            base_dir = SEED_BASE_DIR.joinpath(prog_name)
            seed_dir = base_dir.joinpath("seeds")
            if seed_dir.is_dir():
                shutil.rmtree(seed_dir)
            seed_dir.mkdir()

            for queue_file in base_dir.joinpath("output/main/queue").iterdir():
                if queue_file.is_dir():
                    continue
                shutil.copy(queue_file, seed_dir.joinpath(queue_file.name))


# returns true if a crashing input is found that only triggers for the
# mutated binary
def check_crashing_inputs(testing_container, crashing_inputs, crash_dir,
                          orig_bin, mut_bin, args, start_time, covered, stage):
    if not crash_dir.is_dir():
        return False

    for path in crash_dir.iterdir():
        if path.is_file() and path.name != "README.txt":
            if str(path) not in crashing_inputs:
                input_args = args.replace("<WORK>/", IN_DOCKER_WORKDIR
                        ).replace("@@", str(path)
                        ).replace("___FILE___", str(path))
                # Run input on original binary
                orig_cmd = ["/run_bin.sh", orig_bin] + shlex.split(input_args)
                proc = run_exec_in_container(testing_container, False, orig_cmd)
                orig_res = proc.stdout
                orig_returncode = proc.returncode
                if orig_returncode != 0:
                    print("orig bin returncode != 0, crashing base bin:")
                    print("args:", orig_cmd, "returncode:", orig_returncode)
                    print(orig_res)

                # Run input on mutated binary
                mut_cmd = ["/run_bin.sh", mut_bin] + shlex.split(input_args)
                proc = run_exec_in_container(testing_container, False, mut_cmd)
                mut_res = proc.stdout

                num_triggered = len(mut_res.split(TRIGGERED_STR)) - 1
                mut_res = mut_res.replace(TRIGGERED_STR, b"")
                mut_res = mut_res
                mut_returncode = proc.returncode

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
                }

                if (orig_returncode != mut_returncode):  # or orig_res != mut_res):
                    return True
    return False


# Eval function for the afl plus plus fuzzer, compiles the mutated program
# and fuzzes it. Finally various eval data is returned
def base_eval(run_data, docker_image, executable):
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
    seeds = mut_data['seeds']
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
                executable,
                str(compile_args),
                str(prog_bc),
                str(IN_DOCKER_WORKDIR/seeds),
                str(args)
            ], # the arguments
            environment={
                'TRIGGERED_OUTPUT': str(""),
                'TRIGGERED_FOLDER': str(covered.path),
            },
            init=True,
            cpuset_cpus=str(core_to_use),
            auto_remove=True,
            volumes={
                str(HOST_TMP_PATH): {'bind': str(IN_DOCKER_WORKDIR)+"/tmp/", 'mode': 'ro'},
                "/dev/shm": {'bind': "/dev/shm", 'mode': 'rw'},
            },
            working_dir=str(workdir),
            mem_limit="1g",
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
                try:
                    return [plot_data[-2]]
                except IndexError:
                    return [plot_data[-1]]
        else:
            # Did not find a plot
            return []

    except Exception as exc:
        raise ValueError(''.join(all_logs)) from exc

def aflpp_eval(run_data):
    run_data['crash_dir'] = "output/default/crashes"
    run_data['fuzzer_args'] = run_data['mut_data']['args']
    result = base_eval(run_data, "mutation-testing-aflpp", "/home/user/eval.sh")
    result['plot_data'] = get_aflpp_logs(run_data['workdir'], result['all_logs'])
    return result

def afl_eval(run_data):
    run_data['crash_dir'] = "output/crashes"
    run_data['fuzzer_args'] = run_data['mut_data']['args']
    result = base_eval(run_data, "mutation-testing-afl", "/home/user/eval.sh")
    result['plot_data'] = get_aflpp_logs(run_data['workdir'], result['all_logs'])
    return result

def aflppfastexploit_eval(run_data):
    run_data['crash_dir'] = "output/default/crashes"
    run_data['fuzzer_args'] = run_data['mut_data']['args']
    result = base_eval(run_data, "mutation-testing-aflppfastexploit", "/home/user/eval.sh")
    result['plot_data'] = get_aflpp_logs(run_data['workdir'], result['all_logs'])
    return result

def aflppmopt_eval(run_data):
    run_data['crash_dir'] = "output/default/crashes"
    run_data['fuzzer_args'] = run_data['mut_data']['args']
    result = base_eval(run_data, "mutation-testing-aflppmopt", "/home/user/eval.sh")
    result['plot_data'] = get_aflpp_logs(run_data['workdir'], result['all_logs'])
    return result

def fairfuzz_eval(run_data):
    run_data['crash_dir'] = "output/crashes"
    run_data['fuzzer_args'] = run_data['mut_data']['args']
    result = base_eval(run_data, "mutation-testing-fairfuzz", "/home/user/eval.sh")
    result['plot_data'] = get_aflpp_logs(run_data['workdir'], result['all_logs'])
    return result

def honggfuzz_eval(run_data):
    run_data['crash_dir'] = "crashes"
    run_data['fuzzer_args'] = run_data['mut_data']['args'].replace("@@", "___FILE___")
    result = base_eval(run_data, "mutation-testing-honggfuzz", "/home/user/eval.sh")
    result['plot_data'] = []
    return result

def libfuzzer_eval(run_data):
    result = base_eval(run_data, "mutation-testing-libfuzzer", "/home/user/eval.sh")
    return result

# def aflppasan_eval(run_data):
#     return aflpp_base_eval(
#         run_data, "mutator_aflppasan", "/home/user/eval.sh")

# def aflppubsan_eval(run_data):
#     return aflpp_base_eval(
#         run_data, "mutator_aflppubsan", "/home/user/eval.sh")

# def aflppmsan_eval(run_data):
#     return aflpp_base_eval(
#         run_data, "mutator_aflppmsan", "/home/user/eval.sh")

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
    "aflpp": aflpp_eval,
    "afl": afl_eval,
    "aflpp_fast_exploit": aflppfastexploit_eval,
    "aflpp_mopt": aflppmopt_eval,
    "afl_fairfuzz": fairfuzz_eval,
    "honggfuzz": honggfuzz_eval,
}

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
        # Get the right seeds
        if USE_GATHERED_SEEDS:
            seeds = SEED_BASE_DIR.joinpath(prog).joinpath('seeds')
        else:
            seeds = Path(prog_info['seeds'])

        # Compile the mutation location detector for the prog.
        args = ["./run_mutation.py",
                "-bc", prog_info['orig_bc'],
                *(["-cpp"] if prog_info['is_cpp'] else []),  # conditionally add cpp flag
                "--bc-args=" + build_compile_args(prog_info['bc_compile_args'], IN_DOCKER_WORKDIR),
                "--bin-args=" + build_compile_args(prog_info['bin_compile_args'], IN_DOCKER_WORKDIR)]

        run_exec_in_container(mutator, True, args)


        if FILTER_MUTATIONS and DETECT_MUTATIONS:
            print("Filtering mutations, running all seed files.")
            # Prepare the folder where the number of the generated seeds is put.
            shutil.rmtree(mutation_list_dir, ignore_errors=True)
            mutation_list_dir.mkdir(parents=True)
            # Run the seeds through the detector binary.
            detector_bin = Path(prog_info['orig_bc']).with_suffix(".ll.opt_mutate")
            detector_args_lines = ""
            for seed in list(seeds.glob("*")):
                detector_args = prog_info['args']
                detector_args = detector_args.replace("<WORK>/", "").replace("@@", str(seed))
                detector_args_lines += detector_args
                detector_args_lines += "\n"
            run_exec_in_container(mutator, False,
                    ["./iterate_seeds.sh", mutation_list_dir, detector_bin, detector_args_lines])

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
            mutations = list((p.name, prog, prog_info, seeds, mutation_data) for p in mutation_list_dir.glob("*"))
        else:
            mutations = list((str(p['UID']), prog, prog_info, seeds, mutation_data) for p in mutation_data)
        print(f"Found {len(mutations)} mutations for {prog}")

        for mut in mutations:
            stats.new_mutation(EXEC_ID, {
                'prog': mut[1],
                'mutation_id': mut[0],
                'mutation_data': mut[4][int(mut[0])],
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
        mutation_type = mut[4][int(mutation_id)]['type']
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
        for (mutation_id, prog, prog_info, seeds, mutation_data) in all_mutations:
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
                'seeds': seeds,
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
            task_result['covered_file_seen'], task_result['total_time'])

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

        run_exec_in_container(mutator, True, [
                "./run_mutation.py",
                "-bc",
                *(["-cpp"] if data['is_cpp'] else []),  # conditionally add cpp flag
                "-m", data['mutation_id'],
                "--out-dir", str(mut_base_dir),
                data['orig_bc']
        ])

        # compile the compare version of the mutated binary
        run_exec_in_container(testing, True, [
                "/usr/bin/clang++-11",
                "-v",
                "-o", str(mut_base_dir/"mut_base"),
                *shlex.split(compile_args),
                "/workdir/tmp/lib/libdynamiclibrary.so",
                str(prog_bc)
        ] )

        seeds = data['seeds']
        orig_bin = Path(IN_DOCKER_WORKDIR)/"tmp"/Path(data['orig_bin']).relative_to(HOST_TMP_PATH)
        args = data['args']
        docker_mut_bin = get_mut_base_bin(data)

        # check if seeds are already crashing
        checked_seeds = {}

        # do an initial check to see if the seed files are already crashing
        found_by_seeds = check_crashing_inputs(testing, checked_seeds, seeds,
                orig_bin, docker_mut_bin, args, start_time,
                covered, "initial")
        return {
            'total_time': time.time() - start_time,
            'covered_file_seen': covered.found,
            'crashing_inputs': checked_seeds,
            'found_by_seeds': found_by_seeds,
            'all_logs': ["found crashing seed input"]
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

    # build testing image
    proc = subprocess.run([
            "docker", "build",
            "-t", "mutator_testing",
            "--build-arg", f"CUSTOM_USER_ID={os.getuid()}",
            "-f", "eval/Dockerfile.testing",
            "."
        ])
    if proc.returncode != 0:
        print("Could not build testing image.", proc)
        sys.exit(1)

    # build the fuzzer docker images
    for tag, name in [
        ("mutation-testing-system", "system"),
        ("mutation-testing-afl", "afl"),
        ("mutation-testing-aflpp", "aflpp"),
        ("mutation-testing-aflppmopt", "aflppmopt"),
        ("mutation-testing-aflppfastexploit", "aflppfastexploit"),
        ("mutation-testing-fairfuzz", "fairfuzz"),
        ("mutation-testing-honggfuzz", "honggfuzz"),
        ("mutation-testing-libfuzzer", "libfuzzer"),
    ]:
        print(f"Building docker image for {tag} ({name})")
        proc = subprocess.run([
            "docker", "build",
            "--build-arg", f"CUSTOM_USER_ID={os.getuid()}",
            "--tag", tag,
            "-f", f"eval/{name}/Dockerfile",
            "."])
        if proc.returncode != 0:
            print(f"Could not build {tag} image.", proc)
            sys.exit(1)

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
                    tasks[executor.submit(run_data['eval_func'], run_data)] = ("run", core, run_data)
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

def crash_stats(con):
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
    res += crash_stats(con)
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

def main():
    import sys
    import argparse

    # set signal handler for keyboard interrupt
    signal.signal(signal.SIGINT, sigint_handler)

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='cmd', help="These are the possible actions for the eval, "
            "see their individual descriptions.")

    parser_seed = subparsers.add_parser('seed', help="Run a seed gathering stage, to gather seed that are shared by "
            "all fuzzers")

    parser_eval = subparsers.add_parser('eval', help="Run the evaluation executing the requested fuzzers (--fuzzers) on "
            "the requested programs (--progs) and gather the resulting data.")
    parser_eval.add_argument("--fuzzers", nargs='+', required=True,
            help='The fuzzers to evaluate, will fail if the name is not known.')
    parser_eval.add_argument("--progs", nargs='+', required=True,
            help='The programs to evaluate on, will fail if the name is not known.')
    parser_eval.add_argument("--num-repeats", type=int, default=1, help="How often to repeat each mutation for each fuzzer.")

    parser_seed = subparsers.add_parser('plot', help="Generate plots for the gathered data")
    parser_seed.add_argument("db_path", help="The sqlite database to plot.")

    args = parser.parse_args()

    if args.cmd == 'seed':
        gather_seeds()
    elif args.cmd == 'eval':
        run_eval(args.progs, args.fuzzers, args.num_repeats)
    elif args.cmd == 'plot':
        generate_plots(args.db_path)
    else:
        parser.print_help(sys.stderr)

if __name__ == "__main__":
    main()
