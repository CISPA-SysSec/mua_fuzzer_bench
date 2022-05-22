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
from typing import Union, List, Tuple, Set, Dict, Any
import psutil
import contextlib
import concurrent.futures
import shlex
import uuid
import platform
import tempfile
import hashlib
import copy
from inspect import getframeinfo, stack
from itertools import product, chain, zip_longest
from random import choice
from pathlib import Path

import numpy as np

import docker

import logging
# logging.basicConfig(
#     stream=sys.stdout,
#     level=logging.DEBUG,
#     format='%(process)d %(filename)s:%(lineno)s %(levelname)s %(message)s'
# )
# set up logging to file
logging.basicConfig(
     filename='eval.log',
     filemode='w',
     level=logging.DEBUG, 
     format= '[%(asctime)-8s] %(levelname)-6s %(message)-98s    :: %(module)s file://%(pathname)s : %(lineno)d',
     datefmt='%H:%M:%S'
 )

logging.getLogger("docker").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

# set up logging to console
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(message)s')
console.setFormatter(formatter)

# add the handler to the root logger
logging.getLogger('').addHandler(console)
logger = logging.getLogger(__name__)

logger.info("Starting ...")

EXEC_ID = str(uuid.uuid4())

# set the number of concurrent runs
NUM_CPUS = int(os.getenv("MUT_NUM_CPUS", psutil.cpu_count(logical=True)))

# If the detector binary should be build with ASAN
WITH_ASAN = os.getenv("MUT_BUILD_ASAN", "0") == "1"

# If the detector binary should be build with MSAN
WITH_MSAN = os.getenv("MUT_BUILD_MSAN", "0") == "1"

# If container logs should be shown
SHOW_CONTAINER_LOGS = os.getenv("MUT_LOGS", "0") == "1"

# Remove the working directory after a run
RM_WORKDIR = os.getenv("MUT_RM_WORKDIR", "1") == "1"

# If true filter out those mutations that are not covered by seed files, using the detector version.
FILTER_MUTATIONS = os.getenv("MUT_FILTER_MUTS", "0") == "1"

# If true only run the seed inputs and dont do any fuzzing.
JUST_SEEDS = os.getenv("MUT_JUST_SEEDS", "0") == "1"

# If true stop fuzzing when multiple mutations are covered, otherwise only when a crash is found.
STOP_ON_MULTI = os.getenv("MUT_STOP_ON_MULTI", "0") == "1"

SKIP_LOCATOR_SEED_CHECK = os.getenv("MUT_SKIP_LOCATOR_SEED_CHECK", "0") == "1"

# The maximum number of mutants to include in one supermutant
MAX_SUPERMUTANT_SIZE = int(os.getenv("MUT_MAX_SUPERMUTANT_SIZE", "100"))

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


# The programs that can be evaluated
PROGRAMS = {
    "cares_parse_reply": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": False,
        "orig_bin": str(Path("tmp/samples/c-ares/out/ares-parse-reply")),
        "orig_bc": str(Path("tmp/samples/c-ares/out/ares-parse-reply.bc")),
        "name": "cares",
        "path": "samples/c-ares",
        "dict": None,
        "omit_functions": ["LLVMFuzzerTestOneInput"],
    },
    "cares_name": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": False,
        "orig_bin": str(Path("tmp/samples/c-ares/out/ares-name")),
        "orig_bc": str(Path("tmp/samples/c-ares/out/ares-name.bc")),
        "name": "cares",
        "path": "samples/c-ares",
        "dict": None,
        "omit_functions": ["LLVMFuzzerTestOneInput"],
    },
    "woff2_base": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/woff2/out/convert_woff2ttf_fuzzer/convert_woff2ttf_fuzzer")),
        "orig_bc": str(Path("tmp/samples/woff2/out/convert_woff2ttf_fuzzer/convert_woff2ttf_fuzzer.bc")),
        "name": "woff2",
        "path": "samples/woff2/out/convert_woff2ttf_fuzzer",
        "dict": None,
        "omit_functions": ["LLVMFuzzerTestOneInput"],
    },
    "woff2_new": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/woff2/out/convert_woff2ttf_fuzzer_new_entry/convert_woff2ttf_fuzzer_new_entry")),
        "orig_bc": str(Path("tmp/samples/woff2/out/convert_woff2ttf_fuzzer_new_entry/convert_woff2ttf_fuzzer_new_entry.bc")),
        "name": "woff2",
        "path": "samples/woff2/out/convert_woff2ttf_fuzzer_new_entry",
        "dict": None,
        "omit_functions": ["LLVMFuzzerTestOneInput"],
    },
    "re2": {
        "bc_compile_args": [
            {'val': "-std=c++11", 'action': None},
        ],
        "bin_compile_args": [
            # {'val': "tmp/samples/re2_harness/harness.cc", 'action': 'prefix_workdir'},
            {'val': "-lpthread", 'action': None},
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/re2-code/out/re2_fuzzer")),
        "orig_bc": str(Path("tmp/samples/re2-code/out/re2.bc")),
        "name": "re2",
        "path": "samples/re2-code",
        "dict": "tmp/samples/re2_harness/re2.dict",
        "omit_functions": ["LLVMFuzzerTestOneInput"],
    },
     "bloaty": {
         "bc_compile_args": [
            {'val': "-L", 'action': None},
            {'val': "tmp/samples/bloaty/work/third_party/protobuf/cmake/", 'action': 'prefix_workdir'},
            {'val': "-L", 'action': None},
            {'val': "tmp/samples/bloaty/work/third_party/re2/", 'action': 'prefix_workdir'},
            {'val': "-L", 'action': None},
            {'val': "tmp/samples/bloaty/work/third_party/capstone/", 'action': 'prefix_workdir'},
            {'val': "-lprotobuf", 'action': None},
            {'val': "-lre2", 'action': None},
            {'val': "-lcapstone", 'action': None},
            {'val': "-lpthread", 'action': None},
            {'val': "-lz", 'action': None},
         ],
         "bin_compile_args": [
         ],
         "is_cpp": True,
         "orig_bin": str(Path("tmp/samples/bloaty/work/bloaty-orig")),
         "orig_bc": str(Path("tmp/samples/bloaty/work/bloaty.bc")),
         "name": "bloaty",
         "path": "samples/bloaty/",
         "dict": None,
        "omit_functions": ["LLVMFuzzerTestOneInput"],
     },
     "curl": {
        "bc_compile_args": [
           {'val': "-L", 'action': None},
           {'val': "tmp/samples/curl/out/lib/", 'action': 'prefix_workdir'},
           {'val': "-lpthread", 'action': None},
           {'val': "-lidn2", 'action': None},
           {'val': "-lnghttp2", 'action': None},
           {'val': "-lz", 'action': None},
        ],
        "bin_compile_args": [
        ],
        "is_cpp": False,
        "orig_bin": str(Path("tmp/samples/curl/out/curl_fuzzer")),
        "orig_bc": str(Path("tmp/samples/curl/out/curl.bc")),
        "name": "curl",
        "path": "samples/curl/",
        "dict": None,
        "omit_functions": ["LLVMFuzzerTestOneInput"],
     },
    "guetzli": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/guetzli/guetzli-orig")),
        "orig_bc": str(Path("tmp/samples/guetzli/guetzli.bc")),
        "name": "guetzli",
        "path": "samples/guetzli/",
        "dict": "tmp/samples/guetzli_harness/guetzli.dict",
        "omit_functions": ["LLVMFuzzerTestOneInput"],
    },
    "libevent": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
            {'val': '-lstdc++', 'action': None},
        ],
        "is_cpp": False,
        "orig_bin": str(Path("tmp/samples/libevent/out/parse_query_fuzzer")),
        "orig_bc": str(Path("tmp/samples/libevent/out/parse_query_fuzzer.bc")),
        "name": "libevent",
        "path": "samples/libevent/",
        "dict": None,
        "omit_functions": ["LLVMFuzzerTestOneInput"],
    },
    "mjs": {
        "bc_compile_args": [
            {'val': "-ldl", 'action': None},
        ],
        "bin_compile_args": [
        ],
        "is_cpp": False,
        "orig_bin": str(Path("tmp/samples/mjs/out/mjs_fuzzer")),
        "orig_bc": str(Path("tmp/samples/mjs/out/mjs.bc")),
        "name": "mjs",
        "path": "samples/mjs/",
        "dict": None,
        "omit_functions": ["LLVMFuzzerTestOneInput"],
    },
    "jsoncpp": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/jsoncpp/out/jsoncpp-orig")),
        "orig_bc": str(Path("tmp/samples/jsoncpp/out/jsoncpp.bc")),
        "name": "jsoncpp",
        "path": "samples/jsoncpp/",
        "dict": "tmp/samples/jsoncpp_harness/fuzz.dict",
        "omit_functions": ["LLVMFuzzerTestOneInput"],
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
    #  },
    # "aspell": {
    #     "bc_compile_args": [
    #         {'val': "-lpthread", 'action': None},
    #         {'val': "-ldl", 'action': None},
    #     ],
    #     "bin_compile_args": [
    #     ],
    #     "is_cpp": True,
    #     "orig_bin": str(Path("tmp/samples/aspell/out/aspell_fuzzer")),
    #     "orig_bc": str(Path("tmp/samples/aspell/out/aspell_fuzzer.bc")),
    #     "name": "aspell",
    #     "path": "samples/aspell/",
    #     "dict": None,
    # },
    # "vorbis": {
    #     "bc_compile_args": [
    #     ],
    #     "bin_compile_args": [
    #     ],
    #     "is_cpp": True,
    #     "orig_bin": str(Path("tmp/samples/vorbis/out/decode_fuzzer")),
    #     "orig_bc": str(Path("tmp/samples/vorbis/out/decode_fuzzer.bc")),
    #     "name": "vorbis",
    #     "path": "samples/vorbis/",
    #     "dict": "tmp/samples/vorbis_harness/vorbis.dict",
    #     "args": "@@",
    # },
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
    # "libjpeg": {
    #     "bc_compile_args": [
    #     ],
    #     "bin_compile_args": [
    #     ],
    #     "is_cpp": True,
    #     "orig_bin": str(Path("tmp/samples/libjpeg-turbo/out/libjpeg")),
    #     "orig_bc": str(Path("tmp/samples/libjpeg-turbo/out/libjpeg.bc")),
    #     "name": "libjpeg",
    #     "path": "samples/libjpeg-turbo/",
    #     "dict": "tmp/samples/libjpeg-turbo_harness/libjpeg.dict",
    #     "args": "@@",
    # },
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
    # "libcxx": {
    #     "bc_compile_args": [
    #     ],
    #     "bin_compile_args": [
    #     ],
    #     "is_cpp": True,
    #     "orig_bin": str(Path("tmp/samples/libcxx/out/libjpeg")),
    #     "orig_bc": str(Path("tmp/samples/libcxx/out/libjpeg.bc")),
    #     "name": "libcxx",
    #     "path": "samples/libcxx/",
    #     "dict": "tmp/samples/libcxx/libjpeg.dict",
    # },
    # "openthread": {
    #     "bc_compile_args": [
    #     ],
    #     "bin_compile_args": [
    #     ],
    #     "is_cpp": True,
    #     "orig_bin": str(Path("tmp/samples/libcxx/out/libjpeg")),
    #     "orig_bc": str(Path("tmp/samples/libcxx/out/libjpeg.bc")),
    #     "name": "openthread",
    #     "path": "samples/openthread/",
    #     "dict": None,
    # },
    # "libarchive": {
    #     "bc_compile_args": [
    #         # {'val': "-Itmp/samples/libarchive/libarchive/libarchive", 'action': 'prefix_workdir'},
    #         {'val': "-lcrypto", 'action': None},
    #         {'val': "-lacl", 'action': None},
    #         {'val': "-llzma", 'action': None},
    #         {'val': "-llz4", 'action': None},
    #         {'val': "-lbz2", 'action': None},
    #         {'val': "-lz", 'action': None},
    #         {'val': "-ldl", 'action': None},
    #     ],
    #     "bin_compile_args": [
    #     ],
    #     "is_cpp": True,
    #     "orig_bin": str(Path("tmp/samples/libarchive/out/libarchive_fuzzer")),
    #     "orig_bc": str(Path("tmp/samples/libarchive/out/libarchive.bc")),
    #     "name": "libarchive",
    #     "path": "samples/libarchive/",
    #     "dict": None,
    # },
    # "spdk": {
    #     "bc_compile_args": [
    #         {'val': "-ldl", 'action': None},
    #         {'val': "-lpthread", 'action': None},
    #         {'val': "-lnuma", 'action': None},
    #         {'val': "-luuid", 'action': None},
    #     ],
    #     "bin_compile_args": [
    #     ],
    #     "is_cpp": True,
    #     "orig_bin": str(Path("tmp/samples/spdk/out/parse_json_fuzzer")),
    #     "orig_bc": str(Path("tmp/samples/spdk/out/spdk.bc")),
    #     "name": "spdk",
    #     "path": "samples/spdk/",
    #     "dict": None,
    # },
}


BLOCK_SIZE = 1024*4

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
    crashes = list(path.glob("crashes/*"))
    return list(found) + list(crashes)


def collect_afl(path):
    found = [pp for pp in path.glob("**/queue/*") if pp.name != '.state']
    crashes = list([pp for pp in path.glob("**/crashes/*") if pp.name != 'README.txt'])
    return list(found) + list(crashes)


def collect_libfuzzer(path):
    found = path.glob("seeds/*")
    crashes = list(path.glob("artifacts/*"))
    return list(found) + list(crashes)


SEED_HANDLERS = {
    'honggfuzz': collect_honggfuzz,
    'libfuzzer': collect_libfuzzer,
    'aflpp': collect_afl,
    'afl': collect_afl,
}


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)


class CoverageException(Exception):
    def __init__(self, run):
        super().__init__(run)
        self.run = run


class PreparedRuns():
    def __init__(self):
        self.runs = queue.Queue()

    def get_next(self) -> Union[None, dict]:
        try:
            return self.runs.get_nowait()
        except queue.Empty:
            return None

    def add(self, type_: str, data: Any):
        if type_ in ['fuzz', 'check']:
            logger.debug(f"Adding run: {type_} {data['mut_data']['supermutant_id']} {data['mut_data']['prog_bc']} {data['mut_data']['mutation_ids']}")
        elif type_ == 'mut':
            logger.debug(f"Adding run: {type_} {data[0]['supermutant_id']} {data[0]['mutation_ids']}")
        else:
            logger.debug(f"Adding run: {type_} {data}")

        self.runs.put_nowait({'type': type_, 'data': data})


def dbg(*args, **kwargs):
    caller = getframeinfo(stack()[1][0])
    logger.debug(f"{caller.filename}:{caller.lineno}: {args} {kwargs}")
    return args


def fuzzer_container_tag(name):
    return f"mutation-testing-fuzzer-{name}"


def subject_container_tag(name):
    return f"mutation-testing-subject-{name}"


def mutation_locations_path(prog_info):
    orig_bc = Path(prog_info['orig_bc'])
    return orig_bc.with_suffix('.ll.mutationlocations')


def mutation_locations_graph_path(prog_info):
    orig_bc = Path(prog_info['orig_bc'])
    return orig_bc.with_suffix('.ll.mutationlocations.graph')


def mutation_detector_path(prog_info):
    orig_bc = Path(prog_info['orig_bc'])
    return  orig_bc.with_suffix(".ll.opt_mutate")


def mutation_prog_source_path(prog_info):
    orig_bc = Path(prog_info['orig_bc'])
    return orig_bc.with_suffix('.ll.ll')


# Indicates if the evaluation should continue, is mainly used to shut down
# after a keyboard interrupt by the user.
# Global variable that is only written in the sigint_handler, as such it is safe
# to use in a read only fashion by the threads.
should_run = True

# Handler for a keyboard interrupt only sets `should_run` to False.
def sigint_handler(signum, frame):
    global should_run
    logger.info(f"Got stop signal: ({signum}), stopping!")
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

# A class to store information into a sqlite database. This expects sole access
# to the database.
class Stats():

    def __init__(self, db_path):
        super().__init__()
        if db_path is None:
            logger.info(f"Didn't get db_path env, not writing history.")
            self.conn = None
            return
        db_path = Path(db_path)
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

    def next_supermutant_id(self):
        cur = self.supermutant_ctr
        self.supermutant_ctr += 1
        return cur

    def commit(self):
        self.conn.commit()

    @connection
    def new_execution(self, c, exec_id, hostname, git_status, rerun, start_time, args, env):
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
        with open(data['orig_bc'], 'rb') as f:
            bc_file_data = f.read()
        with open(mutation_prog_source_path(data), 'rt') as f:
            prog_source_data = f.read()
        with open(mutation_locations_path(data), 'rt') as f:
            ml_data = f.read()
        c.execute('INSERT INTO progs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                exec_id,
                prog,
                json.dumps(data['bc_compile_args']),
                json.dumps(data['bin_compile_args']),
                str(data['dict']),
                str(data['orig_bin']),
                bc_file_data,
                prog_source_data,
                ml_data,
                None
            )
        )
        self.conn.commit()

    @connection
    def new_supermutant_graph_info(self, c, exec_id, prog, graph_info):
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
    def new_seeds_executed(self, c, exec_id, prog, mutation_id, run_ctr, fuzzer, cf_seen, timed_out, total_time):
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

    def get_bc_file_content(self, prog):
        c = self.db.cursor()
        res = c.execute('select orig_bc_file_data from progs where prog = ?', (prog,))
        res = [r for r in res]
        assert len(res) == 1
        return res[0][0]

    def get_mutation_locations_content(self, prog):
        c = self.db.cursor()
        res = c.execute('select mutation_locations_data from progs where prog = ?', (prog,))
        res = [r for r in res]
        assert len(res) == 1
        return res[0][0]

    def get_prog_source_content(self, prog):
        c = self.db.cursor()
        res = c.execute('select prog_source_file_data from progs where prog = ?', (prog,))
        res = [r for r in res]
        assert len(res) == 1
        return res[0][0]

    def get_supermutations(self, prog):
        c = self.db.cursor()
        res = c.execute('select * from initial_super_mutants where prog = ?', (prog,))
        res = [
            {
                'exec_id': r[0],
                'prog': r[1],
                'super_mutant_id': r[2],
                'mutation_id': r[3],
            }
            for r in res
        ]
        return res


class DockerLogStreamer(threading.Thread):
    def __init__(self, q, container, *args, **kwargs):
        self.q = q
        self.container = container
        super().__init__(*args, **kwargs)

    def run(self):
        global should_run

        def add_lines(lines):
            for line in lines:
                line = line.decode()
                if SHOW_CONTAINER_LOGS:
                    logger.info(line.rstrip())
                if "Fuzzing test case #" in line:
                    continue
                self.q.put(line)

        try:
            # keep getting logs
            add_lines(self.container.logs(stream=True))
        except Exception as exc:
            error_message = traceback.format_exc()
            for line in error_message.splitlines():
                self.q.put(line)
        self.q.put(None)


class CoveredFile:
    def __init__(self, workdir, start_time) -> None:
        super().__init__()
        self.found = {}
        self.path = Path(workdir)/"covered"
        self.start_time = start_time

        if self.path.is_file():
            self.path.unlink()

    def check(self):
        cur_time = time.time() - self.start_time
        cur = set(int(cf.stem) for cf in self.path.glob("*"))
        new = cur - self.found.keys()
        new = {nn: cur_time for nn in new}
        self.found = {**self.found, **new}
        return new

    def file_path(self):
        return self.path


@contextlib.contextmanager
def start_testing_container(core_to_use, trigger_file: CoveredFile, timeout):
    # get access to the docker client to start the container
    docker_client = docker.from_env()

    # Start and run the container
    container = docker_client.containers.run(
        "mutator_testing", # the image
        ["sleep", str(timeout)], # the arguments, give a max uptime for containers
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
        try:
            container.kill(2)
            for _ in range(50):
                time.sleep(.1)
                container.reload()
            while True:
                container.stop()
                logger.info(f"! Container still alive {container.name}, keep killing it.")
                time.sleep(1)
        except docker.errors.NotFound:
            # container is dead
            pass


@contextlib.contextmanager
def start_mutation_container(core_to_use, timeout, docker_run_kwargs=None):
    # get access to the docker client to start the container
    docker_client = docker.from_env()

    # Start and run the container
    container = docker_client.containers.run(
        "mutator_mutator", # the image
        ["sleep", str(timeout) if timeout is not None else 'infinity'], # the arguments, give a max uptime for containers
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
        try:
            container.kill(2)
            for _ in range(50):
                time.sleep(.1)
                container.reload()
            while True:
                container.stop()
                logger.info(f"! Container still alive {container.name}, keep killing it.")
                time.sleep(1)
        except docker.errors.NotFound:
            # container is dead
            pass


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

    timed_out = False
    sub_cmd = ["docker", "exec", *(exec_args if exec_args is not None else []), container_name, *cmd]
    proc = subprocess.Popen(sub_cmd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            close_fds=True,
            preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN))
    try:
        stdout, _ = proc.communicate(timeout=MAX_RUN_EXEC_IN_CONTAINER_TIME if timeout is None else timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, _ = proc.communicate()
        timed_out = True
        
    try:
        stdout = stdout.decode()
    except UnicodeDecodeError:
        stdout = str(stdout)

    if raise_on_error and proc.returncode != 0:
        logger.debug(f"process error (timed out: {timed_out}):", proc.args, stdout)
        raise ValueError(f"exec_in_docker failed\ntimed out: {timed_out}\nexec_code: {proc.returncode}\n{stdout}")
    
    return {'returncode': proc.returncode, 'out': stdout, 'timed_out': timed_out}
        ##################
        # alternative version using docker lib, this errors with lots of docker containers
        # https://github.com/docker/docker-py/issues/2278
        # 
        #  if exec_args is not None:
        #      raise ValueError("Exec args not supported for container exec_run.")
        #  proc = container.exec_run(cmd)
        #  if raise_on_error and proc[0] != 0:
        #      logger.info("process error: =======================",
        #              cmd,
        #              proc[1],
        #              sep="\n")
        #      raise ValueError(proc)
        #  return {'returncode': proc[0], 'out': proc[1]}


def get_mut_base_dir(mut_data: dict) -> Path:
    "Get the path to the directory containing all files related to a mutation."
    return Path("/dev/shm/mut_base/")/mut_data['prog']/printable_m_id(mut_data)


def get_mut_base_bin(mut_data: dict) -> Path:
    "Get the path to the bin that is the mutated base binary."
    return get_mut_base_dir(mut_data)/"mut_base"


def get_seed_dir(seed_base_dir, prog, fuzzer):
    """
    Gets the seed dir inside of seed_base_dir based on the program name.
    Further if there is a directory inside with the name of the fuzzer, that dir is used as the seed dir.
    Example:
    As a sanity check if seed_base_dir/<prog> contains files and directories then an error is thrown.
    seed_base_dir/<prog>/<fuzzer> exists then this dir is taken as the seed dir.
    seed_base_dir/<prog> contains only files, then this dir is the seed dir.
    """
    prog_seed_dir = seed_base_dir/prog
    seed_paths = list(prog_seed_dir.glob("*"))
    has_files = any(sp.is_file() for sp in seed_paths)
    has_dirs = any(sp.is_dir() for sp in seed_paths)
    if has_files and has_dirs:
        raise ValueError(f"There are files and directories in {prog_seed_dir}, either the dir only contains files, "
              f"in which case all files are used as seeds for every fuzzer, or it contains only directories. "
              f"In the second case the content of each fuzzer directory is used as the seeds for the respective fuzzer.")

    if has_dirs:
        # If the fuzzer specific seed dir exists, return it.
        prog_fuzzer_seed_dir = prog_seed_dir/fuzzer
        if not prog_fuzzer_seed_dir.is_dir():
            logger.warning(f"WARN: Expected seed dir to exist {prog_fuzzer_seed_dir}, using full dir instead: {prog_seed_dir}")
            return prog_seed_dir
        return prog_fuzzer_seed_dir

    elif has_files:
        # Else just return the prog seed dir.
        return prog_seed_dir

    # Has no content
    else:
        raise ValueError(f"Seed dir has not content. {prog_seed_dir}")


# returns true if a crashing input is found that only triggers for the
# mutated binary
def check_crashing_inputs(run_data, testing_container, crashing_inputs, crash_dir,
                          workdir, cur_time):
    if not crash_dir.is_dir():
        return { 'result': 'check_done', 'results': [] }
    check_start_time = time.time()

    res = {'result': 'check_done', 'results': []}
    file_ctr = 0
    new_files = list(pp for pp in crash_dir.glob("**/*") if pp not in crashing_inputs and pp.is_file())
    if new_files:
        with tempfile.TemporaryDirectory(dir=workdir) as tmp_in_dir:
            tmp_in_dir = Path(tmp_in_dir)
            assert tmp_in_dir.is_dir()
            for path in new_files:
                # mark path as seen
                crashing_inputs[path] = {}

                sym_path = tmp_in_dir/str(file_ctr)
                file_ctr += 1
                sym_path.symlink_to(path)

                path_full = str(path.resolve())
                assert str(sym_path.resolve()) == path_full

            res = base_eval_crash_check(Path(tmp_in_dir), run_data, cur_time, testing_container)
            
            # update from the symlink paths to the actual file paths
            for sub_res in res.get('results', []):
                if sub_res.get('path') is not None:
                    sub_res['path'] = Path(sub_res['path']).resolve()

    total_check_time = time.time() - check_start_time
    if total_check_time > 1:
        # log when crashing check takes more than one second
        logger.debug(f"Check crashing inputs ({new_files}) took: {total_check_time:.2f}")

    return res


def base_eval_crash_check(input_dir, run_data, cur_time, testing):
    mut_data = run_data['mut_data']
    orig_bin = Path(IN_DOCKER_WORKDIR)/"tmp"/Path(mut_data['orig_bin']).relative_to(HOST_TMP_PATH)
    args = "@@"
    workdir = run_data['workdir']
    docker_mut_bin = get_mut_base_bin(mut_data)
    result_dir = Path(workdir)/'crash_check'
    result_dir.mkdir(parents=True, exist_ok=True)
    for rf in result_dir.glob("*"):
        rf.unlink()

    # do an initial check to see if the seed files are already crashing
    (returncode, out, timed_out) = check_crashing(
        testing, input_dir, orig_bin, docker_mut_bin, args, result_dir)
    if timed_out:
        return {
            'result': 'timeout_check_crashing',
            'total_time': cur_time,
            'covered_file_seen': None,
            'timed_out': True,
            'all_logs': out[-1000:]
        }
    if returncode != 0:
        return {
            'result': 'check_crashed',
            'returncode': returncode,
            'out': out,
        }

    results = []
    for rf in result_dir.glob("*"):
        with open(rf, "rt") as f:
            res = json.load(f)
        # update result with time
        res['time'] = cur_time
        results.append(res)

    # all good report results
    return { 'result': 'check_done', 'results': results }


def update_results(results, new_results, start_time):
    if new_results['result'] not in ['check_done', 'covered', 'multiple']:
        raise ValueError(f"Error during seed crash check: {new_results}")
    new_results = new_results['results']

    has_multiple = False
    has_killed_by_seed = False
    has_timeout_by_seed = False
    has_orig_timeout_by_seed = False
    has_killed = False
    has_timeout = False

    for nr in new_results:
        res = nr['result']
        if res in ['orig_crash', 'orig_timeout', 'orig_timeout_by_seed']:
            key = (res, None)
        else:
            try:
                m_ids = tuple(sorted(set(nr['mutation_ids'])))
            except KeyError as e:
                raise ValueError(f"{e} {nr}")
            key = (res, m_ids)

            # Check that there are no results where multiple ids are found at once.
            if len(m_ids) > 1:
                has_multiple = True

        if key not in results:
            results[key] = nr

        known_result_type = False
        if res == "killed_by_seed":
            has_killed_by_seed = True
            known_result_type = True
        if res == "timeout_by_seed":
            has_timeout_by_seed = True
            known_result_type = True
        if res == "orig_timeout_by_seed":
            has_orig_timeout_by_seed = True
            known_result_type = True
        if res == "killed":
            has_killed = True
            known_result_type = True
        if res == "timeout":
            has_timeout = True
            known_result_type = True
        if res in HANDLED_RESULT_TYPES:
            known_result_type = True

        if not known_result_type:
            raise ValueError(f"Unhandled result: {res} {new_results}")

    if has_multiple:
        return {
            'result': 'multiple',
            'data': new_results,
            'total_time': time.time() - start_time,
            'all_logs': [],
        }

    if has_orig_timeout_by_seed:
        return {
            'result': 'orig_timeout_by_seed',
            'data': results,
            'total_time': time.time() - start_time,
            'all_logs': [],
        }

    if has_killed_by_seed:
        return {
            'result': 'killed_by_seed',
            'data': results,
            'total_time': time.time() - start_time,
            'all_logs': [],
        }

    if has_timeout_by_seed:
        return {
            'result': 'killed_by_seed',
            'data': results,
            'total_time': time.time() - start_time,
            'all_logs': [],
        }

    if has_killed:
        return {
            'result': 'killed',
            'data': results,
            'total_time': time.time() - start_time,
            'all_logs': [],
        }

    if has_timeout:
        return {
            'result': 'killed',
            'data': results,
            'total_time': time.time() - start_time,
            'all_logs': [],
        }
    
    return None


def get_logs(logs_queue):
    all_logs = []
    while True:
        try:
            line = logs_queue.get_nowait()
            all_logs.append(line)
        except queue.Empty:
            break
    return all_logs


def stop_container(container):
    try:
        container.kill(2)
        for _ in range(50):
            time.sleep(.1)
            container.reload()
        while True:
            container.stop()
            logger.info(f"! Container still alive {container.name}, keep killing it.")
            time.sleep(1)
    except (docker.errors.NotFound, docker.errors.APIError):
        # container is dead
        pass


# Does all the eval steps, each fuzzer eval function is based on this one.
# Compiles the mutated program and fuzzes it. Finally the eval data is returned.
def base_eval(run_data, docker_image):
    # get start time for the eval
    start_time = time.time()

    global should_run
    # extract used values
    mut_data = run_data['mut_data']
    timeout = run_data['timeout']

    prog = mut_data['prog']
    fuzzer = run_data['fuzzer']
    run_ctr = run_data['run_ctr']
    workdir = Path("/dev/shm/mutator/")/prog/printable_m_id(mut_data)/fuzzer/str(run_ctr)
    run_data['workdir'] = workdir
    crash_dir = workdir/run_data['crash_dir']
    prog_bc = mut_data['prog_bc']
    compile_args = build_compile_args(mut_data['compile_args'], IN_DOCKER_WORKDIR)
    seed_base_dir = mut_data['seed_base_dir']
    seeds = get_seed_dir(seed_base_dir, mut_data['prog'], run_data['fuzzer'])
    dictionary = mut_data['dict']
    core_to_use = run_data['used_core']

    workdir.mkdir(parents=True, exist_ok=True)

    # get path for covered files
    covered = CoveredFile(workdir, start_time)

    results = {}

    # start testing container
    with start_testing_container(core_to_use, covered, timeout + 60*60) as testing_container:

        seeds = get_seed_dir(mut_data['seed_base_dir'], mut_data['prog'], run_data['fuzzer'])

        new_results = base_eval_crash_check(seeds, run_data, time.time() - start_time, testing_container)
        # add suffix to identify seed results
        for res in new_results.get('results', []):
            res['result'] += '_by_seed'

        res = update_results(results, new_results, start_time)
        if res is not None:
            return res

        if JUST_SEEDS:
            return {
                'result': 'completed',
                'total_time': time.time() - start_time,
                'data': results,
                'all_logs': [],
            }


        # set up data for crashing inputs
        crashing_inputs = {}

        # get access to the docker client to start the container
        docker_client = docker.from_env()
        # Start and run the fuzzing container
        container = docker_client.containers.run(
            docker_image, # the image
            [
                "/home/user/eval.sh",
                str(prog_bc),
                str(compile_args),
                str(IN_DOCKER_WORKDIR/seeds),
            ], # the arguments
            environment={
                'TRIGGERED_OUTPUT': str(""),
                'TRIGGERED_FOLDER': str(covered.path),
                **({'DICT_PATH': str(Path(IN_DOCKER_WORKDIR)/dictionary)} if dictionary is not None else {}),
                **({'MUT_WITH_ASAN': '1'} if WITH_ASAN else {}),
                **({'MUT_WITH_MSAN': '1'} if WITH_MSAN else {}),
            },
            init=True,
            cpuset_cpus=str(core_to_use),
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

        fuzz_start_time = time.time()
        while time.time() < fuzz_start_time + timeout and should_run:
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
            for new_covered, at_time in covered.check().items():
                update_results(results, {
                'result': 'covered',
                    'results': [{
                        'result': 'covered',
                        'mutation_ids': [new_covered],
                        'time': at_time,
                }]}, start_time)

            # Check if a crashing input has already been found
            new_results = check_crashing_inputs(run_data, testing_container, crashing_inputs,
                                                crash_dir, workdir, time.time() - start_time)
            res = update_results(results, new_results, start_time)
            if res is not None:
                stop_container(container)
                res['all_logs'] = get_logs(logs_queue)
                return res

            # Sleep so we only check sometimes and do not busy loop
            time.sleep(CHECK_INTERVAL)

        stop_container(container)

        total_fuzz_time = time.time() - fuzz_start_time

        # as a sanity check make sure that at least the fuzzing time has passed, if not log the results
        unexpected_completion_time = None
        if total_fuzz_time < timeout or timeout + 60 < total_fuzz_time:
            unexpected_completion_time = (total_fuzz_time, timeout)

        # Also collect all remaining crashing outputs
        new_results = check_crashing_inputs(run_data, testing_container, crashing_inputs,
                                    crash_dir, workdir, time.time() - start_time)
        res = update_results(results, new_results, start_time)
        if res is not None:
            res['all_logs'] = get_logs(logs_queue)
            return res

        # Check if covered file is seen, one final time
        for new_covered, at_time in covered.check().items():
            update_results(results, {
                'result': 'covered',
                'results': [{
                    'result': 'covered',
                    'mutation_ids': [new_covered],
                    'time': at_time,
            }]}, start_time)

        all_logs = get_logs(logs_queue)

        return {
            'result': 'completed',
            'total_time': time.time() - start_time,
            'unexpected_completion_time': unexpected_completion_time,
            'data': results,
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


def aflpp_eval(run_data, run_func):
    run_data['crash_dir'] = "output/default/crashes"
    result = run_func(run_data, fuzzer_container_tag("aflpp"))
    # result['plot_data'] = get_aflpp_logs(run_data['workdir'], result['all_logs'])
    result['plot_data'] = []
    return result

def aflpp_asan_eval(run_data, run_func):
    run_data['crash_dir'] = "output/default/crashes"
    result = run_func(run_data, fuzzer_container_tag("aflpp_asan"))
    # result['plot_data'] = get_aflpp_logs(run_data['workdir'], result['all_logs'])
    result['plot_data'] = []
    return result

def afl_eval(run_data, run_func):
    run_data['crash_dir'] = "output/crashes"
    result = run_func(run_data, fuzzer_container_tag("afl"))
    # result['plot_data'] = get_aflpp_logs(run_data['workdir'], result['all_logs'])
    result['plot_data'] = []
    return result

def honggfuzz_eval(run_data, run_func):
    run_data['crash_dir'] = "crashes"
    result = run_func(run_data, fuzzer_container_tag("honggfuzz"))
    result['plot_data'] = []
    return result

def libfuzzer_eval(run_data, run_func):
    run_data['crash_dir'] = "artifacts"
    result = run_func(run_data, fuzzer_container_tag("libfuzzer"))
    result['plot_data'] = []
    return result

def libfuzzer_asan_eval(run_data, run_func):
    run_data['crash_dir'] = "artifacts"
    result = run_func(run_data, fuzzer_container_tag("libfuzzer_asan"))
    result['plot_data'] = []
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


def prepend_main_arg(args):
    return [
        {'val': "tmp/samples/common/main.cc", 'action': 'prefix_workdir'},
        *args
    ]


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
    "libfuzzer": libfuzzer_eval,
    "libfuzzer_asan": libfuzzer_asan_eval,
    "afl": afl_eval,
    "aflpp": aflpp_eval,
    "aflpp_asan": aflpp_asan_eval,
    "honggfuzz": honggfuzz_eval,
}


def check_run(run_data):
    # get start time for the eval
    start_time = time.time()

    global should_run
    # extract used values
    mut_data = run_data['mut_data']
    timeout = run_data['timeout']

    prog = mut_data['prog']
    fuzzer = run_data['fuzzer']
    run_ctr = run_data['run_ctr']
    workdir = Path("/dev/shm/mutator/")/prog/printable_m_id(mut_data)/fuzzer/str(run_ctr)
    run_data['workdir'] = workdir
    inputs_to_check = mut_data['check_run_input_dir']
    core_to_use = run_data['used_core']

    workdir.mkdir(parents=True, exist_ok=True)

    # get path for covered files
    covered = CoveredFile(workdir, start_time)

    results = {}

    # start testing container
    with start_testing_container(core_to_use, covered, timeout + 60*60) as testing_container:

        new_results = base_eval_crash_check(inputs_to_check, run_data, time.time() - start_time, testing_container)

        res = update_results(results, new_results, start_time)

        # clean up tmp dir
        shutil.rmtree(inputs_to_check)

        if res is not None:
            res['plot_data'] = []
            return res

        # did not find a crash, restart this mutation
        return {
            'result': 'retry',
            'total_time': time.time() - start_time,
            'data': results,
            'all_logs': [],
            'plot_data': [],
        }


def load_rerun_prog(rerun, prog, prog_info):
    prog_source_content = rerun.get_prog_source_content(prog)
    with open(mutation_prog_source_path(prog_info), 'wt') as f:
        f.write(prog_source_content)

    mutation_locations_content = rerun.get_mutation_locations_content(prog)
    with open(mutation_locations_path(prog_info), 'wt') as f:
        f.write(mutation_locations_content)


def instrument_prog(container, prog_info):
    # Compile the mutation location detector for the prog.
    args = ["./run_mutation.py",
            "-bc", prog_info['orig_bc'],
            *(["-cpp"] if prog_info['is_cpp'] else ['-cc']),  # specify compiler
            "--bc-args=" + build_compile_args(prog_info['bc_compile_args'], '/home/mutator'),
            "--bin-args=" + build_compile_args(prepend_main_arg(prog_info['bin_compile_args']), '/home/mutator')]
    try:
        run_exec_in_container(container.name, True, args)
    except Exception as e:
        logger.warning(f"Exception during instrumenting {e}")
        raise e


# Find functions that are reachable from fnA
def find_reachable(call_g, fnA, reachable_keys=None, found_so_far=None):
    if reachable_keys is None: reachable_keys = {}
    if found_so_far is None: found_so_far = set()

    for fnB in call_g[fnA]:
        if fnB in found_so_far: continue
        found_so_far.add(fnB)
        if fnB not in call_g: continue
        if fnB in reachable_keys:
            for k in reachable_keys[fnB]:
                found_so_far.add(k)
        else:
            keys = find_reachable(call_g, fnB, reachable_keys, found_so_far)
    return found_so_far


# Produce reachability dictionary given the call graph.
# For each function, we have functions that are reachable from it.
def reachable_dict(call_g):
    reachable = {}
    for fnA in call_g:
        keys = find_reachable(call_g, fnA, reachable)
        reachable[fnA] = keys
    return reachable


# Given the call graph, produce the reachability matrix with 1 for reachability
# and 0 for non reachability. The rows and columns are locations
def reachability_matrix(call_g):
    reachability = reachable_dict(call_g)
    rows = list(reachability.keys())
    columns = list(reachability.keys())
    matrix = []
    for i in rows:
        matrix_row = []
        for j in columns:
            matrix_row.append(1 if i in reachability[j] or j in reachability[i] or i == j else 0)
            #matrix_row.append(1 if i in reachability[j] or i == j else 0)
        matrix.append(matrix_row)
    return matrix, columns


MAX_MUTATIONS_PER_FUNCTION = 10_000


def location_mutation_mapping(mutations):
    loc_mut_map = defaultdict(list)
    for mut in mutations:
        mut_id = mut[0]
        fn = mut[3][int(mut_id)]['funname']
        loc_mut_map[fn].append(mut_id)

    # If a function has more than 10000 mutations, ignore that function.
    for fn, muts in loc_mut_map.items():
        if len(muts) > MAX_MUTATIONS_PER_FUNCTION:
            logger.warning(f"WARN: got a function: ({fn}) with more than {MAX_MUTATIONS_PER_FUNCTION} mutations, skipping it.")
            del loc_mut_map[fn]

    return {**loc_mut_map}


def load_call_graph(callgraph, mutants):
    my_g = {}
    called = {}

    for fn_a, fn_b in callgraph:
        if fn_a not in my_g: my_g[fn_a] = []
        my_g[fn_a].append(fn_b)
        called[fn_b] = True

    # now, populate leaf functions
    for b in called:
        if b not in my_g: my_g[b] = []

    unknown_funcs = [uf for uf in mutants.keys() if uf not in my_g]
    # add unknown functions to callgraph
    for uf in unknown_funcs:
        my_g[uf] = []

    # mark all unknown functions as reachable by all
    for reachable in my_g.values():
        reachable.extend(unknown_funcs)
    return my_g


def pop_mutant(mutants, eligible, has_mutants, indices, matrix, keys):
    """
    Get a single mutant id, choice is made from the eligible locations and the corresponding
    index of has_mutants is set to false if no mutants are remaining for that location.
    """
    chosen_idx = np.random.choice(indices[eligible])
    chosen = keys[chosen_idx]
    possible_mutants = mutants[str(chosen)]
    mut = int(possible_mutants.pop())
    if len(possible_mutants) == 0:
        has_mutants[chosen_idx] = False
    # Remove locations reachable by the chosen location from the eligible list
    eligible &= np.invert(matrix[chosen_idx])
    # Remove location that can reach the chosen location from the eligible list
    eligible &= np.invert(matrix[:, chosen_idx])
    return mut

def find_supermutants(matrix, keys, mutants):
    indices = np.arange(len(matrix))
    # for each index a boolean value if there are any mutants remaining
    has_mutants = np.array([bool(mutants.get(keys[ii])) for ii in range(len(matrix))])

    # the selected supermutants, each entry contains a list of mutants that are a supermutant
    supermutants = []

    while True:
        # continue while there are more mutants remaining
        available = np.array(has_mutants, copy=True)
        if not np.any(available):
            break

        # mutants selected for the current supermutant
        selected_mutants = []

        # while more mutants can be added to the supermutants
        while np.any(available):
            mutant = pop_mutant(
                # these arguments are changed in the called function
                mutants, available, has_mutants,
                # these are not
                indices, matrix, keys)
            selected_mutants.append(mutant)
            if len(selected_mutants) >= MAX_SUPERMUTANT_SIZE:
                break

        supermutants.append(selected_mutants)
    return supermutants


UNKNOWN_FUNCTION_IDENTIFIER = ":unnamed:"
SPLITTER = " | "
ENTRY = "LLVMFuzzerTestOneInput"

def augment_graph(orig_graph: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """
    Takes the graph and augments it by replacing unknown function calls with all possible calls.
    :param orig_graph:
    :return:
    """
    result = dict()
    mapping = dict()
    # first get an initial mapping of the result set and collect all known functions
    for key in orig_graph.keys():
        key_splitted = key.split(SPLITTER)[:-1]
        funname = key_splitted[0]
        result[funname] = list()
        mapped_head = mapping.setdefault(tuple(key_splitted[1:]), list())
        mapped_head.append(funname)

    #then go over all call locations and look for replacements for unknown calls and just add known calls
    for function, call_locations in orig_graph.items():
        new_locations = set()
        for call_location in call_locations:
            call_splitted = call_location.split(SPLITTER)[:-1]
            called_funname = call_splitted[0]
            if called_funname == UNKNOWN_FUNCTION_IDENTIFIER:
                call_types = tuple(call_splitted[1:])
                if call_types in mapping:
                    for fun in mapping[call_types]:
                        new_locations.add(fun)
            else:
                if called_funname in result:
                    new_locations.add(called_funname)

        result[function.split(SPLITTER)[0]] = list(new_locations)

    return result


def flatten_callgraph(call_graph):
    caller_callee = []
    for caller, callees in call_graph.items():
        for callee in callees:
            caller_callee.append((caller, callee))
    return caller_callee


def get_callgraph(prog_info, graph_info):
    with open(mutation_locations_graph_path(prog_info), 'rt') as f:
        call_graph = json.load(f)
    graph_info['call_graph_raw'] = call_graph
    call_graph = augment_graph(call_graph)
    graph_info['call_graph_augmented'] = call_graph
    return flatten_callgraph(call_graph)


def get_supermutations(prog_info, mutations):
    graph_info = {}
    callgraph = get_callgraph(prog_info, graph_info)

    loc_mut_map = location_mutation_mapping(mutations)
    callgraph = load_call_graph(callgraph, loc_mut_map)

    total_mutants =  sum([len(loc_mut_map[loc]) for loc in loc_mut_map])

    matrix, keys = reachability_matrix(callgraph)
    entry_idx = keys.index(ENTRY)
    assert entry_idx is not None
    matrix = np.array(matrix, dtype=bool)
    reachable_mask = matrix[entry_idx]

    # only get reachable functions
    matrix = matrix[reachable_mask][:,reachable_mask]
    keys = np.array(keys)
    unreachable_functions = list(keys[~reachable_mask])
    keys = keys[reachable_mask]


    # assert that everything has the right dimensions
    assert len(matrix) == len(matrix[0]) == len(keys)
    logger.info(f'Computed reachability, there are {len(callgraph)} functions, {len(keys)} reachable.')

    supermutants = find_supermutants(matrix, keys, loc_mut_map)

    sum_reachable = sum((len(sm) for sm in supermutants))
    min_reachable = min((len(sm) for sm in supermutants))
    max_reachable = max((len(sm) for sm in supermutants))
    avg_reachable = sum_reachable / len(supermutants)
    logger.info(f"Supermutants for reachable {len(supermutants)} (reduction: {sum_reachable / len(supermutants):.2f}) containing mutations:\n"
          f"total: {sum_reachable}, avg: {avg_reachable:.2f}, min: {min_reachable}, max: {max_reachable}")

    supermutants_unreachable = [(ff, mm) for ff, muts in loc_mut_map.items() for mm in muts]

    # split up unreachable mutations making sure that no
    # mutations in the same function are in the same supermutant
    func_to_mutants = defaultdict(list)
    for ff, mm in supermutants_unreachable:
        func_to_mutants[ff].append(mm)

    highest_mut_func_count = max(len(mm) for mm in func_to_mutants.values())
    new_supermutants = []
    for ii in range(highest_mut_func_count):
        new_supermutants.append([])

    ii = 0
    for ii in range(highest_mut_func_count):
        for ff, mm_in_ff in func_to_mutants.items():
            try:
                mm = mm_in_ff.pop(0)
            except IndexError:
                continue
            assert ff in unreachable_functions
            new_supermutants[ii].append(mm)

    # if the number of mutants per supermutant is too large, split them up
    MAX_ACCEPTABLE_SUPERMUTANT_SIZE = 200
    found_too_large = True
    while found_too_large:
        found_too_large = False
        for ii in range(len(new_supermutants)):
            ns = new_supermutants[ii]
            if len(ns) > MAX_ACCEPTABLE_SUPERMUTANT_SIZE:
                found_too_large = True
                chunk_0 = ns[:len(ns)//2]
                chunk_1 = ns[len(ns)//2:]
                new_supermutants[ii] = chunk_0
                new_supermutants.append(chunk_1)
    
    for ns in new_supermutants:
        assert len(ns) <= MAX_ACCEPTABLE_SUPERMUTANT_SIZE

    logger.info(f'There are {len(supermutants_unreachable)} mutants in unreachable functions.')
    supermutants.extend(new_supermutants)

    # assert that all mutants have been assigned
    assert total_mutants == sum((len(sm) for sm in supermutants)), f"{total_mutants} == {sum((len(sm) for sm in supermutants))}"
    logger.info(f"Made {len(supermutants)} supermutants out of {total_mutants} mutations "
          f"a reduction by {total_mutants / len(supermutants):.2f} times.")
    return supermutants, graph_info


def get_all_mutations(stats, mutator, progs, seed_base_dir, rerun, rerun_mutations):
    if rerun:
        rerun = ReadStatsDb(rerun)

    if rerun_mutations is not None:
        with open(rerun_mutations, 'rt') as f:
            rerun_mutations = json.load(f)

    all_mutations = []
    # For all programs that can be done by our evaluation
    for prog in progs:
        try:
            prog_info = PROGRAMS[prog]
        except Exception as err:
            logger.error(err)
            logger.error(f"Prog: {prog} is not known, known progs are: {PROGRAMS.keys()}")
            sys.exit(1)
        start = time.time()
        logger.info("="*50)
        logger.info(f"Compiling base and locating mutations for {prog}")

        if rerun is None:
            instrument_prog(mutator, prog_info)
        else:
            load_rerun_prog(rerun, prog, prog_info)

        stats.new_prog(EXEC_ID, prog, prog_info)

        # get info on mutations
        with open(mutation_locations_path(prog_info), 'rt') as f:
            mutation_data = json.load(f)

        if FILTER_MUTATIONS:
            if rerun is not None:
                # .opt_mutate is not restored so we can not do a coverage measurement
                # If this is needed either figure out how to create .opt_mutate from .bc and .mutationlocations
                # or also restore it.
                raise NotImplementedError("Can not filter mutations on a rerun.")
            # Run the seeds through the mutation detector
            seeds = Path(seed_base_dir/prog)
            logger.info("Filtering mutations, running all seed files.")
            filtered_mutations = measure_mutation_coverage(mutator, prog_info, seeds)

        mutations = list((str(p['UID']), prog, prog_info, mutation_data) for p in mutation_data)

        # Remove mutations for functions that should not be mutated
        omit_functions = prog_info['omit_functions']
        mutations = [mm for mm in mutations if mm[3][int(mm[0])]['funname'] not in omit_functions]

        # If rerun_mutations is specified, collect those mutations
        if rerun_mutations is not None:
            mutations_dict = {int(mm[0]): mm for mm in mutations}
            filtered_mutations = []
            rerun_mutations_for_prog = rerun_mutations[prog]['ids']
            for mtu in rerun_mutations_for_prog:
                assert mtu in mutations_dict.keys(), "Can not find specified rerun mutation id in mutations for prog."
                filtered_mutations.append(mutations_dict[mtu])
            mutations = filtered_mutations

        logger.info(f"Found {len(mutations)} mutations for {prog}")
        for mut in mutations:
            stats.new_mutation(EXEC_ID, {
                'prog': mut[1],
                'mutation_id': mut[0],
                'mutation_data': mut[3][int(mut[0])],
            })

        if FILTER_MUTATIONS:
            logger.info("Updating for filtered mutations, checking the found mutations.")
            all_mutation_ids = set((p['UID'] for p in mutation_data))
            filtered_mutation_ids = set((int(m) for m in filtered_mutations))
            assert len(filtered_mutation_ids - all_mutation_ids) == 0, 'Filtered mutation ids contain ids not in all ids.'
            mutations = list((str(mut_id), prog, prog_info, mutation_data) for mut_id in filtered_mutations)
            logger.info(f"After filtering: found {len(mutations)} mutations for {prog}")

        if rerun:
            supermutations_raw = rerun.get_supermutations(prog)
            expected_exec_id = supermutations_raw[0]['exec_id']
            len_sm = max(sm['super_mutant_id'] for sm in supermutations_raw) + 1
            mutations_set = set(int(mm[0]) for mm in mutations)
            supermutations = [[] for _ in range(len_sm)]
            for sm in supermutations_raw:
                assert sm['exec_id'] == expected_exec_id
                mut_id = sm['mutation_id']
                super_mut_id = sm['super_mutant_id']

                # if we specify which mutations to rerun only recreate those supermutants
                # a check if these mutation ids exist happened when collecting the mutation data
                if rerun_mutations is not None:
                    if mut_id not in mutations_set:
                        continue
                else:
                    # check that the mutation is actually available in the rerun
                    assert mut_id in mutations_set

                supermutations[super_mut_id].append(mut_id)

            # Not all supermutants are required if a specific set of mutations is specified.
            if rerun_mutations is not None:
                mode = rerun_mutations[prog]['mode']
                if mode == 'single':
                    logger.info("Rerun with single mode!")
                    supermutations = [[mm] for mm in chain(*supermutations)]
                elif mode == 'keep':
                    logger.info("Rerun keeping supermutations!")
                    supermutations = [sm for sm in supermutations if len(sm) > 0]
                else:
                    raise ValueError("Unknown rerun_mutations mode:", mode)
            
        else:
            supermutations, graph_info = get_supermutations(prog_info, mutations)
            stats.new_supermutant_graph_info(EXEC_ID, prog, graph_info)


        for ii, sm in enumerate(supermutations):
            stats.new_initial_supermutant(EXEC_ID, prog, ii, sm)

        mutations = list((sm, prog, prog_info, mutation_data) for sm in supermutations)

        all_mutations.extend(mutations)
        logger.info(f"Preparations for {prog} took: {time.time() - start:.2f} seconds")

    return all_mutations

def sequence_mutations(all_mutations):
    """
    Randomize order mutations in a way to get the most diverse mutations first.
    Diverse as in the mutations are from different progs and different types.
    """
    random.shuffle(all_mutations)

    #  grouped_mutations = defaultdict(list)
    #  for mut in all_mutations:
    #      prog = mut[1]
    #      mutation_id = mut[0]
    #      mutation_type = mut[3][int(mutation_id)]['type']
    #      grouped_mutations[(prog, mutation_type)].append(mut)
    #
    #  sequenced_mutations = []
    #
    #  while len(grouped_mutations) > 0:
    #      empty_lists = []
    #      for key, mut_list in grouped_mutations.items():
    #          sequenced_mutations.append(mut_list.pop())
    #          if len(mut_list) == 0:
    #              empty_lists.append(key)
    #      for empty in empty_lists:
    #          del grouped_mutations[empty]
    # 
    # return sequenced_mutations
    return all_mutations

def printable_m_id(mut_data):
    return f"S{mut_data['supermutant_id']}"

# Generator that first collects all possible runs and adds them to stats.
# Then yields all information needed to start a eval run
def get_all_runs(stats, fuzzers, progs, seed_base_dir, timeout, num_repeats, rerun, rerun_mutations):
    with start_mutation_container(None, 24*60*60) as mutator:
        all_mutations = get_all_mutations(stats, mutator, progs, seed_base_dir, rerun, rerun_mutations)

        all_mutations = sequence_mutations(all_mutations)

        # measure coverage by seeds
        if not SKIP_LOCATOR_SEED_CHECK:
            for prog in progs:
                prog_info = PROGRAMS[prog]
                for fuzzer in fuzzers:
                    seeds = get_seed_dir(seed_base_dir, prog, fuzzer)
                    seed_covered_mutations = measure_mutation_coverage(mutator, prog_info, seeds)
                    logger.info(f"Measured locator seed coverage for: {prog} {fuzzer} {seeds} => {len(seed_covered_mutations)}")
                    stats.locator_seed_covered(EXEC_ID, prog, fuzzer, seed_covered_mutations)

        all_runs = []

        # Go through the mutations
        for m_id, prog, prog_info, mutation_data in all_mutations:
            # Gather all data for a mutation
            # Arguments on how to execute the binary
            args = "@@"
            # Original binary to check if crashing inputs also crash on
            # unmodified version
            orig_bin = str(Path(prog_info['orig_bin']).absolute())

            mut_data = {
                'orig_bc': prog_info['orig_bc'],
                'compile_args': prog_info['bc_compile_args'] + prog_info['bin_compile_args'],
                'is_cpp': prog_info['is_cpp'],
                'args': args,
                'prog': prog,
                'dict': prog_info['dict'],
                'orig_bin': orig_bin,
                'seed_base_dir': seed_base_dir,
                'supermutant_id': stats.next_supermutant_id(),
                'mutation_ids': m_id,
                'mutation_data': [mutation_data[int(mut_id)] for mut_id in m_id],
            }

            # For each fuzzer gather all information needed to start a eval run
            fuzzer_runs = []
            for fuzzer in fuzzers:
                try:
                    eval_func = FUZZERS[fuzzer]
                except Exception as err:
                    logger.info(err)
                    logger.info(f"Fuzzer: {fuzzer} is not known, known fuzzers are: {FUZZERS.keys()}")
                    sys.exit(1)
                # Get the working directory based on program and mutation id and
                # fuzzer, which is a unique path for each run
                for run_ctr in range(num_repeats):
                    # gather all info
                    run_data = {
                        'run_ctr': run_ctr,
                        'fuzzer': fuzzer,
                        'eval_func': eval_func,
                        'timeout': int(timeout)*60,
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
    except OSError as err:
        logger.info(f"Could not clean up {mut_base_dir}: {err}")


def split_up_supermutant(multi, all_muts):
    """
    Split up the mutants listed in all_muts, into as many chunks as there are mutants in multi, making sure that the
    mutants listed in multi end up in different chunks. This can be used to split up a supermutant where
    multiple mutations are covered at once.
    """
    multi = set(chain(*multi))
    all_muts = set(all_muts)
    assert all_muts & multi == multi, f"Not all covered mutations are in the possible mutations, something is wrong. " \
                                      f"all_muts: {all_muts}, multi: {multi}"
    others = all_muts - multi

    chunk_size = int(len(others) / len(multi)) + 1
    multi = list(multi)
    others = list(others)

    mut_chunks = []

    for ii, cc in zip_longest(range(len(multi)), list(chunks(others, chunk_size)), fillvalue=[]):
        chosen = [multi[ii]] + cc
        mut_chunks.append(chosen)

    logger.debug(f"{multi}\n{mut_chunks}\n{all_muts}")
    assert len(list(chain(*mut_chunks))) == len(all_muts), f"mut_chunks: {len(list(chain(*mut_chunks)))}, all_muts: {len(all_muts)}"
    assert set(chain(*mut_chunks)) == all_muts, f"mut_chunks: {mut_chunks}, all_muts: {all_muts}"
    return mut_chunks


def split_up_supermutant_by_distance(mutation_ids: List[int]) -> Tuple[List[int], List[int]]:
    m_ids = [int(mm) for mm in mutation_ids]
    chunk_1, chunk_2 = [], []
    for ii, m_id in enumerate(sorted(m_ids)):
        if ii % 2 == 0:
            chunk_1.append(m_id)
        else:
            chunk_2.append(m_id)

    return chunk_1, chunk_2


HANDLED_RESULT_TYPES = set([
    'covered', 'covered_by_seed',
    'killed', 'killed_by_seed',
    'timeout', 'timeout_by_seed',
    'orig_timeout', 'orig_crash',
])

def has_result(mut_id, results, to_search):
    unhandled_search_types = set(to_search) - HANDLED_RESULT_TYPES
    assert unhandled_search_types == set(), f'Unhandled search types: {unhandled_search_types}'
    unhandled_result_types = set(rr['result'] for rr in results) - HANDLED_RESULT_TYPES
    assert unhandled_result_types == set(), f'Unhandled result types: {unhandled_result_types}'

    for res in [rr for rr in results if rr['result'] in [*to_search]]:
        if mut_id in res['mutation_ids']:
            return res
    return None


def copy_fuzzer_inputs(data):
    tmp_dir = Path(tempfile.mkdtemp(dir="/dev/shm/mutator_tmp/"))
    found_inputs = SEED_HANDLERS[data['fuzzer']](data['workdir'])
    for fi in found_inputs:
        file_hash = hash_file(fi)
        dest_path = tmp_dir/file_hash
        shutil.copyfile(fi, dest_path)
    return tmp_dir


def record_supermutant_multi(stats, mut_data, results, fuzzer, run_ctr, description):
    multies = set()
    for rr in results:
        try:
            mut_ids = tuple(sorted(rr['mutation_ids']))
        except KeyError:
            continue
        result = rr['result']
        entry = (result, mut_ids)
        if len(mut_ids) > 1 and entry not in multies:
            multies.add(entry)

    stats.new_supermutant_multi(EXEC_ID, mut_data, multies, fuzzer, run_ctr, description)


# Helper function to wait for the next eval run to complete.
# Also updates the stats and which cores are currently used.
# If `break_after_one` is true, return after a single run finishes.
def handle_run_result(stats, prepared_runs, active_mutants, run_future, data):
    mut_data = data['mut_data']
    prog_bc = mut_data['prog_bc']
    prog = mut_data['prog']
    try:
        # if there was no exception get the data
        run_result = run_future.result()
    except Exception:
        # if there was an exception record it
        trace = traceback.format_exc()
        mutation_ids = mut_data['mutation_ids']
        if len(mutation_ids) > 1:
            logger.info(f"= run ###:      {mut_data['prog']}:{printable_m_id(mut_data)}:{data['fuzzer']} Run crashed, retrying with less mutations ...")
            chunk_1, chunk_2 = split_up_supermutant_by_distance(mutation_ids)
            recompile_and_run(prepared_runs, data, stats.next_supermutant_id(), chunk_1)
            recompile_and_run(prepared_runs, data, stats.next_supermutant_id(), chunk_2)
        else:
            mut_id = list(mutation_ids)[0]
            stats.run_crashed(EXEC_ID, mut_data['prog'], mut_id, data['run_ctr'], data['fuzzer'], trace)
            stats.done_run('crashed', EXEC_ID, mut_data['prog'], mut_id, data['run_ctr'], data['fuzzer'])
            logger.info(f"= run ###:      {mut_data['prog']}:{printable_m_id(mut_data)}:{data['fuzzer']}\n{trace}")
    else:
        result_type = run_result['result']
        if result_type == 'multiple':

            if STOP_ON_MULTI:
                raise ValueError("Got multiple.")

            multi = run_result['data']
            record_supermutant_multi(stats, mut_data, multi, data['fuzzer'], data['run_ctr'], 'multiple_result')
            multi_ids = set([tuple(sorted(mm['mutation_ids'])) for mm in multi if len(mm['mutation_ids']) > 1])
            logger.info(f"= run (multi):  {mut_data['prog']}:{printable_m_id(mut_data)}:{multi_ids}")
            all_mutations = mut_data['mutation_ids']
            new_supermutants = split_up_supermutant(multi_ids, all_mutations)

            # start the new split up supermutants
            for sm in new_supermutants:
                recompile_and_run(prepared_runs, data, stats.next_supermutant_id(), sm)

        elif result_type == 'orig_timeout_by_seed':
            logger.info(f"! orig timeout by seed! {printable_m_id(mut_data)}")
            for mut_id in mut_data['mutation_ids']:
                stats.run_crashed(EXEC_ID, mut_data['prog'], mut_id, data['run_ctr'], data['fuzzer'],
                    'orig timeout by seed!!!\n' + str(run_result))
                stats.done_run('orig_timeout_by_seed', EXEC_ID, mut_data['prog'], mut_id, data['run_ctr'], data['fuzzer'])
        elif result_type == 'retry':
            mut_data = copy.deepcopy(mut_data)
            del mut_data['check_run']
            del mut_data['check_run_input_dir']
            recompile_and_run(prepared_runs, data, stats.next_supermutant_id(), mut_data['mutation_ids'])
        elif result_type == 'killed_by_seed':
            logger.info(f"= run (seed):   {mut_data['prog']}:{printable_m_id(mut_data)}:{data['fuzzer']}")

            all_mutation_ids = set(mut_data['mutation_ids'])
            assert len(all_mutation_ids) > 0

            total_time = run_result['total_time']
            results = sorted(run_result['data'].values(), key=lambda x: x['time'])
            del run_result

            record_supermutant_multi(stats, mut_data, results, data['fuzzer'], data['run_ctr'], 'killed_by_seed')

            killed_mutants = set()
            for mut_id in all_mutation_ids:
                seed_covered = 1 if has_result(mut_id, results, ['covered_by_seed']) else 0
                timeout = 1 if has_result(mut_id, results, ['timeout_by_seed']) else None
                killed = has_result(mut_id, results, ['killed_by_seed'])

                if killed or timeout:
                    stats.new_seeds_executed(
                        EXEC_ID, prog, mut_id, data['run_ctr'], data['fuzzer'],
                        seed_covered, timeout, total_time)

                    if killed is not None:
                        stats.new_seed_crashing_inputs(EXEC_ID, prog, mut_id, data['fuzzer'], [killed])

                    killed_mutants |= set([mut_id])
                    stats.done_run('killed_by_seed', EXEC_ID, mut_data['prog'], mut_id, data['run_ctr'], data['fuzzer'])

            assert len(killed_mutants) >= 1, f"Expected at least one mutant to be killed.: {results}"
            assert len(all_mutation_ids & killed_mutants) == len(killed_mutants), "No mutations in common"

            remaining_mutations = all_mutation_ids - killed_mutants
            if len(remaining_mutations) > 0:
                recompile_and_run(prepared_runs, data, stats.next_supermutant_id(), remaining_mutations)
            else:
                logger.info(f"! no more mutations (all: {len(all_mutation_ids)} killed: {len(killed_mutants)})")
        elif result_type == 'killed':
            def record_seed_result(seed_covered, seed_timeout, prog, fuzzer, run_ctr, mut_id):
                stats.new_seeds_executed(
                    EXEC_ID,
                    prog,
                    mut_id,
                    run_ctr,
                    fuzzer,
                    seed_covered,
                    seed_timeout,
                    None)

            def record_run_done(plot_data, covered_time, total_time, prog, fuzzer, run_ctr, mut_id):
                stats.new_run_executed(
                    plot_data,
                    EXEC_ID,
                    run_ctr,
                    prog,
                    mut_id,
                    fuzzer,
                    covered_time,
                    total_time)

            def record_run_timeout(time, path, orig_cmd, mut_cmd, prog, fuzzer, run_ctr, mut_id):
                data = {
                    'time': time,
                    'path': path,
                    'orig_returncode': None,
                    'mut_returncode': None,
                    'orig_cmd': orig_cmd,
                    'mut_cmd': mut_cmd,
                    'orig_res': None,
                    'mut_res': None,
                    'orig_timeout': None,
                    'timeout': 1
                }
                stats.new_crashing_inputs(
                    [data],
                    EXEC_ID,
                    prog,
                    mut_id,
                    run_ctr,
                    fuzzer)

            logger.info(f"= run (killed): {prog}:{printable_m_id(mut_data)}:{data['fuzzer']}")
            # killed by the fuzzer (but not already by seeds)
            # but the run is not completed, filter out the killed mutations and try again with remaining
            total_time = run_result['total_time']
            plot_data = run_result['plot_data']
            results = sorted(run_result['data'].values(), key=lambda x: x['time'])
            del run_result

            record_supermutant_multi(stats, mut_data, results, data['fuzzer'], data['run_ctr'], 'killed')

            all_mutation_ids = set(int(mm) for mm in mut_data['mutation_ids'])
            assert len(all_mutation_ids) > 0
            result_ids = set(int(mm) for rr in results for mm in rr['mutation_ids'])
            assert len(result_ids - set(all_mutation_ids)) == 0, f"{sorted(result_ids)}\n{sorted(all_mutation_ids)}"

            if any([rr for rr in results if rr['result'] in ['orig_crash', 'orig_timeout']]):
                logger.warning('Original binary crashed or timed out, retrying. If this problem persists, check the setup.')
                recompile_and_run(prepared_runs, data, stats.next_supermutant_id(), all_mutation_ids)
            else:
                # check if there are multi covered kills
                multi_kills = []
                for res in [rr for rr in results if rr['result'] in ['killed']]:
                    mut_ids = res['mutation_ids']
                    if len(mut_ids) > 1:
                        multi_kills.append(res)

                if multi_kills:
                    # there is at at least one input that causes a crash where multiple mutations are involved
                    # to make sure that fuzzers correctly kill mutations, recheck the inputs on those mutations
                    # individually

                    # there can also be mutants that are killed but not part of a multi kill
                    # so just get every mutation that was killed and recheck all of them
                    killed_mutants: set[int] = set(chain(*[rr['mutation_ids']
                                    for rr in results
                                    if rr['result'] in ['killed']]))
                    
                    # get the remaining mutations
                    cur_mutations: set[int] = set((int(m_id) for m_id in mut_data['mutation_ids']))
                    assert len(killed_mutants) >= 1
                    assert len(cur_mutations & killed_mutants) == len(killed_mutants), f"Killed mutations not in supermutant: {cur_mutations}, {killed_mutants}"
                    remaining_mutations = cur_mutations - killed_mutants

                    logger.info(f"! multi, killed {len(killed_mutants)} remaining {len(remaining_mutations)}")

                    # start check run for each killed mutation
                    for km in killed_mutants:
                        tmp_dir = copy_fuzzer_inputs(data)
                        start_check_run(prepared_runs, data, stats.next_supermutant_id(), [km], tmp_dir)

                    # start a new run for a supermutant containing all remaining mutations
                    if len(remaining_mutations) > 0:
                        recompile_and_run(prepared_runs, data, stats.next_supermutant_id(), remaining_mutations)
                    else:
                        logger.info(f"! no more mutations")

                else:
                    killed_mutants = set()
                    for mut_id in all_mutation_ids:
                        # no mutation should have been killed by seeds or there is a bug
                        if has_result(mut_id, results, ['killed_by_seed']):
                            raise ValueError("killed_by_seed result in killed run result.")

                        # here we are only interested in the mutations that have been killed
                        # the other mutations are tried again
                        killed = has_result(mut_id, results, ['killed'])
                        timeout = has_result(mut_id, results, ['timeout'])
                        if not (killed or timeout):
                            continue

                        killed_mutants.add(mut_id)

                        # record covered by seed 
                        seed_covered = has_result(mut_id, results, ['covered_by_seed'])
                        if seed_covered:
                            seed_covered = seed_covered.get('time', None)
                        seed_timeout = 1 if has_result(mut_id, results, ['timeout_by_seed']) else None
                        record_seed_result(seed_covered, seed_timeout, prog, data['fuzzer'], data['run_ctr'], mut_id)

                        # record covered
                        covered_time = has_result(mut_id, results, ['covered', 'killed'])
                        if covered_time:
                            covered_time = covered_time.get('time', None)
                        record_run_done(plot_data, covered_time, total_time, prog, data['fuzzer'], data['run_ctr'], mut_id)

                        # record killed or timeout
                        if killed:
                            killed = copy.deepcopy(killed)
                            killed['orig_timeout'] = None
                            killed['timeout'] = None
                            stats.new_crashing_inputs(
                                [killed],
                                EXEC_ID,
                                prog,
                                mut_id,
                                data['run_ctr'],
                                data['fuzzer'])
                            stats.done_run('killed', EXEC_ID, mut_data['prog'], mut_id, data['run_ctr'], data['fuzzer'])
                        elif timeout:
                            record_run_timeout(timeout['time'], timeout['path'], [], timeout['args'],
                            prog, data['fuzzer'], data['run_ctr'], mut_id)
                            stats.done_run('timeout', EXEC_ID, mut_data['prog'], mut_id, data['run_ctr'], data['fuzzer'])
                            
                        result_types = set(rr['result'] for rr in results)
                        unknown_result_types = result_types - HANDLED_RESULT_TYPES
                        assert unknown_result_types == set(), f"Unknown result types: {unknown_result_types}\n{results}"

                    if len(killed_mutants) == 0:
                        if len(all_mutation_ids) == 1:
                            # There is only one mutation that could have been found.
                            # If there is a timeout result mark that mutation as killed, we just didn't get the triggered file.
                            timeout = None
                            for rr in results:
                                if rr['result'] == 'timeout':
                                    timeout = rr
                                    break
                            if timeout:
                                mut_id = list(all_mutation_ids)[0]
                                
                                seed_covered = has_result(mut_id, results, ['covered_by_seed'])
                                if seed_covered:
                                    seed_covered = seed_covered.get('time', None)
                                seed_timeout = 1 if has_result(mut_id, results, ['timeout_by_seed']) else None
                                record_seed_result(seed_covered, seed_timeout,
                                    prog, data['fuzzer'], data['run_ctr'], mut_id)

                                covered_time = has_result(mut_id, results, ['covered', 'killed'])
                                if covered_time:
                                    covered_time = covered_time.get('time', None)
                                record_run_done(plot_data, covered_time, total_time,
                                    prog, data['fuzzer'], data['run_ctr'], mut_id)

                                record_run_timeout(timeout['time'], timeout['path'], [], timeout['args'],
                                    prog, data['fuzzer'], data['run_ctr'], mut_id)
                                stats.done_run('timeout_no_trigger', EXEC_ID, mut_data['prog'], mut_id, data['run_ctr'], data['fuzzer'])
                            else:
                                # No timeout seen, mark run as crashed
                                results_str = '\n'.join(str(rr) for rr in results)
                                msg = f'Killed run result but no killed mutations found:\n{results_str}\n{all_mutation_ids}'
                                stats.run_crashed(EXEC_ID, mut_data['prog'], mut_id, data['run_ctr'], data['fuzzer'], msg)
                                logger.info(f"= run ###:      {mut_data['prog']}:{printable_m_id(mut_data)}:{data['fuzzer']} Killed run result but no killed mutations found.")
                                logger.debug(msg)
                                stats.done_run('crashed_no_trigger', EXEC_ID, mut_data['prog'], mut_id, data['run_ctr'], data['fuzzer'])
                        else:
                            # Multiple mutations, split up and try again
                            logger.info(f"= run ###:      {mut_data['prog']}:{printable_m_id(mut_data)}:{data['fuzzer']} Killed run result but no killed mutations found, retrying ...")
                            chunk_1, chunk_2 = split_up_supermutant_by_distance(all_mutation_ids)
                            recompile_and_run(prepared_runs, data, stats.next_supermutant_id(), chunk_1)
                            recompile_and_run(prepared_runs, data, stats.next_supermutant_id(), chunk_2)
                    else:
                        # find and start the new supermutant with the remaining mutations
                        cur_mutations: set[int] = set((int(m_id) for m_id in mut_data['mutation_ids']))
                        assert len(cur_mutations & killed_mutants) == len(killed_mutants), "No mutations in common"

                        remaining_mutations = cur_mutations - killed_mutants
                        if len(remaining_mutations) > 0:
                            recompile_and_run(prepared_runs, data, stats.next_supermutant_id(), remaining_mutations)
                        else:
                            logger.info(f"! no more mutations")
            
        elif result_type == 'completed':
            if run_result['unexpected_completion_time']:
                logs = ''.join([ll for ll in run_result['all_logs'] if ll])

                times = run_result['unexpected_completion_time']
                actual_time = times[0]
                expected_time = times[1]

                # if there are multiple mutation ids start a separate run for each of them
                # else mark the mutation as as crashing
                mutation_ids = mut_data['mutation_ids']
                assert len(mutation_ids) >= 1
                if len(mutation_ids) > 1:
                    logger.info(f"= run ###:      {mut_data['prog']}:{printable_m_id(mut_data)}:{data['fuzzer']}\n"
                        f"rerunning in chunks (unexpected completion time: {actual_time}, expected: {expected_time})")

                    chunk_1, chunk_2 = split_up_supermutant_by_distance(mutation_ids)
                    recompile_and_run(prepared_runs, data, stats.next_supermutant_id(), chunk_1)
                    recompile_and_run(prepared_runs, data, stats.next_supermutant_id(), chunk_2)
                else:
                    mut_id = mutation_ids[0]
                    stats.run_crashed(EXEC_ID, mut_data['prog'], mut_id, data['run_ctr'], data['fuzzer'],
                    f"unexpected completion time\n\n{logs}")

                    stats.done_run('unexpected_completion_time', EXEC_ID, mut_data['prog'], mut_id, data['run_ctr'], data['fuzzer'])
                    logger.info(f"= run ###:      {mut_data['prog']}:{printable_m_id(mut_data)}:{data['fuzzer']}\n"
                        f"unexpected completion time: {actual_time}, expected: {expected_time}")
            else:
                logger.info(f"= run [+]:      {prog}:{printable_m_id(mut_data)}:{data['fuzzer']}")
                total_time = run_result['total_time']
                plot_data = run_result['plot_data']
                results = sorted(run_result['data'].values(), key=lambda x: x['time'])
                del run_result

                record_supermutant_multi(stats, mut_data, results, data['fuzzer'], data['run_ctr'], 'completed')

                orig_timeout = any(rr['result'] == 'orig_timeout' for rr in results)
                if orig_timeout:
                    logger.warning(f"Original binary timed out, retrying... Consider fixing the subject.")
                    recompile_and_run(prepared_runs, data, stats.next_supermutant_id(), mut_data['mutation_ids'])
                else:
                    all_mutation_ids = mut_data['mutation_ids']
                    assert len(all_mutation_ids) > 0

                    for mut_id in all_mutation_ids:
                        # no mutation should have been killed or there is a bug
                        if has_result(mut_id, results, ['killed', 'killed_by_seed', 'timeout', 'timeout_by_seed']):
                            raise ValueError("Killed result in completed run.", results)
                        # record covered by seed
                        seed_covered = has_result(mut_id, results, ['covered_by_seed'])
                        if seed_covered:
                            seed_covered = seed_covered.get('time', None)
                        seed_timeout_time = 1 if has_result(mut_id, results, ['timeout_by_seed']) else None
                        stats.new_seeds_executed(
                            EXEC_ID,
                            prog,
                            mut_id,
                            data['run_ctr'],
                            data['fuzzer'],
                            seed_covered,
                            seed_timeout_time,
                            None)

                        # record covered
                        covered_time = has_result(mut_id, results, ['covered'])
                        if covered_time:
                            covered_time = covered_time.get('time', None)
                        stats.new_run_executed(
                            plot_data,
                            EXEC_ID,
                            data['run_ctr'],
                            prog,
                            mut_id,
                            data['fuzzer'],
                            covered_time,
                            total_time)

                        result_types = set(rr['result'] for rr in results)
                        unknown_result_types = result_types - HANDLED_RESULT_TYPES
                        assert unknown_result_types == set(), f"Unknown result types: {unknown_result_types}\n{results}"
                        stats.done_run('complete', EXEC_ID, mut_data['prog'], mut_id, data['run_ctr'], data['fuzzer'])
        else:
            raise ValueError(f"Unknown run result type: {result_type}")
        active_mutants[prog_bc]['killed'] = True
        pass

    # Update mutant reference count and remove mutant data if no more references
    active_mutants[prog_bc]['ref_cnt'] -= 1
    if active_mutants[prog_bc]['ref_cnt'] == 0:
        # If mutant was never killed, we want to keep a copy for inspection.
        if not active_mutants[prog_bc]['killed']:
            if prog_bc.is_file():
                shutil.copy(str(prog_bc), UNSOLVED_MUTANTS_DIR)

        clean_up_mut_base_dir(mut_data)
    elif active_mutants[prog_bc]['ref_cnt'] < 0:
        logger.info(f"error negative mutant reference count: {prog_bc} {active_mutants[prog_bc]}")

    # Delete the working directory as it is not needed anymore
    if RM_WORKDIR:
        workdir = Path(data['workdir'])
        try:
            shutil.rmtree(workdir)
        except OSError:
            traceback.print_exc()
        try:
            remaining_files = list(workdir.glob("**/*"))
            if remaining_files:
                rem_f_str = '\n'.join(str(rr) for rr in remaining_files)
                logger.info(f"Still contains files:\n{rem_f_str}")
                try:
                    dbg(run_result)
                except:
                    pass
                try:
                    dbg(trace)
                except:
                    pass
        except Exception as err:
            logger.info(err)

        parent_dirs = workdir.parents
        for parent_dir in parent_dirs:
            try:
                # Also remove parents if it doesn't contain anything anymore.
                # That is all runs for this mutation are done.
                parent_dir.rmdir()
            except Exception:
                break


def recompile_and_run(prepared_runs, data, new_supermutand_id, mutations):
    old_supermutant_id = data['mut_data']['supermutant_id']
    data = copy.deepcopy(data)
    mut_data = data['mut_data']
    mut_data['mutation_ids'] = list(mutations)
    mut_data['supermutant_id'] = new_supermutand_id
    if 'previous_supermutant_ids' in mut_data:
        mut_data['previous_supermutant_ids'].append(old_supermutant_id)
    else:
        mut_data['previous_supermutant_ids'] = [old_supermutant_id]
    workdir = Path("/dev/shm/mutator/")/mut_data['prog']/printable_m_id(mut_data)/data['fuzzer']/str(data['run_ctr'])
    workdir.mkdir(parents=True)
    data['workdir'] = workdir
    logger.info(f"! new supermutant (run): {printable_m_id(mut_data)} with {len(mut_data['mutation_ids'])} mutations")
    prepared_runs.add('mut', (mut_data, [data]))


def recompile_and_run_from_mutation(prepared_runs, mut_data, fuzzer_runs, new_supermutand_id, mutations):
    old_supermutant_id = mut_data['supermutant_id']
    mut_data = copy.deepcopy(mut_data)
    mut_data['mutation_ids'] = list(mutations)
    mut_data['supermutant_id'] = new_supermutand_id

    if 'previous_supermutant_ids' in mut_data:
        mut_data['previous_supermutant_ids'].append(old_supermutant_id)
    else:
        mut_data['previous_supermutant_ids'] = [old_supermutant_id]

    fuzzer_runs = copy.deepcopy(fuzzer_runs)
    for fr in fuzzer_runs:
        workdir = Path("/dev/shm/mutator/")/mut_data['prog']/printable_m_id(mut_data)/fr['fuzzer']/str(fr['run_ctr'])
        workdir.mkdir(parents=True)
        fr['workdir'] = workdir
        fr['mut_data'] = mut_data

    logger.info(f"! new supermutant (run): {printable_m_id(mut_data)} with {len(mut_data['mutation_ids'])} mutations")
    prepared_runs.add('mut', (mut_data, fuzzer_runs))



def start_check_run(prepared_runs, data, new_supermutand_id, mutations, input_dir):
    data = copy.deepcopy(data)
    mut_data = data['mut_data']
    mut_data['mutation_ids'] = list(mutations)
    mut_data['supermutant_id'] = new_supermutand_id
    mut_data['check_run_input_dir'] = input_dir
    mut_data['check_run'] = True
    workdir = Path("/dev/shm/mutator/")/mut_data['prog']/printable_m_id(mut_data)/data['fuzzer']/str(data['run_ctr'])
    workdir.mkdir(parents=True)
    data['workdir'] = workdir
    logger.info(f"! new supermutant (check): {printable_m_id(mut_data)} with {len(mut_data['mutation_ids'])} mutations")
    prepared_runs.add('mut', (mut_data, [data]))


def handle_mutation_result(stats, prepared_runs, active_mutants, task_future, data):
    _, mut_data, fuzzer_runs = data
    logger.debug(f"mut finished for: {mut_data['prog_bc']}")
    prog = mut_data['prog']
    mutation_ids = mut_data['mutation_ids']

    try:
        # Check if there was an exception.
        _ = task_future.result()
    except Exception:
        trace = traceback.format_exc()
        supermutant_id = mut_data['supermutant_id']
        if len(mutation_ids) > 1:
            # If there was an exception for multiple mutations, retry with less.
            chunk_1, chunk_2 = split_up_supermutant_by_distance(mutation_ids)

            logger.info(f"= mutation ###:      {mut_data['prog']}:{printable_m_id(mut_data)}\n"
                  f"rerunning in two chunks with len: {len(chunk_1)}, {len(chunk_2)}")
            logger.debug(trace)
            stats.supermutation_preparation_crashed(EXEC_ID, prog, supermutant_id, trace)

            recompile_and_run_from_mutation(prepared_runs, mut_data, copy.deepcopy(fuzzer_runs), stats.next_supermutant_id(), chunk_1)
            recompile_and_run_from_mutation(prepared_runs, mut_data, copy.deepcopy(fuzzer_runs), stats.next_supermutant_id(), chunk_2)
        else:
            # Else record it.
            logger.info(f"= mutation ###: crashed {prog}:{printable_m_id(mut_data)}")
            logger.debug(trace)
            stats.supermutation_preparation_crashed(EXEC_ID, prog, supermutant_id, trace)
            for mutation_id in mutation_ids:
                stats.mutation_preparation_crashed(EXEC_ID, prog, supermutant_id, mutation_id)

        # Nothing more to do.
        return

    logger.info(f"= mutation [+]: {prog}:{printable_m_id(mut_data)}")

    if mut_data.get('check_run'):
        # remove flag that specifies the mutation should be used for a check run and start as check run
        mut_data['check_run'] = False
        for fr in fuzzer_runs:
            prepared_runs.add('check', fr)

    else:
        # Otherwise add all possible runs to prepared runs.
        for fr in fuzzer_runs:
            prepared_runs.add('fuzz', fr)

    # Update reference count for this mutant
    logger.debug(f"add mutant reference count: {mut_data['prog_bc']} {len(fuzzer_runs)}")
    active_mutants[mut_data['prog_bc']]['ref_cnt'] += len(fuzzer_runs)


def wait_for_task(stats, tasks, cores, prepared_runs, active_mutants):
    "Wait for a task to complete and process the result."
    if len(tasks) == 0:
        logger.info("WARN: Trying to wait for a task but there are none.")
        logger.info(cores.cores)
        return

    # wait for a task to complete
    completed_task = next(concurrent.futures.as_completed(tasks))
    # get the data associated with the task and remove the task from the list
    (task_type, core, data) = tasks[completed_task]
    del tasks[completed_task]

    # free the core for future use
    cores.release_core(core)

    # handle the task result
    if task_type == "run":
        handle_run_result(stats, prepared_runs, active_mutants, completed_task, data)
    elif task_type == "mutation":
        handle_mutation_result(stats, prepared_runs, active_mutants, completed_task, data)
    else:
        raise ValueError("Unknown task type.")


def check_crashing(testing_container, input_dir, orig_bin, mut_bin, args, result_dir):
    if not input_dir.is_dir():
        raise ValueError(f"Given seed dir path is not a directory: {input_dir}")

    covered_dir = Path("/dev/shm/covered/")
    covered_dir.mkdir(parents=True, exist_ok=True)

    max_runtime = 2 if not (WITH_ASAN or WITH_MSAN) else 20

    with tempfile.TemporaryDirectory(dir=covered_dir) as covered:

        proc = run_exec_in_container(testing_container.name, False,
                ['/iterate_seeds.py',
                    '--seeds', input_dir,
                    '--args', args,
                    '--orig', orig_bin,
                    '--mut', mut_bin,
                    '--workdir', IN_DOCKER_WORKDIR,
                    '--results', str(result_dir),
                ],
                [
                    '--env', f"TRIGGERED_FOLDER={covered}",
                    '--env', f'MUT_MAX_RUN={max_runtime}'
                ], timeout=120*60)

    return proc['returncode'], proc['out'], proc['timed_out']


def prepare_mutation(core_to_use, data):
    assert len(data['mutation_ids']) > 0, "No mutations to prepare!"

    compile_args = data['compile_args']
    compile_args = build_compile_args(prepend_main_arg(compile_args), IN_DOCKER_WORKDIR)
    mut_base_dir = get_mut_base_dir(data)
    mut_base_dir.mkdir(parents=True, exist_ok=True)

    prog_bc_name = (Path(data['orig_bc']).with_suffix(f".ll.mut.bc").name)
    prog_ll_name = (Path(data['orig_bc']).with_suffix(f".ll.mut.ll").name)
    prog_bc = mut_base_dir/prog_bc_name
    prog_ll = mut_base_dir/prog_ll_name
    data['prog_bc'] = prog_bc

    prog_bc.parent.mkdir(parents=True, exist_ok=True)

    if WITH_ASAN:
        compile_args = "-fsanitize=address " + compile_args
    if WITH_MSAN:
        compile_args = "-fsanitize=memory " + compile_args

    # get path for covered file and rm the file if it exists
    covered = CoveredFile(mut_base_dir, time.time())

    with start_mutation_container(core_to_use, 60*60) as mutator, \
         start_testing_container(core_to_use, covered, 60*60) as testing:

        run_mut_res = None
        clang_res = None
        try:
            run_mut_res = run_exec_in_container(mutator.name, True, [
                    "./run_mutation.py",
                    "-ll", "-bc",
                    *(["-cpp"] if data['is_cpp'] else ['-cc']),  # conditionally add cpp flag
                    *["-ml", *[str(mid) for mid in data['mutation_ids']]],
                    "--out-dir", str(mut_base_dir),
                    data['orig_bc']
            ])
        except Exception as exc:
            raise RuntimeError(f"Failed to compile mutation") from exc

        with open(prog_ll, 'rt') as f:
            ll_data = f.read()
            for mid in data['mutation_ids']:
                assert ll_data.find(f"signal_triggered_mutation(i64 {mid})") != -1, f"Did not find \"signal_triggered_mutation(i64 {mid})\" in {prog_ll}. All expected mutation ids: {data['mutation_ids']}"

        try:
            clang_args = [
                "/usr/bin/clang++-11",
                "-v",
                "-o", str(mut_base_dir/"mut_base"),
                "/workdir/tmp/lib/libdynamiclibrary.so",
                str(prog_bc),
                *shlex.split(compile_args),
            ] 
            # compile the compare version of the mutated binary
            clang_res = run_exec_in_container(testing, True, clang_args)
        except Exception as exc:
            raise RuntimeError(f"Failed to compile mutation:\n{clang_args}\nrun_mutation output:\n{run_mut_res}\n") from exc


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

    def has_free(self):
        return any(cc is False for cc in self.cores)

    def usage(self):
        return len([cc for cc in self.cores if cc]) / len(self.cores)


def print_run_start_msg(run_data):
    prog = run_data['mut_data']['prog']
    mutation_id = printable_m_id(run_data['mut_data'])
    fuzzer = run_data['fuzzer']
    run_ctr = run_data['run_ctr']
    logger.info(f"> run:          {prog}:{mutation_id}:{fuzzer}:{run_ctr}")


def print_mutation_prepare_start_msg(mut_data, fuzzer_runs):
    fuzzers = " ".join(set(ff['fuzzer'] for ff in fuzzer_runs))
    num_repeats = max(ff['run_ctr'] for ff in fuzzer_runs) + 1
    logger.info(f"> mutation:     {mut_data['prog']}:{printable_m_id(mut_data)} - {num_repeats} - {fuzzers} " +
                f"(num muts: {len(mut_data['mutation_ids'])})")
    return True


def get_git_status():
    proc_rev = subprocess.run(['git', 'rev-parse', 'HEAD'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc_rev.returncode != 0:
        logger.info("Could not get git rev.", proc_rev)
        sys.exit(1)
    proc_status = subprocess.run(['git', 'status'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc_status.returncode != 0:
        logger.info("Could not get git status.", proc_status)
        sys.exit(1)

    return proc_rev.stdout.decode() + '\n' + proc_status.stdout.decode()


def build_subject_docker_images(progs):
    # build the subject docker images
    known_programs = list(PROGRAMS.keys())

    for prog in progs:
        if prog not in known_programs:
            logger.info(f"Unknown program: {prog}, known programs are: {' '.join(known_programs)}")
            sys.exit(1)

    for name in set(PROGRAMS[prog]['name'] for prog in progs):
        tag = subject_container_tag(name)
        logger.info(f"Building docker image for {tag} ({name})")
        proc = subprocess.run([
            "docker", "build",
            "--build-arg", f"CUSTOM_USER_ID={os.getuid()}",
            "--tag", tag,
            "-f", f"subjects/Dockerfile.{name}",
            "."], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if proc.returncode != 0:
            try:
                stdout = proc.stdout.decode()
            except:
                stdout = str(proc.stdout)
            logger.info(f"Could not build {tag} image.\n"
                  f"{proc.args} -> {proc.returncode}\n"
                  f"{stdout}")
            sys.exit(1)
        # extract sample files
        proc = subprocess.run(f"""
            docker rm dummy || true
            docker create -ti --name dummy {tag} bash
            docker cp dummy:/home/mutator/samples tmp/
            docker rm -f dummy""", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if proc.returncode != 0:
            logger.info(f"Could not extract {tag} image sample files.", proc)
            sys.exit(1)

    # If running with asan or msan build a unmutated version instrumented with those sanitizers and update the orig_bin path
    if (WITH_ASAN or WITH_MSAN): #  and prog_info.get('san_is_built') is None:
        if WITH_ASAN and WITH_MSAN:
            logger.info("Can't have both active MUT_BUILD_ASAN and MUT_BUILD_MSAN")
            sys.exit(1)

        with start_mutation_container(None, 60*60) as build_container:
            for prog in progs:
                prog_info = PROGRAMS[prog]
                if prog_info.get('san_is_built') is not None:
                    continue
                compile_args = build_compile_args(
                    prepend_main_arg(prog_info['bc_compile_args'] + prog_info['bin_compile_args']),
                    "/home/mutator/")
                orig_bin = Path(prog_info['orig_bin'])
                orig_sanitizer_bin = str(orig_bin.parent.joinpath(orig_bin.stem + "_san" + orig_bin.suffix))
                prog_info['orig_bin'] = orig_sanitizer_bin
                orig_bc = prog_info['orig_bc']

                run_exec_in_container(build_container, True, [
                    'clang++' if prog_info['is_cpp'] else 'clang',
                    *(['-fsanitize=address'] if WITH_ASAN else []),
                    *(['-fsanitize=memory'] if WITH_MSAN else []),
                    "-g", "-D_FORTIFY_SOURCE=0",
                    str(Path("/home/mutator", orig_bc)),
                    *shlex.split(compile_args),
                    "-o", str(Path("/home/mutator").joinpath(orig_sanitizer_bin))
                ])

                prog_info['san_is_built'] = True


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
        logger.info("Could not build testing image.", proc)
        sys.exit(1)

    # build the fuzzer docker images
    for name in ["system"] + fuzzers:
        if name != 'system' and name not in FUZZERS.keys():
            logger.info(f"Unknown fuzzer: {name}, known fuzzers are: {' '.join(list(FUZZERS.keys()))}")
            sys.exit(1)
        tag = fuzzer_container_tag(name)
        logger.info(f"Building docker image for {tag} ({name})")
        proc = subprocess.run([
            "docker", "build",
            "--build-arg", f"CUSTOM_USER_ID={os.getuid()}",
            "--tag", tag,
            "-f", f"eval/{name}/Dockerfile",
            "."], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if proc.returncode != 0:
            try:
                stdout = proc.stdout.decode()
            except:
                stdout = str(proc.stdout)
            logger.info(f"Could not build {tag} image.\n"
                  f"{proc.args} -> {proc.returncode}\n"
                  f"{stdout}")
            sys.exit(1)

    build_subject_docker_images(progs)


def print_stats(ii, start_time, num_mutations):
    cur_time = (time.time() - start_time)/(60*60)
    percentage_done = ii/num_mutations
    try:
        time_total = cur_time / percentage_done
        time_left = time_total - cur_time
    except ZeroDivisionError:
        time_total = 0
        time_left = 0
    print(f"{ii}/{num_mutations} ({percentage_done*100:05.2f}%)  {cur_time:.2f}->{time_left:.2f}(={time_total:.2f}) hours\r", end='')
    return True


def start_next_task(prepared_runs: PreparedRuns, all_runs, tasks, executor, stats, start_time, num_runs, core, ii):
    # Check if any runs are prepared
    while True:
        run_data = prepared_runs.get_next()
        if run_data is not None:
            break
        else:
            # No runs are ready, prepare a mutation and all corresponding runs.
            try:
                # Get the next mutant
                print("="*100)
                ii, (mut_data, fuzzer_runs) = next(all_runs)

                prepared_runs.add('mut', (mut_data, fuzzer_runs))

            except StopIteration:
                # Done with all mutations and runs, break out of this loop and finish eval.
                return False

    # A task is ready to start, get it and start the run.
    if run_data['type'] == 'fuzz':
        run_data = run_data['data']
        # update core, print message and submit task
        run_data['used_core'] = core
        print_run_start_msg(run_data)
        tasks[executor.submit(run_data['eval_func'], run_data, base_eval)] = ("run", core, run_data)
    elif run_data['type'] == 'check':
        run_data = run_data['data']
        # update core, print message and submit task
        run_data['used_core'] = core
        print_run_start_msg(run_data)
        tasks[executor.submit(check_run, run_data)] = ("run", core, run_data)
    elif run_data['type'] == 'mut':
        mut_data, fuzzer_runs = run_data['data']
        mut_data['used_core'] = core
        stats.new_supermutant(EXEC_ID, mut_data)
        print_mutation_prepare_start_msg(mut_data, fuzzer_runs)
        tasks[executor.submit(prepare_mutation, core, mut_data)] = \
            ("mutation", core, (ii, mut_data, fuzzer_runs))
    else:
        raise ValueError(f"Unknown run type: {run_data}")
    print_stats(ii, start_time, num_runs)
    return ii


def run_eval(progs, fuzzers, timeout, num_repeats, seed_base_dir, rerun, rerun_mutations):
    global should_run

    if rerun_mutations is not None:
        assert rerun is not None, "To use the --rerun-mutations options the --rerun option is required."

    seed_base_dir = Path(seed_base_dir)
    execution_start_time = time.time()

    # prepare environment
    base_shm_dir = Path("/dev/shm/mutator")
    base_shm_dir.mkdir(parents=True, exist_ok=True)
    base_shm_dir = Path("/dev/shm/mutator_tmp")
    base_shm_dir.mkdir(parents=True, exist_ok=True)

    # Initialize the stats object
    stats = Stats("/dev/shm/mutator/stats.db")

    # Record current eval execution data
    # Get the current git status
    git_status = get_git_status()
    stats.new_execution(
        EXEC_ID, platform.uname()[1], git_status, rerun, execution_start_time,
        json.dumps({
            'progs': progs, 'fuzzers': fuzzers, 'timeout': timeout, 'num_repeats': num_repeats,
            'seed_base_dir': str(seed_base_dir), 'rerun': rerun, 'rerun_mutations': rerun_mutations
        }),
        json.dumps({k: v for k, v in os.environ.items()})
    )

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
        prepared_runs = PreparedRuns()
        # start time
        start_time = time.time()
        # Get each run
        all_runs = get_all_runs(stats, fuzzers, progs, seed_base_dir, timeout, num_repeats, rerun, rerun_mutations)
        num_runs = len(all_runs)
        all_runs = enumerate(all_runs)
        ii = 0

        while True:
            # Check if a core is free, if so start next task.
            core = cores.try_reserve_core()
            if core is not None and should_run:
                ii = start_next_task(prepared_runs, all_runs, tasks, executor, stats, start_time, num_runs, core, ii)
                # add tasks while there are more free cores
                if cores.has_free():
                    continue

            # If all tasks are done, stop.
            if len(tasks) == 0:
                break
            # All tasks have been added, wait for a task to complete.
            wait_for_task(stats, tasks, cores, prepared_runs, active_mutants)

    # Record total time for this execution.
    stats.execution_done(EXEC_ID, time.time() - execution_start_time)

    logger.info("eval done :)")


def get_seed_gathering_runs(fuzzers, progs, timeout, seed_base_dir, num_repeats):
    assert num_repeats >= 1
    all_runs = []

    for prog in progs:
        try:
            prog_info = PROGRAMS[prog]
        except Exception as err:
            logger.info(err)
            logger.info(f"Prog: {prog} is not known, known progs are: {PROGRAMS.keys()}")
            sys.exit(1)

        for fuzzer in fuzzers:
            try:
                eval_func = FUZZERS[fuzzer]
            except Exception as err:
                logger.info(err)
                logger.info(f"Fuzzer: {fuzzer} is not known, known fuzzers are: {FUZZERS.keys()}")
                sys.exit(1)

            # Gather all data to start a seed gathering run

            # Compile arguments
            compile_args = prog_info['bc_compile_args'] + prog_info['bin_compile_args']

            mut_data = {
                'orig_bc': Path(IN_DOCKER_WORKDIR)/prog_info['orig_bc'],
                'compile_args': compile_args,
                'is_cpp': prog_info['is_cpp'],
                'prog': prog,
                'dict': prog_info['dict'],
            }

            for ii in range(num_repeats):

                workdir = Path(tempfile.mkdtemp(
                    prefix=f"{prog}__{fuzzer}__{ii}__",
                    dir="/dev/shm/mutator_seed_gathering/"))

                run_data = {
                    'fuzzer': fuzzer,
                    'seed_base_dir': seed_base_dir,
                    'timeout': int(timeout) * 60,
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
    logger.info(f"> run:     {prog}:{fuzzer}")


def handle_seed_run_result(run_future, run_data, all_runs):
    workdir = run_data['workdir']
    try:
        # if there was no exception get the data
        run_result = run_future.result()
    except Exception as e:
        # if there was an exception record it
        trace = traceback.format_exc()
        workdir_exception_file = f'{workdir}/exception'
        logger.info(f"= run ###: Failed for {workdir}, writing exception message to {workdir_exception_file}")
        with open(workdir_exception_file, 'wt') as f:
            f.write(str(e))
            f.write(str(trace))
            logger.debug(f"{e}\n{trace}")
    else:
        errored_file = run_result.get('file_error')
        should_restart = run_result.get('restart')
        if errored_file:
            seed_dir = run_data['seed_dir']
            errored_file = seed_dir/errored_file
            logger.info(f"Removing errored file: {errored_file}")
            try:
                errored_file.unlink()
            except FileNotFoundError:
                logger.info("Already deleted!")
            should_restart = True
        if should_restart:
            logger.info(f"Restarting run")
            shutil.rmtree(workdir)
            all_runs.append(run_data)

        logger.info(f"= run    : {workdir}")


def seed_gathering_run(run_data, docker_image):
    global should_run
    start_time = time.time()
    # extract used values
    mut_data = run_data['mut_data']
    timeout = run_data['timeout']
    seed_base_dir = run_data['seed_base_dir']
    workdir = run_data['workdir']
    orig_bc = mut_data['orig_bc']
    compile_args = build_compile_args(mut_data['compile_args'], IN_DOCKER_WORKDIR)
    seeds = get_seed_dir(seed_base_dir, mut_data['prog'], run_data['fuzzer'])
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
            str(orig_bc),
            str(compile_args),
            str(IN_DOCKER_WORKDIR/seeds),
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
    while time.time() < fuzz_time + timeout and should_run:
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

    if should_run and time.time() - timeout < start_time:
        # The runtime is less than the timeout, something went wrong.
        logger.warning(f"{''.join(all_logs)}")
        raise RuntimeError(''.join(all_logs))

    return {
        'all_logs': all_logs,
    }


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def split_seed_dir(prog, num_splits, seed_base_dir, base_dir):
    split_size = 256*4
    seed_dir = seed_base_dir/prog
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
    logger.info(f"Seed files have been split into {len(split_dirs)} dirs, each with ~{split_size} seeds.")

    return split_dirs


def get_seed_checking_runs(fuzzers, progs, num_splits, base_dir):
    logger.info(fuzzers, progs)
    all_split_dirs = []
    all_runs = []

    for prog in progs:
        try:
            prog_info = PROGRAMS[prog]
        except Exception as err:
            logger.info(err)
            logger.info(f"Prog: {prog} is not known, known progs are: {PROGRAMS.keys()}")
            sys.exit(1)

        split_dirs = split_seed_dir(prog, num_splits, base_dir)
        logger.info(f"num split_dirs {len(split_dirs)}")

        for fuzzer in fuzzers:
            try:
                eval_func = FUZZERS[fuzzer]
            except Exception as err:
                logger.info(err)
                logger.info(f"Fuzzer: {fuzzer} is not known, known fuzzers are: {FUZZERS.keys()}")
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
    timeout = run_data['timeout']
    workdir = run_data['workdir']
    orig_bc = mut_data['orig_bc']
    compile_args = mut_data['compile_args']
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
            str(orig_bc),
            str(compile_args),
            str(IN_DOCKER_WORKDIR/seeds),
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
    while time.time() < fuzz_time + timeout and should_run:
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

    if should_run and time.time() - timeout < start_time:
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


def check_seeds(progs, fuzzers, seed_base_dir):
    global should_run

    # prepare environment
    base_shm_dir = Path("/dev/shm/mutator_check_seeds")
    shutil.rmtree(base_shm_dir, ignore_errors=True, onerror=lambda *x: logger.warning(x))
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
                logger.info(f"Waiting for one of {len(tasks)} tasks.")
                wait_for_seed_run(tasks, cores, all_runs)

        assert len(all_runs) == 0 or should_run is False

    logger.info("Moving seeds back to where they belong...")
    for prog, split_dirs in all_split_dirs:
        seed_dir = seed_base_dir/prog
        # backup currently active seeds as they will be replaces
        seed_backup_dir = Path('tmp/seed_backup')/prog
        logger.info(f"Backing up seed files for prog: {prog} from {seed_dir} to {seed_backup_dir}.")
        shutil.rmtree(seed_backup_dir, ignore_errors=True)
        seed_backup_dir.parent.mkdir(exist_ok=True, parents=True)
        seed_dir.rename(seed_backup_dir)

        # copy the checked seeds into active seeds
        seed_dir.mkdir(parents=True)
        for sd in split_dirs:
            for ff in sd.glob("*"):
                if ff.is_dir():
                    logger.info("Did not expect any directories in the seed dirs, something is wrong.")
                shutil.copy2(ff, seed_dir)

    logger.info("seed checking done :)")


def gather_seeds(progs, fuzzers, timeout, num_repeats, per_fuzzer, source_dir, destination_dir):
    global should_run

    source_dir = Path(source_dir)
    destination_dir = Path(destination_dir)
    destination_dir.mkdir(parents=True, exist_ok=True)

    # prepare environment
    seed_coverage_base_shm_dir = Path("/dev/shm/mutator_seed_gathering")
    shutil.rmtree(seed_coverage_base_shm_dir, ignore_errors=True)
    seed_coverage_base_shm_dir.mkdir(parents=True, exist_ok=True)

    build_docker_images(fuzzers, progs)

    # Keep a list of which cores can be used
    cores = CpuCores(NUM_CPUS)

    # for each mutation and for each fuzzer do a run
    with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_CPUS) as executor:
        # keep a list of all tasks
        tasks = {}
        # Get each seed gathering runs
        all_runs = get_seed_gathering_runs(fuzzers, progs, timeout, source_dir, num_repeats)

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
                logger.info(f"Waiting for one of {len(tasks)} tasks.")
                wait_for_seed_run(tasks, cores, all_runs)

        assert len(all_runs) == 0 or should_run is False

    logger.info("Copying seeds to target dir ...")
    all_runs_dir = destination_dir/"all_runs"
    seed_runs = []
    coverage_dirs = list(seed_coverage_base_shm_dir.glob("*"))
    for ii, seed_source in enumerate(coverage_dirs):
        logger.info(f"{ii+1} / {len(coverage_dirs)}")
        if not seed_source.is_dir():
            continue

        seed_base_dir_parts = str(seed_source.name).split('__')
        prog = seed_base_dir_parts[0]
        fuzzer = seed_base_dir_parts[1]
        instance = seed_base_dir_parts[2]
        fuzzed_seed_dir = all_runs_dir/prog/fuzzer/instance
        fuzzed_seed_dir.mkdir(parents=True, exist_ok=True)

        collector = SEED_HANDLERS[fuzzer]
        found_seeds = collector(seed_source)

        for fs in found_seeds:
            file_hash = hash_file(fs)
            dest_path = fuzzed_seed_dir/file_hash
            shutil.copyfile(fs, dest_path)

        seed_runs.append({
            'prog': prog,
            'fuzzer': fuzzer,
            'instance': instance,
            'dir': str(fuzzed_seed_dir),
            'num_seeds': len(found_seeds),
        })

    # for each seed_run, minimize the run in new folder minimize_dir
    all_minimized_runs_dir = destination_dir/"minimized_runs"

    minimize_shm_dir = Path("/dev/shm/minimize_coverage_seeds")
    shutil.rmtree(minimize_shm_dir, ignore_errors=True, onerror=lambda *x: logger.warning(x))
    minimize_shm_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Minimizing seeds ...")
    for ii, sr in enumerate(seed_runs):
        logger.info(f"{ii+1} / {len(seed_runs)}")
        sr_fuzzer = sr['fuzzer']
        sr_prog = sr['prog']
        sr_seed_dir = Path(sr['dir'])
        sr_minimized_dir = all_minimized_runs_dir.joinpath(sr_seed_dir.relative_to(all_runs_dir))
        sr_minimized_dir.mkdir(parents=True)
        sr['minimized_dir'] = str(sr_minimized_dir)
        minimize_seeds_one(minimize_shm_dir, sr_prog, sr_fuzzer, sr_seed_dir, sr_minimized_dir)
        minimized_files = list(Path(sr['minimized_dir']).glob("*"))
        sr['num_seeds_minimized'] = len(minimized_files)


    with start_mutation_container(None, None) as mutator:
        logger.info("Instrumenting progs ...")
        for prog in set(sr['prog'] for sr in seed_runs):
            logger.info(prog)
            prog_info = PROGRAMS[prog]
            instrument_prog(mutator, prog_info)

        kcov_res_dir = Path('/dev/shm/kcov_res')
        shutil.rmtree(kcov_res_dir, ignore_errors=True)
        kcov_res_dir.mkdir(parents=True)

        seed_coverage_base_shm_dir = Path("/dev/shm/seed_coverage")
        shutil.rmtree(seed_coverage_base_shm_dir, ignore_errors=True)
        seed_coverage_base_shm_dir.mkdir(parents=True, exist_ok=True)

        logger.info("Measuring coverage ...")
        for ii, sr in enumerate(seed_runs):
            logger.info(f"{ii+1} / {len(seed_runs)}")
            prog = sr['prog']
            sr_seed_dir = sr['dir']
            try:
                covered_mutations = measure_mutation_coverage(mutator, PROGRAMS[prog], sr_seed_dir)
            except CoverageException as e:
                exception_path = kcov_res_dir/f"exception_{sr['prog']}_{sr['fuzzer']}_{sr['instance']}"
                exception_message = f"{e}\n{traceback.format_exc()}"
                logger.warning(f"Got exception, writing exception to {exception_path}")
                logger.debug(f"{exception_message}")
                with open(exception_path, 'wt') as f:
                    f.write(exception_message)
                continue

            sr['covered_mutations'] = covered_mutations

            kcov_res_path = kcov_res_dir/f"{sr['prog']}_{sr['fuzzer']}_{sr['instance']}.json"
            get_kcov(prog, sr_seed_dir, kcov_res_path)
            with open(kcov_res_path) as f:
                kcov_res = json.load(f)
            sr['kcov_res'] = kcov_res

            logger.info(f"{sr['prog']} {sr['fuzzer']} {sr['instance']}: "
                  f"created {sr['num_seeds_minimized']} seeds inputs covering {len(covered_mutations)} mutations")

    runs_by_prog_fuzzer = defaultdict(list)
    for sr in seed_runs:
        runs_by_prog_fuzzer[(sr['prog'], sr['fuzzer'])].append(sr)

    median_runs_base_dir = destination_dir/'median_runs'
    median_runs_base_dir.mkdir()

    logger.info(f"Copying median runs to: {str(median_runs_base_dir)}")
    for rr in runs_by_prog_fuzzer.values():
        sorted_runs = sorted(rr, key=lambda x: len(x['covered_mutations']))
        mr = sorted_runs[int(len(sorted_runs) / 2)]
        median_run_dir = median_runs_base_dir/mr['prog']/mr['fuzzer']
        median_run_dir.mkdir(parents=True)

        minimized_files = list(Path(mr['minimized_dir']).glob("*"))
        for si in minimized_files:
            shutil.copyfile(si, median_run_dir/si.name)

    with open(destination_dir/'info.json', 'wt') as f:
        json.dump(seed_runs, f)
    logger.info(f"Done gathering seeds.")


def coverage_fuzzing(progs, fuzzers, fuzz_time, seed_dir, result_dir, instances):
    seed_dir = Path(seed_dir)
    result_dir = Path(result_dir)

    assert seed_dir.exists(), f"Expected the --seed-dir: {seed_dir} to exist."
    assert not result_dir.exists(), f"Expected the --result-dir: {result_dir} to not exist."

    gather_seeds(progs, fuzzers, fuzz_time, instances, True, seed_dir, result_dir)


# dest dir is seed_base_dir
def import_seeds(source_dir, dest_dir):
    source_dir = Path(source_dir)
    dest_dir = Path(dest_dir)
    for seed_source in source_dir.glob("*"):
        if not seed_source.is_dir():
            logger.info(f"Warning: Expected only directories but this path is not a directory: {seed_source}")
            continue

        if seed_source.name not in PROGRAMS:
            logger.info(f"Warning: Directory does not match any program name, files in this directory will not be imported: {seed_source}")
            continue

        seed_files = [sf for sf in seed_source.glob("**/*") if sf.is_file()]
        prog_dest_dir = dest_dir/seed_source.name
        prog_dest_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Copying seed files from {seed_source} to {prog_dest_dir} ...")

        num_already_exist = 0
        num_copied = 0
        num_too_big = 0

        for sf in seed_files:
            file_hash = hash_file(sf)
            dest_path = prog_dest_dir/file_hash
            if dest_path.is_file():
                num_already_exist += 1
                continue
            if sf.stat().st_size >= 1_000_000:
                num_too_big += 1
                continue
            shutil.copyfile(sf, dest_path)
            num_copied += 1

        logger.info(f"Copied {num_copied} and ignored: {num_already_exist} (same hash) + {num_too_big} (size too large).")


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

TOTAL_FUZZER = 'combined'
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
        logger.info("Crashed runs:")
        logger.info(crashes)
        res += "<h2>Crashes</h2>"
        res += crashes.to_html()

    crashes = pd.read_sql_query("""
        select *
        from base_bin_crashes
    """, con)
    res = ""
    if len(crashes) > 0:
        logger.info("Base bin crashes:")
        logger.info(crashes)
        res += "<h2>Base Bin Crashes</h2>"
        res += crashes.to_html()

    crashes = pd.read_sql_query("""
        select *
        from not_covered_but_found
    """, con)
    res = ""
    if len(crashes) > 0:
        logger.info("Not Covered but Found:")
        logger.info(crashes)
        res += "<h2>Not Covered but Found</h2>"
        res += crashes.to_html()

    crashes = pd.read_sql_query("""
        select *
        from covered_by_seed_but_not_fuzzer
    """, con)
    res = ""
    if len(crashes) > 0:
        logger.info("Covered By Seed but Not Fuzzer:")
        logger.info(crashes)
        res += "<h2>Covered By Seed but Not Fuzzer</h2>"
        res += crashes.to_html()
    return res

def fuzzer_stats(con):
    import pandas as pd
    stats = pd.read_sql_query("SELECT * from run_results_by_fuzzer", con)
    logger.info(stats)
    # logger.info(stats[['fuzzer', 'total', 'done', 'found', 'f_by_f', 'avg_run_min', 'cpu_days']].to_latex())
    res = "<h2>Fuzzer Stats</h2>"
    res += stats.to_html()
    return res

def fuzzer_prog_stats(con):
    import pandas as pd
    stats = pd.read_sql_query("SELECT * from run_results_by_prog_and_fuzzer", con)
    logger.info(stats)
    # logger.info(stats[['fuzzer', 'total', 'done', 'found', 'f_by_f', 'avg_run_min', 'cpu_days']].to_latex())
    res = "<h2>Fuzzer by Program Stats</h2>"
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

def latex_stats_seeds(out_dir):
    run_data = []
    for res_json in Path("seeds/seeds_coverage/").glob("info_*.json"):
        with open(res_json, 'rt') as f:
            run_data.extend(json.load(f))

    bucketed = defaultdict(list)
    for dd in run_data:
        bucketed[(dd['prog'], dd['fuzzer'])].append(dd)

    data = defaultdict(lambda: defaultdict(dict))
    for pf, bb in bucketed.items():
        sorted_bb = sorted(bb, key=lambda x: len(x['covered_mutations']))
        median_bb = sorted_bb[len(sorted_bb)//2]
        bb = median_bb
        data[bb['prog']][bb['fuzzer']] = median_bb

    all_progs = sorted(set(data.keys()))
    all_fuzzers = sorted(set(kk for dd in data.values() for kk in dd.keys()))
    
    res_table = ""

    all_fuzzers_str = ' & '.join(all_fuzzers)
    res_table += rf"Program &   \#Type &&   {all_fuzzers_str} \\" + "\n"
    res_table += r"\midrule" + "\n"

    for ii, pp in enumerate(all_progs):
        f_line = rf"\multirow{{3}}{{*}}{{{pp}}} & F: &"
        m_line = rf"                     & M: &"
        l_line = rf"                     & L: &"

        for ff in all_fuzzers:
            fuzzer_res = data[pp][ff]
            covered_mutations = len(fuzzer_res['covered_mutations'])
            covered_lines = len(set(tuple(ll) for ll in fuzzer_res['kcov_res']['covered_lines']))
            num_seeds = fuzzer_res['num_seeds_minimized']
            f_line += f" & {num_seeds}"
            m_line += f" & {covered_mutations}"
            l_line += f" & {covered_lines}"

        # max_num_mutations = "---"
        # max_num_lines = "---"
        # f_line += rf" & & \\"
        # m_line += rf" & & {max_num_mutations} \\"
        # l_line += rf" & & {max_num_lines} \\"

        f_line += rf" \\"
        m_line += rf" \\"
        l_line += rf" \\"
        res_table += f_line + "\n"
        res_table += m_line + "\n"
        res_table += l_line + "\n"
        if ii < len(all_progs) - 1:
            res_table += r"\cmidrule{4-7}" + "\n"

    with open(out_dir/"seed-stats.tex", "wt") as f:
        f.write(res_table)


def latex_stats(out_dir, con):
    # def value_to_file(stats, name, path):
    #     print(name)
    #     print(stats[name])
    #     val = stats[name].unique()
    #     print(val)
    #     assert len(val) == 1
    #     val = val[0]
    #     path = path.with_stem(path.stem + "---" + name.replace('_', '-'))
    #     with open(path, 'w') as f:
    #         f.write(str(val))

    # def write_table(latex, path):
    #     latex = re.sub(r'\\(toprule|midrule|bottomrule)$', r'\\hline', latex, flags=re.M)
    #     with open(path, 'w') as f:
    #         f.write(latex)

    import pandas as pd
    logger.info(f"Writing latex tables to: {out_dir}")

    latex_stats_seeds(out_dir)

    old_float_format = pd.options.display.float_format
    pd.options.display.float_format = lambda x : '{:.0f}'.format(x) if round(x,0) == x else '{:,.2f}'.format(x)

    stats = pd.read_sql_query("SELECT * from run_results_by_fuzzer", con)
    stats[['fuzzer', 'done', 'covered', 'c_by_seed', 'found', 'f_by_seed', 'f_by_f']].to_latex(
        buf=out_dir/"fuzzer-stats.tex",
        header=['prog', 'total', 'covered', 'by seed', 'found', 'by seed', 'by fuzzer'],
        na_rep='---',
        index=False,
    )

    stats = pd.read_sql_query("SELECT * from run_results_by_prog", con)
    stats[['prog', 'done', 'covered', 'f_by_seed', 'interesting', 'f_by_one', 'f_by_all']].to_latex(
        buf=out_dir/"prog-stats.tex",
        header=['prog', 'total', 'covered', 'by seed', 'stubborn', 'by one', 'by all'],
        na_rep='---',
        index=False,
    )

    stats = pd.read_sql_query("SELECT * from run_results_by_mut_type", con)
    stats[['name', 'done', 'covered', 'f_by_seed', 'interesting', 'f_by_one', 'f_by_all']].to_latex(
        buf=out_dir/"mut-type-stats.tex",
        header=['mutation', 'total', 'covered', 'by seed', 'stubborn', 'by one', 'by all'],
        na_rep='---',
        index=False,
    )

    stats = pd.read_sql_query("SELECT * from run_results_by_prog_and_fuzzer", con)
    stats[['prog', 'fuzzer', 'done', 'covered', 'f_by_seed', 'interesting', 'f_by_one', 'f_by_all']].to_latex(
        buf=out_dir/"prog-fuzzer-stats.tex",
        header=['prog', 'fuzzer', 'total', 'covered', 'by seed', 'stubborn', 'by one', 'by all'],
        na_rep='---',
        index=False,
    )

    old_max_with = pd.get_option('display.max_colwidth')
    pd.set_option('display.max_colwidth', 1000)

    stats = pd.read_sql_query("SELECT * from mutation_types", con)
    stats[['pattern_name', 'description', 'procedure']].to_latex(
        buf=out_dir/"mutations.tex",
        header=['mutation', 'description', 'procedure'],
        na_rep='---',
        index=False,
        column_format="p{.18\\textwidth}p{.4\\textwidth}p{.4\\textwidth}",
        longtable=True,
        multirow=True,
    )

    pd.options.display.float_format = old_float_format
    pd.set_option('display.max_colwidth', old_max_with)

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
        import matplotlib.pyplot as plt
        from matplotlib import ticker
        import seaborn
        import numpy as np

        seaborn.set(style='ticks')

        fuzzers = data.fuzzer.unique()
        values = { ff: [] for ff in fuzzers }
        for row in data.itertuples():
            if row.prog != 'all':
                continue
            values[row.fuzzer].append((row.time, row.value))

        fig, ax = plt.subplots()
        ax.set_title(title)
        ax.set_xlabel('Time in Minutes')
        # ax.set_xscale('log')
        ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
        ax.set_ylabel('Killed Mutants' if absolute else 'Killed Mutants %')
        ax.grid(True, which='both')
        plot_handles = []
        for ff, vals in values.items():
            x, y = list(zip(*vals))
            handle, = ax.plot(x, y, label=ff)
            plot_handles.append(handle)
        ax.legend(handles=plot_handles, bbox_to_anchor=(0.5, -0.2), loc='upper center', ncol=3)
        # fig.subplots_adjust(top=1-tt, bottom=0.25, wspace=0.2)
        fig.tight_layout()
        seaborn.despine(ax=ax)

        plot_path_svg = plot_dir.joinpath(f"{slug_title}.svg")
        plot_path_pdf = plot_path_svg.with_suffix(".pdf")
        fig.savefig(plot_path_pdf, format="pdf")
        plt.close(fig)
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
        # if event.found_by_seed:
        #     continue
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

    # logger.info(mutation_info)
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

def wayne_diagram(values, total_sum, fuzzers, plot_pdf_path):
    import matplotlib.pyplot as plt
    import matplotlib.patches as patches

    fig, ax = plt.subplots()

    ax.set_title("Overlap of Killed Mutants between Fuzzers")
    ax.set_axis_off()
    ax.set_xlim([.78, 2.1])
    ax.set_ylim([0, 1.06])

    def ell(offset, angle, color):
        return patches.Ellipse(offset, 1, 0.5, angle=angle, alpha=.3, color=color)

    cmap = plt.get_cmap('Set1')

    ax.add_patch(ell((1.1825, .4), 90+45, color=cmap.colors[0]))
    ax.text(0.85, .84, fuzzers[0], color=cmap.colors[0], alpha=.7)

    ax.add_patch(ell((1.425, .52), 90+45, color=cmap.colors[1]))
    ax.text(1.1, .96, fuzzers[1], color=cmap.colors[1], alpha=.7)

    ax.add_patch(ell((1.425, .52), 90-45, color=cmap.colors[2]))
    ax.text(1.6, .96, fuzzers[2], color=cmap.colors[2], alpha=.7)

    ax.add_patch(ell((1.6675, .4), 90-45, color=cmap.colors[3]))
    ax.text(1.85, .84, fuzzers[3], color=cmap.colors[3], alpha=.7)


    texts = {
        '1___': (None, (0.9, .48)),
        '_2__': (None, (1.2, .77)),
        '__3_': (None, (1.56, .77)),
        '___4': (None, (1.85, .48)),
        '12__': (None, (1.07, .62)),
        '1_3_': (None, (1.1, .25)),
        '1__4': (None, (1.375, .07)),
        '_23_': (None, (1.375, .64)),
        '_2_4': (None, (1.65, .25)),
        '__34': (None, (1.69, .62)),
        '_234': (None, (1.55, .48)),
        '1_34': (None, (1.28, .18)),
        '12_4': (None, (1.48, .18)),
        '123_': (None, (1.2, .48)),
        '1234': (None, (1.375, .32)),
    }

    texts = {kk: (values[kk], (vv[1][0], vv[1][1])) for kk, vv in texts.items()}

    for tt in texts.values():
        ax.text(tt[1][0], tt[1][1], tt[0])

    ax.text(.8, .01, f"Total Killed: {total_sum}")

    # note that text is not scaled
    scaling = 1.4
    fig.set_size_inches(scaling*7, scaling*4)

    fig.savefig(plot_pdf_path, format="pdf")
    plt.close(fig)


def plot_killed_union(runs, run_results, plot_dir):
    from itertools import combinations
    all_fuzzers = sorted(runs.fuzzer.unique())
    if len(all_fuzzers) != 4:
        logger.info(f"Results are contain not exactly 4 fuzzers ({all_fuzzers}), skipping wayne diagram.")
        return

    found = run_results[run_results['confirmed'].notnull()]

    fuzzers_found_mutation = defaultdict(list)
    for _, ff in found.iterrows():
        fuzzers_found_mutation[(ff['exec_id'], ff['prog'], ff['mut_id'])].append(ff['fuzzer'])


    # Separate buckets
    values = {
        '1___': 0,
        '_2__': 0,
        '__3_': 0,
        '___4': 0,
        '12__': 0,
        '1_3_': 0,
        '1__4': 0,
        '_23_': 0,
        '_2_4': 0,
        '__34': 0,
        '_234': 0,
        '1_34': 0,
        '12_4': 0,
        '123_': 0,
        '1234': 0,
    }

    total_sum = 0
    for ff in fuzzers_found_mutation.values():
        # Count each bucket separately
        key = ""
        for ii, fuzzer in enumerate(all_fuzzers):
            if fuzzer in ff:
                key += f"{ii+1}"
            else:
                key += "_"
        values[key] += 1

        total_sum += 1

    values = {kk: f"{vv}\n[{(100*vv/total_sum):.1f}%]" for kk, vv in values.items()}
    
    plot_path_pdf = plot_dir.joinpath(f"wayne-diagram-separate.pdf")
    wayne_diagram(values, total_sum, all_fuzzers, plot_path_pdf)
    

def generate_plots(db_path, to_disk, skip_script):
    import pandas as pd
    db_path = Path(db_path)

    plot_dir = db_path.parent/"plots"
    if to_disk:
        shutil.rmtree(plot_dir, ignore_errors=True)
        plot_dir.mkdir(parents=True, exist_ok=True)

    con = sqlite3.connect(db_path)
    con.isolation_level = None
    con.row_factory = sqlite3.Row

    if not skip_script:
        logger.info("Executing eval.sql script...")
        with open("eval.sql", "rt") as f:
            cur = con.cursor()
            cur.executescript(f.read())
        logger.info("done")

    if to_disk:
        latex_stats(plot_dir, con)

    res = header()
    # logger.info("crashes")
    # res += error_stats(con)
    # logger.info("fuzzer stats")
    # res += fuzzer_stats(con)
    # logger.info("fuzzer prog stats")
    # res += fuzzer_prog_stats(con)
    # logger.info("mut stats")
    # res += mut_stats(con)
    # logger.info("prog stats")
    # res += prog_stats(con)
    # logger.info("afl stats")
    # res += aflpp_stats(con)

    # logger.info("select mut_types")
    # mut_types = pd.read_sql_query("SELECT * from mut_types", con)
    logger.info("select runs")
    runs = pd.read_sql_query("select * from run_results_by_mut_type_and_fuzzer", con)
    logger.info("select run_results")
    run_results = pd.read_sql_query("select * from run_results", con)
    # logger.info("select unique_finds")
    # unique_finds = pd.read_sql_query("select * from unique_finds", con)
    # #  logger.info("select unique_finds_overall")
    # #  unique_finds_overall = pd.read_sql_query("select * from unique_finds_overall", con)
    # logger.info("select mutation_types")
    # mutation_info = pd.read_sql_query("select * from mutation_types", con)

    # res += "<h2>Plots</h2>"
    # res += "<h3>Overall Plots</h3>"
    # logger.info("overall")
    total_plot_data = gather_plot_data(runs, run_results)
    if total_plot_data is not None:
        res += plot(plot_dir if to_disk else None, f"Killed Covered Mutants Overall", "overall", total_plot_data['covered'], total_plot_data['num_mutations'], False)
        res += plot(plot_dir if to_disk else None, f"Killed Mutants Overall", "overall", total_plot_data['total'], total_plot_data['num_mutations'], False)
        res += plot(plot_dir if to_disk else None, f"Absolute Killed Mutants Overall", "overall", total_plot_data['absolute'], total_plot_data['num_mutations'], True)

    if to_disk:
        plot_killed_union(runs, run_results, plot_dir)
    #  res += '<h4>Unique Finds</h4>'
    #  res += 'Left finds what upper does not.'
    #  res += matrix_unique_finds(unique_finds_overall).to_html(na_rep="")

    # for mut_type in mut_types['mut_type']:
    #     logger.info(mut_type)
    #     res += create_mut_type_plot(plot_dir, mut_type,
    #         runs[runs.mut_type == mut_type],
    #         run_results[run_results.mut_type == mut_type],
    #         unique_finds[unique_finds.mut_type == mut_type],
    #         mutation_info[mutation_info.mut_type == mut_type],
    #     )
    # res += footer()

    # out_path = db_path.with_suffix(".html").resolve()
    # logger.info(f"Writing plots to: {out_path}")
    # with open(out_path, 'w') as f:
    #     f.write(res)
    # logger.info(f"Open: file://{out_path}")


def merge_dbs(out_path, in_paths):
    logger.info(f"{out_path}, {in_paths}")

    out_db_path = Path(out_path)
    if out_db_path.is_file():
        logger.info(f"Removing file: {out_db_path}")
        out_db_path.unlink()

    # copy the first database
    proc = subprocess.run(f'sqlite3 {in_paths[0]} ".dump" | sqlite3 {out_path}',
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode != 0:
        logger.info("Failed to copy the first db.", proc)
        sys.exit(1)

    # TODO check that the other database has the same commit and git state?

    # copy all data
    for in_db in in_paths[1:]:
        inserts = "\n".join((
                f"insert into {table} select * from to_merge.{table};"
                for table in ['execution', 'all_runs', 'mutations', 'progs', 'executed_runs', 'executed_seeds', 'aflpp_runs',
                              'seed_crashing_inputs', 'crashing_inputs', 'crashing_supermutation_preparation', 'crashing_mutation_preparation', 'run_crashed',
                              'initial_super_mutants', 'started_super_mutants']))
        command = f'''sqlite3 {out_db_path} "
attach '{in_db}' as to_merge;
BEGIN;
{inserts}
COMMIT;
detach to_merge;"'''
        logger.info(command)
        proc = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if proc.returncode != 0:
            logger.info(f"Failed to copy the first db. {proc}")
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


def measure_mutation_coverage(mutator, prog_info, seed_dir):
    detector_path = mutation_detector_path(prog_info)
    args = "@@"
    # create tmp folder to where to put trigger signals
    with tempfile.TemporaryDirectory(dir=HOST_TMP_PATH) as trigger_folder:
        in_docker_trigger_folder = Path('/home/mutator/tmp/').joinpath(Path(trigger_folder).relative_to(HOST_TMP_PATH))
        # start detector and run through all seed files
        run = run_exec_in_container(mutator.name, False,
            [
                '/home/mutator/iterate_seeds_simple.py',
                '--seeds', seed_dir,
                '--args', args,
                '--binary', detector_path,
                '--workdir', '/home/mutator'
            ],
            exec_args=['--env', f"TRIGGERED_FOLDER={in_docker_trigger_folder}"],
            timeout=60*60*4)
        if run['timed_out'] or run['returncode'] != 0:
            logger.info(f"Got returncode != 0: {run['returncode']}")
            raise CoverageException(run)
        # get a list of all mutation ids from triggered folder
        mutation_ids = list(pp.stem for pp in Path(trigger_folder).glob("**/*"))
        return mutation_ids


def seed_minimization_run(run_data, docker_image):
    global should_run
    start_time = time.time()
    # extract used values
    mut_data = run_data['mut_data']
    workdir = run_data['workdir']
    orig_bc = mut_data['orig_bc']
    compile_args = mut_data['compile_args']
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
            str(orig_bc),
            str(compile_args),
            str(seeds_in),
            str(seeds_out),
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


def minimize_seeds_one(base_shm_dir, prog, fuzzer, in_path, out_path):
    try:
        prog_info = PROGRAMS[prog]
    except Exception as err:
        logger.info(err)
        logger.info(f"Prog: {prog} is not known, known progs are: {PROGRAMS.keys()}")
        sys.exit(1)
    try:
        eval_func = FUZZERS[fuzzer]
    except Exception as err:
        logger.info(err)
        logger.info(f"Fuzzer: {fuzzer} is not known, known fuzzers are: {FUZZERS.keys()}")
        sys.exit(1)

    with tempfile.TemporaryDirectory(dir=base_shm_dir) as active_dir:
        active_dir = Path(active_dir)
        # copy seed_path dir into a tmp dir to make sure to not disturb the original seeds
        seed_in_tmp_dir = active_dir/"seeds_in"
        seed_in_tmp_dir.mkdir()
        seed_out_tmp_dir = active_dir/"seeds_out"
        seed_out_tmp_dir.mkdir()

        in_files = list(in_path.glob("*"))
        for ff in in_files:
            if ff.is_dir():
                raise ValueError("Did not expect any directories in the seed path, something is wrong.")
            shutil.copy2(ff, seed_in_tmp_dir)

        # Compile arguments
        compile_args = build_compile_args(prog_info['bc_compile_args'] + prog_info['bin_compile_args'], IN_DOCKER_WORKDIR)
        # Arguments on how to execute the binary
        args = "@@"

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

        # move minimized seeds to result path
        for ff in seed_out_tmp_dir.glob("*"):
            if ff.is_dir():
                logger.info("Did not expect any directories in the seed path, something is wrong.")
            shutil.copy2(ff, out_path)


def minimize_seeds(seed_path_base, res_path_base, fuzzers, progs, per_fuzzer):
    global should_run
    seed_path_base = Path(seed_path_base)
    res_path_base = Path(res_path_base)

    if res_path_base.exists():
        logger.info(f"Result path already exists, to avoid data loss, it is required that this path does not exist: {res_path_base}")
        sys.exit(1)

    # prepare environment
    base_shm_dir = Path("/dev/shm/minimize_seeds")
    shutil.rmtree(base_shm_dir, ignore_errors=True, onerror=lambda *x: logger.warning(x))
    base_shm_dir.mkdir(parents=True, exist_ok=True)

    build_docker_images(fuzzers, progs)

    for prog, fuzzer in product(progs, fuzzers):
        if not should_run:
            break

        # Gather all data to start a seed minimization run
        prog_seed_path = seed_path_base/prog
        if per_fuzzer:
            prog_seed_path = prog_seed_path/fuzzer
        if not prog_seed_path.is_dir():
            logger.info(f"There is no seed directory for prog: {prog}, seed files need to be here: {prog_seed_path}")
            sys.exit(1)
        prog_fuzzer_res_path = res_path_base/prog/fuzzer
        prog_fuzzer_res_path.mkdir(parents=True)

        minimize_seeds_one(base_shm_dir, prog, fuzzer, prog_seed_path, prog_fuzzer_res_path)
    logger.info("seed minimization done :)")



def seed_coverage_run(run_data, docker_image):
    global should_run

    # extract used values
    mut_data = run_data['mut_data']
    workdir = run_data['workdir']
    orig_bin = run_data['orig_bin']
    args = mut_data['args']
    seed_path = run_data['seed_path']
    # seeds_out = run_data['seed_out_dir']

    workdir.mkdir(parents=True, exist_ok=True)

    # get access to the docker client to start the container
    docker_client = docker.from_env()

    # Start and run the container
    container = docker_client.containers.run(
        docker_image, # the image
        [
            "/home/mutator/seed_coverage.py",
            "--prog", str(orig_bin),
            "--prog-args", str(args),
            "--seeds", str(seed_path),
            "--workdir", str(workdir),
        ], # the arguments
        user=os.getuid(),
        privileged=True,
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

    return all_logs


def get_kcov(prog, seed_path, res_path):
    global should_run
    prog_info = PROGRAMS[prog]
    seed_path = Path(seed_path)
    res_path = Path(res_path)

    if not seed_path.is_dir():
        logger.info(f"There is no seed directory for prog: {prog}, seed files need be in this dir: {seed_path}")
        sys.exit(1)

    if res_path.exists():
        logger.info(f"Result path already exists, to avoid data loss, it is required that this dir does not exist: {res_path}")
        sys.exit(1)

    with tempfile.TemporaryDirectory(dir="/dev/shm/seed_coverage") as active_dir:
        active_dir = Path(active_dir)

        # copy seed_path dir into a tmp dir to make sure to not disturb the original seeds
        seed_in_tmp_dir = active_dir/"seeds_in"
        seed_in_tmp_dir.mkdir()
        for ff in seed_path.glob("*"):
            if ff.is_dir():
                logger.info("Did not expect any directories in the seed path, something is wrong.")
                sys.exit(1)
            shutil.copy2(ff, seed_in_tmp_dir)

        # Compile arguments
        compile_args = build_compile_args(prog_info['bc_compile_args'] + prog_info['bin_compile_args'], IN_DOCKER_WORKDIR)
        # Arguments on how to execute the binary
        args = "@@"

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

        orig_bin = Path(prog_info['orig_bin'])

        # copy bin into workdir for easy access
        shutil.copy2(orig_bin, workdir)
        orig_bin = workdir/orig_bin.name

        run_data = {
            'orig_bin': orig_bin,
            'workdir': workdir,
            'seed_path': seed_in_tmp_dir,
            'mut_data': mut_data,
        }

        # collect the seed coverage
        all_logs = seed_coverage_run(run_data, subject_container_tag(prog_info['name']))

        res_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy(workdir/f"result.json", res_path)
        except FileNotFoundError as e:
            logger.warning("Failed to get results file.")
            logs_message = ''.join(all_logs)
            logger.warning(f"{logs_message}")
            raise e

def seed_coverage(seed_path, res_path, prog):
    # prepare environment
    base_shm_dir = Path("/dev/shm/seed_coverage")
    shutil.rmtree(base_shm_dir, ignore_errors=True)
    base_shm_dir.mkdir(parents=True, exist_ok=True)

    build_subject_docker_images([prog])

    try:
        _ = PROGRAMS[prog]
    except Exception as err:
        logger.info(err)
        logger.info(f"Prog: {prog} is not known, known progs are: {PROGRAMS.keys()}")
        sys.exit(1)

    get_kcov(prog, seed_path, res_path)


def main():
    import sys
    import argparse

    # set signal handler for keyboard interrupt
    signal.signal(signal.SIGINT, sigint_handler)

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='cmd', help="These are the possible actions for the eval, "
            "see their individual descriptions.")

    # CMD: eval 
    parser_eval = subparsers.add_parser('eval',
        help="Run the evaluation executing the requested fuzzers (--fuzzers) on "
             "the requested programs (--progs) and gather the resulting data.")
    parser_eval.add_argument("--fuzzers", nargs='+', required=True,
        help='The fuzzers to evaluate, will fail if the name is not known.')
    parser_eval.add_argument("--progs", nargs='+', required=True,
        help='The programs to evaluate on, will fail if the name is not known.')
    parser_eval.add_argument("--fuzz-time", required=True,
        help='Time in minutes for how long the fuzzers have to find mutations.')
    parser_eval.add_argument("--num-repeats", type=int, default=1,
        help="How often to repeat each mutation for each fuzzer.")
    parser_eval.add_argument("--seed-dir", required=True,
        help="The directory containing the initial seed inputs.")
    parser_eval.add_argument("--rerun", default=None,
        help="Rerun a previous experiment based on that runs database. "
             "Requires a path to the database as the argument. "
             "The rerun is done by restoring the bitcode and mutationlocation files "
             "as well as the supermutants for each program.")
    parser_eval.add_argument("--rerun-mutations", default=None,
        help="Path to a json file containing a list of mutation ids for each program to rerun, "
             "as well as a mode specifying if the original supermutants should be restored (keep) or each "
             "mutation should be analyzed individually (single). "
             "Requires the --rerun option to be used. Example: {'prog': {'ids': [1, 2, 3], 'mode': 'single'}")
    del parser_eval

    # CMD: coverage_fuzzing
    parser_coverage = subparsers.add_parser('coverage_fuzzing',
            help="Run the evaluation executing the requested fuzzers (--fuzzers) on "
                 "the requested programs (--progs) and gather the resulting data.")
    parser_coverage.add_argument("--fuzzers", nargs='+', required=True,
            help='The fuzzers to evaluate, will fail if the name is not known.')
    parser_coverage.add_argument("--progs", nargs='+', required=True,
            help='The programs to evaluate on, will fail if the name is not known.')
    parser_coverage.add_argument("--fuzz-time", required=True,
            help='Time in minutes for how long the fuzzers have to find coverage.')
    parser_coverage.add_argument("--seed-dir", required=True,
            help="The directory containing the initial seed inputs.")
    parser_coverage.add_argument("--result-dir", default=None,
            help="The directory where the coverage seed inputs that are collected during fuzzing are stored. "
                 "One directory for each fuzzer and instance.")
    parser_coverage.add_argument("--instances", type=int, default=1,
            help="The number of instances for each fuzzer, that will be run. Defaults to 1.")
    del parser_coverage

    # CMD: check_seeds 
    parser_check_seeds = subparsers.add_parser('check_seeds', help="Execute the seeds once with every fuzzer to check that they do not "
            " cause any errors, if they cause an error the seed files are deleted.")
    parser_check_seeds.add_argument("--fuzzers", nargs='+', required=True,
            help='The fuzzers to use check with.')
    parser_check_seeds.add_argument("--progs", nargs='+', required=True,
            help='The programs to check for.')
    del parser_check_seeds

    # CMD: gather_seeds 
    parser_gather_seeds = subparsers.add_parser('gather_seeds', help="Run the fuzzers on the unmutated binary to find inputs. "
            "Check the resulting fuzzing working directories for their individual results, this is not done by the framework.")
    parser_gather_seeds.add_argument("--fuzzers", nargs='+', required=True,
            help='The fuzzers to run, will fail if the name is not known.')
    parser_gather_seeds.add_argument("--progs", nargs='+', required=True,
            help='The programs to fuzz, will fail if the name is not known.')
    parser_gather_seeds.add_argument("--timeout", required=True,
            help='Time in minutes for how long the fuzzers have to find seed inputs.')
    parser_gather_seeds.add_argument("--num-repeats", type=int, default=1,
            help="How often to repeat each seed collection for each fuzzer.")
    parser_gather_seeds.add_argument("--seed-dir", required=True,
            help="The directory with the seeds to start with.")
    parser_gather_seeds.add_argument("--dest-dir", required=True,
            help="The directory where to put the found seeds.")
    parser_gather_seeds.add_argument("--per-fuzzer", default=False, action="store_true",
            help="If seeds should be gathered on a per fuzzer basis (if given) or combined (default).")
    del parser_gather_seeds

    # CMD: import_seeds 
    parser_import_seeds = subparsers.add_parser('import_seeds', help="Copy the seed files from the directory into the used seed directory. "
            "Note that the used seed directory can be specified using the MUT_SEED_DIR environment variable.")
    parser_import_seeds.add_argument("--source", help="The source seed directory.")
    parser_import_seeds.add_argument("--dest", help="The destination seed directory.")
    del parser_import_seeds

    # CMD: plot 
    parser_plot = subparsers.add_parser('plot', help="Generate plots for the gathered data")
    parser_plot.add_argument("--artifacts", default=False, action="store_true",
            help="If further detailed plots and latex tables should be written to disk.")
    parser_plot.add_argument("--skip-script", default=False, action="store_true",
            help="If plot has already been called on the current db, so eval.sql script has been executed on the db. "
                "This option can be used to skip reevaluating the "
                "script, speeding up the plot process. Useful for debugging of plotting.")
    parser_plot.add_argument("db_path", help="The sqlite database to plot.")
    del parser_plot

    # CMD: merge 
    parser_merge = subparsers.add_parser('merge', help="Merge result databases.")
    parser_merge.add_argument("out_db_path",
        help='The path where the database that contains all other databases will be stored. '
             'If this file exists it will be deleted!')
    parser_merge.add_argument("in_db_paths", nargs='+',
        help='Paths of the databases that will be merged, these dbs will not be modified.')
    del parser_merge

    # CMD: minimize_seeds 
    parser_minimize_seeds = subparsers.add_parser('minimize_seeds',
            help="Minimize the seeds by finding the minimum set (greedily) "
            "that covers all mutations reached by the full set of seeds.")
    parser_minimize_seeds.add_argument("--seed_path", required=True,
            help=f'The base dir for the seed files. Needs to be inside: {HOST_TMP_PATH}')
    parser_minimize_seeds.add_argument("--res_path", required=True,
            help=f'The path where the minimized seeds will be written to. Needs to be inside: {HOST_TMP_PATH}')
    parser_minimize_seeds.add_argument("--progs", nargs='+', required=True,
        help='The program on which to minimize the seeds.')
    parser_minimize_seeds.add_argument("--fuzzers", nargs='+', required=True,
        help='The fuzzer on which is used to minimize the seeds.')
    parser_minimize_seeds.add_argument("--per-fuzzer", default=False, action="store_true",
            help="If the inputs seed directory is already split up on a per fuzzer basis.")
    del parser_minimize_seeds

    # CMD: seed_coverage
    parser_seed_coverage = subparsers.add_parser('seed_coverage',
            help="Measure the seed coverage on the programs using kcov.")
    parser_seed_coverage.add_argument("--seed-path", required=True,
            help=f'The base dir for the seed files. Needs to be inside: {HOST_TMP_PATH}')
    parser_seed_coverage.add_argument("--res-path", required=True,
            help=f'The path where the coverage stats will be written to. Needs to be inside: {HOST_TMP_PATH}')
    parser_seed_coverage.add_argument("--prog", required=True,
        help='The program for which to measure coverage.')
    del parser_seed_coverage

    args = parser.parse_args()

    if args.cmd == 'eval':
        run_eval(args.progs, args.fuzzers, args.fuzz_time, args.num_repeats,
                 args.seed_dir, args.rerun, args.rerun_mutations)
    elif args.cmd == 'coverage_fuzzing':
        coverage_fuzzing(args.progs, args.fuzzers, args.fuzz_time,
        args.seed_dir, args.result_dir, args.instances)
    elif args.cmd == 'check_seeds':
        check_seeds(args.progs, args.fuzzers)
    elif args.cmd == 'gather_seeds':
        gather_seeds(args.progs, args.fuzzers, args.timeout, args.num_repeats,
        args.per_fuzzer, args.seed_dir, args.dest_dir)
    elif args.cmd == 'import_seeds':
        import_seeds(args.source, args.dest)
    elif args.cmd == 'plot':
        generate_plots(args.db_path, args.artifacts, args.skip_script)
    elif args.cmd == 'merge':
        merge_dbs(args.out_db_path, args.in_db_paths)
    elif args.cmd == 'minimize_seeds':
        minimize_seeds(args.seed_path, args.res_path, args.fuzzers, args.progs, args.per_fuzzer)
    elif args.cmd == 'seed_coverage':
        seed_coverage(args.seed_path, args.res_path, args.prog)
    else:
        parser.print_help(sys.stderr)

if __name__ == "__main__":
    main()
