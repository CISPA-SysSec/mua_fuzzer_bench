#!/usr/bin/env python3
from collections import defaultdict
from concurrent.futures import Future
from functools import partial
import sys
import os
import time
import subprocess
import csv
import traceback
import signal
import queue
import json
import shutil
import random
import re
from typing import Any, Dict, List, Set, Optional, Tuple, Union, cast
import concurrent.futures
import shlex
import platform
import tempfile
import copy
from itertools import product, chain, zip_longest
from pathlib import Path

import numpy as np

import docker   # type: ignore

import logging
from docker_interaction import DockerLogStreamer, run_exec_in_container, start_mutation_container, start_testing_container

from constants import EXEC_ID, MUTATOR_LLVM_DOCKERFILE_PATH, MUTATOR_LLVM_IMAGE_NAME, MUTATOR_MUATATOR_IMAGE_NAME, MUTATOR_MUTATOR_DOCKERFILE_PATH, NUM_CPUS, WITH_ASAN, WITH_MSAN, RM_WORKDIR, FILTER_MUTATIONS, \
    JUST_SEEDS, STOP_ON_MULTI, SKIP_LOCATOR_SEED_CHECK, MAX_SUPERMUTANT_SIZE, CHECK_INTERVAL, \
    HOST_TMP_PATH, UNSOLVED_MUTANTS_DIR, IN_DOCKER_WORKDIR, SHARED_DIR, IN_DOCKER_SHARED_DIR, PROGRAMS
from helpers import CoveredFile, dbg, fuzzer_container_tag, get_mut_base_bin, get_mut_base_dir, get_seed_dir, hash_file, mutation_detector_path, mutation_locations_graph_path, \
    mutation_locations_path, mutation_prog_source_path, printable_m_id, shared_dir_to_docker, subject_container_tag
from db import ReadStatsDb, Stats

# set up logging to file
logging.basicConfig(
     filename='eval.log',
     filemode='w',
     level=logging.DEBUG, 
     format= '[%(asctime)s.%(msecs)03d] %(levelname)-6s %(message)s',
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


class CoverageException(Exception):
    def __init__(self, run):
        super().__init__(run)
        self.run = run


class PreparedRuns():
    def __init__(self):
        self.runs: queue.Queue = queue.Queue()

    def get_next(self) -> Optional[dict]:
        try:
            return self.runs.get_nowait()
        except queue.Empty:
            return None

    def add(self, type_: str, data: Any):
        if type_ in ['fuzz', 'check']:
            logger.debug(f"Adding run, type: {type_} supermutant_id: {data['mut_data']['supermutant_id']} prog_bc: {data['mut_data']['prog_bc']} mutation_ids: {data['mut_data']['mutation_ids']}")
        elif type_ == 'mut':
            logger.debug(f"Adding run: {type_} {data[0]['supermutant_id']} {data[0]['mutation_ids']}")
        else:
            logger.debug(f"Adding run: {type_} {data}")

        self.runs.put_nowait({'type': type_, 'data': data})


class CpuCores():
    def __init__(self, num_cores):
        self.cores: list[bool] = [False]*num_cores

    def try_reserve_core(self) -> Optional[int]:
        try:
            idx = self.cores.index(False)
            self.cores[idx] = True
            return idx
        except ValueError:
            return None

    def release_core(self, idx):
        assert self.cores[idx] == True, "Trying to release an already free core"
        self.cores[idx] = False

    def has_free(self):
        return any(cc is False for cc in self.cores)

    def usage(self):
        return len([cc for cc in self.cores if cc]) / len(self.cores)

run_result_type = Dict[str, Any] # more precise value type: Union[bool, int, str, None, List[Dict[str, Any]]]
callgraph_type = Dict[str, List[str]]
tasks_type = Dict[Future, Tuple[str, int, Any]]

# returns true if a crashing input is found that only triggers for the
# mutated binary
def check_crashing_inputs(run_data, testing_container, crashing_inputs, crash_dir,
                          workdir, cur_time) -> run_result_type:
    if not crash_dir.is_dir():
        return { 'result': 'check_done', 'results': [] }
    check_start_time = time.time()

    res: run_result_type = {'result': 'check_done', 'results': []}
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


def base_eval_crash_check(input_dir, run_data, cur_time, testing) -> run_result_type:
    mut_data = run_data['mut_data']
    orig_bin = Path(IN_DOCKER_WORKDIR)/"tmp"/Path(mut_data['orig_bin']).relative_to(HOST_TMP_PATH)
    args = "@@"
    workdir = run_data['workdir']
    docker_mut_bin = shared_dir_to_docker(get_mut_base_bin(mut_data))
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
        res: str = nr['result']
        if res in ['orig_crash', 'orig_timeout', 'orig_timeout_by_seed']:
            key: Tuple[str, Optional[Tuple[int, ...]]] = (res, None)
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
    workdir_path = Path("mutator")/prog/printable_m_id(mut_data)/fuzzer/str(run_ctr)
    workdir_host = SHARED_DIR/workdir_path
    workdir_docker = IN_DOCKER_SHARED_DIR/workdir_path
    run_data['workdir'] = workdir_host
    crash_dir = workdir_host/run_data['crash_dir']
    prog_bc = mut_data['prog_bc']
    compile_args = build_compile_args(mut_data['compile_args'], IN_DOCKER_WORKDIR)
    seed_base_dir = mut_data['seed_base_dir']
    seeds = get_seed_dir(seed_base_dir, mut_data['prog'], run_data['fuzzer'])
    dictionary = mut_data['dict']
    core_to_use = run_data['used_core']

    workdir_host.mkdir(parents=True, exist_ok=True)

    # get path for covered files
    covered = CoveredFile(workdir_path, start_time)

    results: run_result_type = {}

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
        crashing_inputs: Dict[Path, dict] = {}

        # get access to the docker client to start the container
        docker_client = docker.from_env()
        # Start and run the fuzzing container
        container = docker_client.containers.run(
            docker_image, # the image
            [
                "/home/user/eval.sh",
                str(shared_dir_to_docker(prog_bc)),
                str(compile_args),
                str(IN_DOCKER_WORKDIR/seeds),
            ], # the arguments
            environment={
                'TRIGGERED_OUTPUT': str(""),
                'TRIGGERED_FOLDER': str(covered.docker_path),
                **({'DICT_PATH': str(Path(IN_DOCKER_WORKDIR)/dictionary)} if dictionary is not None else {}),
                **({'MUT_WITH_ASAN': '1'} if WITH_ASAN else {}),
                **({'MUT_WITH_MSAN': '1'} if WITH_MSAN else {}),
            },
            init=True,
            cpuset_cpus=str(core_to_use),
            auto_remove=True,
            volumes={
                str(HOST_TMP_PATH): {'bind': str(IN_DOCKER_WORKDIR)+"/tmp/", 'mode': 'ro'},
                str(SHARED_DIR): {'bind': str(IN_DOCKER_SHARED_DIR), 'mode': 'rw'},
            },
            working_dir=str(workdir_docker),
            mem_swappiness=0,
            log_config=docker.types.LogConfig(type=docker.types.LogConfig.types.JSON,
                config={'max-size': '10m'}),
            detach=True
        )

        logs_queue: queue.Queue = queue.Queue()
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
                                                crash_dir, workdir_host, time.time() - start_time)
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
                                    crash_dir, workdir_host, time.time() - start_time)
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


def eval_dispatch_func(run_data, run_func, crash_dir, container_tag):
    run_data['crash_dir'] = crash_dir
    result = run_func(run_data, fuzzer_container_tag(container_tag))
    return result


def load_fuzzers():
    fuzzers = {}
    for fuzzer_dir in Path("dockerfiles/fuzzers").iterdir():
        if fuzzer_dir.name.startswith("."):
            continue # skip hidden files

        if fuzzer_dir.name == "system":
            continue

        if not fuzzer_dir.is_dir():
            continue
        
        fuzzer_config_path = fuzzer_dir/"config.json"
        with open(fuzzer_config_path, "r") as f:
            fuzzer_config = json.load(f)

        fuzzer_name = fuzzer_dir.name
        fuzzer_crash_dir = fuzzer_config["crash_dir"]
        partial_eval_func = partial(
            eval_dispatch_func,
            crash_dir=fuzzer_crash_dir, container_tag=fuzzer_name
        )

        fuzzers[fuzzer_name] = {
            "eval_func": partial_eval_func,
            "queue_dir": fuzzer_config["queue_dir"],
            "queue_ignore_files": fuzzer_config["queue_ignore_files"],
            "crash_dir": fuzzer_crash_dir,
            "crash_ignore_files": fuzzer_config["crash_ignore_files"],
        }

    return fuzzers


FUZZERS = load_fuzzers()


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
    workdir_path = Path("mutator")/prog/printable_m_id(mut_data)/fuzzer/str(run_ctr)
    workdir_host = SHARED_DIR/workdir_path
    workdir_docker = IN_DOCKER_SHARED_DIR/workdir_path
    run_data['workdir'] = workdir_host
    inputs_to_check = mut_data['check_run_input_dir']
    core_to_use = run_data['used_core']

    workdir_host.mkdir(parents=True, exist_ok=True)

    # get path for covered files
    covered = CoveredFile(workdir_path, start_time)

    results: run_result_type = {}

    # start testing container
    with start_testing_container(core_to_use, covered, timeout + 60*60) as testing_container:

        new_results = base_eval_crash_check(inputs_to_check, run_data, time.time() - start_time, testing_container)

        res = update_results(results, new_results, start_time)

        # clean up tmp dir
        shutil.rmtree(inputs_to_check)

        if res is not None:
            return res

        # did not find a crash, restart this mutation
        return {
            'result': 'retry',
            'total_time': time.time() - start_time,
            'data': results,
            'all_logs': [],
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
def find_reachable(call_g: callgraph_type, fnA: str, reachable_keys: Optional[Dict[str, Set[str]]] = None, found_so_far: Optional[Set[str]] = None) -> Set[str]:
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
def reachable_dict(call_g: callgraph_type) -> Dict[str, Set[str]]:
    reachable: Dict[str, Set[str]] = {}
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


def load_call_graph(callgraph, mutants) -> callgraph_type:
    my_g: callgraph_type = {}
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

def find_supermutants(matrix, keys, mutants) -> List[List[int]]:
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
    result: Dict[str, List[str]] = dict()
    mapping: Dict[Tuple, List[str]] = dict()
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


def get_supermutations_callgraph(prog_info, mutations):
    graph_info: Dict[str, callgraph_type] = {}
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
    new_supermutants: List[List[int]] = []
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


def indirect_call_info(graph):
    """
    Takes the graph and collects a dictionary of calls by their types.
    """
    mapping = defaultdict(list)
    # first get an initial mapping of the result set and collect all known functions
    for key in graph.keys():
        key_splitted = key.split(SPLITTER)[:-1]
        funname = key_splitted[0]
        type_key = tuple(key_splitted[1:])
        mapping[type_key].append(funname)

    return mapping

"""
def get_supermutations_cfg(prog_info, mutations):
    import cfg_supermutants
    entry_node = 'LLVMFuzzerTestOneInput'
    cfg_base_dir = Path('tmp/cfgs')

    with open(mutation_locations_graph_path(prog_info), 'rt') as f:
        call_graph = json.load(f)

    call_info = indirect_call_info(call_graph)

    muts = [
        (mm[0], mm[3][mm[0]]['funname'], mm[3][mm[0]]['instr'])
        for mm in mutations
    ]

    try:
        shutil.rmtree(cfg_base_dir)
    except OSError as err:
        logger.info(f"Could not clean up {cfg_base_dir}: {err}")

    cfg_base_dir.mkdir(parents=True, exist_ok=True)
    with start_mutation_container(None, None) as container:
        tmp_dir = cfg_base_dir/"dots"
        tmp_dir.mkdir()
        bc_path_in_container = Path("/home/mutator", prog_info['orig_bc'])
        tmp_dir_in_container = Path("/home/mutator/tmp/cfgs", Path(tmp_dir).name)
        run_exec_in_container(
            container, raise_on_error=True,
            cmd=["opt", "-passes=dot-cfg", "-debug-pass-manager", str(bc_path_in_container), "-S", "-o", "bitcode.ll"],
            exec_args=['--workdir', str(tmp_dir_in_container)],
        )
        cfg_graph, bitcode = cfg_supermutants.create_initial_graph(tmp_dir)

    call_graph = cfg_supermutants.add_function_call_edges(cfg_graph, call_info)
    print("CFG:", cfg_graph, "call graph:", call_graph)
    # print(call_graph.out_edges("LLVMFuzzerTestOneInput"))

    cfg_supermutants.load_mutations(cfg_graph, muts)

    tc_cfg_graph = cfg_supermutants.transitive_closure(cfg_graph)
    tc_call_graph = cfg_supermutants.transitive_closure(call_graph)

    reachable_muts = cfg_supermutants.get_reachable_mutants(cfg_graph, call_graph, entry_node)
    print(f"Found {len(reachable_muts)} reachable mutations (from {entry_node}) based on cfg and call graph.")

    # mut_info = mutations[0][3]
    # for rm in reachable_muts:
    #     funname = mut_info[rm]['funname']
    #     line = mut_info[rm]['line']
    #     col = mut_info[rm]['column']
    #     file_path = mut_info[rm]['filePath']
    #     directory = mut_info[rm]['directory']
    #     mut_type = mut_info[rm]['type']
    #     print(rm, mut_type, funname, f"{directory}/{file_path}:{line}:{col}")
    #     # print(mm[0], mm[3][mm[0]]['funname'], mm[3][mm[0]]['instr'])

    supermutants = cfg_supermutants.get_supermutants(tc_cfg_graph, tc_call_graph, reachable_muts)

    print(f"Generated {len(supermutants)} supermutants out of {len(reachable_muts)} reachable mutants ", end='')
    print(f"a reduction of {(len(reachable_muts) + len(tc_cfg_graph.graph['mut_failed'])) / len(supermutants)}. Failed muts: {len(tc_cfg_graph.graph['mut_failed'])}.")

    # For testing if there are supermutants where multiple mutants are seen in one execution.
    # supermutants = [sm for sm in supermutants if len(sm) > 1]

    return supermutants, None


def get_supermutations_simple_reachable(prog_info, mutations):
    import cfg_supermutants
    entry_node = 'LLVMFuzzerTestOneInput'
    cfg_base_dir = Path('tmp/cfgs')

    with open(mutation_locations_graph_path(prog_info), 'rt') as f:
        call_graph = json.load(f)

    call_info = indirect_call_info(call_graph)

    muts = [
        (mm[0], mm[3][mm[0]]['funname'], mm[3][mm[0]]['instr'])
        for mm in mutations
    ]

    try:
        shutil.rmtree(cfg_base_dir)
    except OSError as err:
        logger.info(f"Could not clean up {cfg_base_dir}: {err}")

    cfg_base_dir.mkdir(parents=True, exist_ok=True)
    with start_mutation_container(None, None) as container:
        tmp_dir = cfg_base_dir/"dots"
        tmp_dir.mkdir()
        bc_path_in_container = Path("/home/mutator", prog_info['orig_bc'])
        tmp_dir_in_container = Path("/home/mutator/tmp/cfgs", Path(tmp_dir).name)
        run_exec_in_container(
            container, raise_on_error=True,
            cmd=["opt", "-passes=dot-cfg", "-debug-pass-manager", str(bc_path_in_container), "-S", "-o", "bitcode.ll"],
            exec_args=['--workdir', str(tmp_dir_in_container)],
        )
        cfg_graph, bitcode = cfg_supermutants.create_initial_graph(tmp_dir)

    call_graph = cfg_supermutants.add_function_call_edges(cfg_graph, call_info)
    print("CFG:", cfg_graph, "call graph:", call_graph)
    # print(call_graph.out_edges("LLVMFuzzerTestOneInput"))

    cfg_supermutants.load_mutations(cfg_graph, muts)

    reachable_muts = cfg_supermutants.get_reachable_mutants(cfg_graph, call_graph, entry_node)
    print(f"Found {len(reachable_muts)} reachable mutations (from {entry_node}) based on cfg and call graph.")

    supermutants = [[mm] for mm in reachable_muts]

    print(f"Generated {len(supermutants)} supermutants out of {len(reachable_muts)} reachable mutants ", end='')
    print(f"a reduction of {(len(reachable_muts)) / len(supermutants)}")

    # For testing if there are supermutants where multiple mutants are seen in one execution.
    # supermutants = [sm for sm in supermutants if len(sm) > 1]

    return supermutants, None
 """

def measure_mutation_coverage_per_file(mutator, prog_info, seed_dir):
    detector_path = mutation_detector_path(prog_info)
    args = "@@"
    # create tmp folder to where to put trigger signals
    with tempfile.TemporaryDirectory(dir=HOST_TMP_PATH) as trigger_folder, \
         tempfile.TemporaryDirectory(dir=HOST_TMP_PATH) as result_dir:
        result_file = Path(result_dir)/"results.json"
        in_docker_trigger_folder = Path('/home/mutator/tmp/').joinpath(Path(trigger_folder).relative_to(HOST_TMP_PATH))
        in_docker_result_file = Path('/home/mutator/tmp/').joinpath(Path(result_file).relative_to(HOST_TMP_PATH))
        in_docker_seed_dir = Path('/home/mutator/tmp/').joinpath(Path(seed_dir).resolve().relative_to(HOST_TMP_PATH))
        # start detector and run through all seed files
        run = run_exec_in_container(mutator.name, False,
            [
                '/home/mutator/iterate_seeds_individual.py',
                '--seeds', in_docker_seed_dir,
                '--args', args,
                '--binary', detector_path,
                '--workdir', '/home/mutator',
                '--results-file', str(in_docker_result_file),
            ],
            exec_args=['--env', f"TRIGGERED_FOLDER={in_docker_trigger_folder}"],
            timeout=60*60*4)

        if run['timed_out'] or run['returncode'] != 0:
            logger.info(f"Got returncode != 0: {run['returncode']}")
            print(run['out'])
            raise CoverageException(run)

        with open(result_file, 'rt') as f:
            data = json.load(f)
        return data


def get_supermutations_seed_reachable(prog, prog_info, mutations, mutator_container, seed_base_dir, fuzzers):
    MAX_SM_SIZE = 200

    mut_data = {mm[0]: mm[3][mm[0]] for mm in mutations}

    covered_mutations = set()
    input_coverages: Dict[int, Set[int]] = defaultdict(set)
    for fuzzer in fuzzers:
        seeds = get_seed_dir(seed_base_dir, prog, fuzzer)
        seed_covered_mutations = measure_mutation_coverage_per_file(mutator_container, prog_info, seeds)
        for scv in seed_covered_mutations.values():
            scv = set(scv)
            covered_mutations |= scv
            for mm in scv:
                input_coverages[mm] |= scv

    # some mutations are in omitted functions, however, this is not respected in the coverage measurement
    # do this filtering now
    covered_mutations = set(filter(lambda x: x in mut_data, covered_mutations))
            
    mutations_todo = sorted(list(covered_mutations), key=lambda mm: len(input_coverages[mm]), reverse=True)
    supermutants = []

    while mutations_todo:
        used_funcs = set()
        candidates = mutations_todo.copy()
        supermutant = []
        collisions = set()

        while candidates:
            mt = candidates.pop()
            candidate_fun = mut_data[mt]['funname']
            if candidate_fun not in used_funcs:
                used_funcs.add(candidate_fun)
                supermutant.append(mt)
                collisions |= input_coverages[mt]
                candidates = list(filter(lambda x: x not in collisions, candidates))
                if len(supermutant) >= MAX_SM_SIZE:
                    break

        for can in supermutant:
            mutations_todo.remove(can)
        
        supermutants.append(supermutant)

    all_mutations = set(mm[0] for mm in mutations)
    not_covered_mutations = all_mutations - covered_mutations

    nc_mut_per_instr = defaultdict(list)
    for nc_mut in not_covered_mutations:
        funname = mut_data[nc_mut]['funname']
        bb_name = mut_data[nc_mut]['bb_name']
        instr = mut_data[nc_mut]['instr']
        # nc_mut_per_instr[(funname, instr)].append(nc_mut) # 53
        # nc_mut_per_instr[(funname, bb_name)].append(nc_mut) # 58
        nc_mut_per_instr[funname].append(nc_mut) # 479

    not_covered_supermutants = []
    while len(nc_mut_per_instr) > 0:
        supermutant = []
        done_locs = []
        for loc in nc_mut_per_instr:
            nc_muts = nc_mut_per_instr[loc]
            try:
                supermutant.append(nc_muts.pop())
            except IndexError:
                done_locs.append(loc)
            if len(nc_muts) == 0:
                done_locs.append(loc)

            if len(supermutant) >= MAX_SM_SIZE:
                break

        for dl in done_locs:
            nc_mut_per_instr.pop(dl)

        # Order in reversed
        supermutant = list(sorted(supermutant, reverse=True))

        not_covered_supermutants.append(supermutant)

    logger.info(
        f"Generated {len(supermutants)} supermutants out of {len(covered_mutations)} " +
        f"covered mutants a reduction of {(len(covered_mutations)) / len(supermutants):.2f}")

    logger.info(
        f"Generated {len(not_covered_supermutants)} supermutants out of {len(not_covered_mutations)} " +
        f"not covered mutants a reduction of {(len(not_covered_mutations)) / len(not_covered_supermutants):.2f}")

    return supermutants + not_covered_supermutants, {
        'covered': list(covered_mutations),
        'covered_supermutants': list(supermutants),
        'not_covered': list(not_covered_mutations),
        'not_covered_supermutants': list(not_covered_supermutants),
    }


def get_all_mutations(stats, mutator, progs: List[str], seed_base_dir, fuzzers: List[str], rerun, rerun_mutations):
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

        mutations = list((int(p['UID']), prog, prog_info, mutation_data) for p in mutation_data)

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
            mutations = list((int(mut_id), prog, prog_info, mutation_data) for mut_id in filtered_mutations)
            logger.info(f"After filtering: found {len(mutations)} mutations for {prog}")

        if rerun:
            supermutations_raw = rerun.get_supermutations(prog)
            expected_exec_id = supermutations_raw[0]['exec_id']
            len_sm = max(sm['super_mutant_id'] for sm in supermutations_raw) + 1
            mutations_set = set(int(mm[0]) for mm in mutations)
            supermutations: List[List[int]] = [[] for _ in range(len_sm)]
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
            # supermutations, graph_info = get_supermutations_simple_reachable(prog_info, mutations)
            supermutations, graph_info = get_supermutations_seed_reachable(prog, prog_info, mutations, mutator, seed_base_dir, fuzzers)
            stats.new_supermutant_graph_info(EXEC_ID, prog, graph_info)


        for ii, sm in enumerate(supermutations):
            stats.new_initial_supermutant(EXEC_ID, prog, ii, sm)

        s_mutations = list((sm, prog, prog_info, mutation_data) for sm in supermutations)

        all_mutations.extend(s_mutations)
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

# Generator that first collects all possible runs and adds them to stats.
# Then yields all information needed to start a eval run
def get_all_runs(stats, fuzzers, progs, seed_base_dir, timeout, num_repeats, rerun, rerun_mutations):
    with start_mutation_container(None, 24*60*60) as mutator:
        all_mutations = get_all_mutations(stats, mutator, progs, seed_base_dir, fuzzers, rerun, rerun_mutations)

        all_mutations = sequence_mutations(all_mutations)

        # measure coverage by seeds
        if not SKIP_LOCATOR_SEED_CHECK and rerun is None:
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
                'mutation_ids': [int(mm) for mm in m_id],
                # 'mutation_ids': m_id,
                'mutation_data': [mutation_data[int(mut_id)] for mut_id in m_id],
            }

            # For each fuzzer gather all information needed to start a eval run
            fuzzer_runs = []
            for fuzzer in fuzzers:
                try:
                    eval_func = FUZZERS[fuzzer]['eval_func']
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


def split_up_supermutant(multi_tp: Set[Tuple[int, ...]], all_muts_list: List[int]):
    """
    Split up the mutants listed in all_muts, into as many chunks as there are mutants in multi, making sure that the
    mutants listed in multi end up in different chunks. This can be used to split up a supermutant where
    multiple mutations are covered at once.
    """
    multi_set: Set[int] = set(chain(*multi_tp))
    all_muts = set([int(mm) for mm in all_muts_list])
    assert all_muts & multi_set == multi_set, f"Not all covered mutations are in the possible mutations, something is wrong. " \
                                      f"all_muts: {all_muts}, multi: {multi_set}"
    others_set = all_muts - multi_set

    chunk_size = int(len(others_set) / len(multi_set)) + 1
    multi = list(multi_set)
    others = list(others_set)

    mut_chunks = []

    ii: Union[int, list]
    cc: Union[List[int], list]
    for ii, cc in zip_longest(range(len(multi)), list(chunks(others, chunk_size)), fillvalue=[]):
        ii = cast(int, ii)
        chosen = [multi[ii]] + cc
        mut_chunks.append(chosen)

    logger.debug(f"{multi}\n{mut_chunks}\n{all_muts}")
    assert len(list(chain(*mut_chunks))) == len(all_muts), f"mut_chunks: {len(list(chain(*mut_chunks)))}, all_muts: {len(all_muts)}"
    assert set(chain(*mut_chunks)) == all_muts, f"mut_chunks: {mut_chunks}, all_muts: {all_muts}"
    return mut_chunks


def split_up_supermutant_by_distance(mutation_ids: Set[int]) -> Tuple[List[int], List[int]]:
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

def has_result(mut_id: int, results: List[Dict[str, Any]], to_search: List[str]) -> Optional[Dict[str, Any]]:
    unhandled_search_types = set(to_search) - HANDLED_RESULT_TYPES
    assert unhandled_search_types == set(), f'Unhandled search types: {unhandled_search_types}'
    unhandled_result_types = set(rr['result'] for rr in results) - HANDLED_RESULT_TYPES
    assert unhandled_result_types == set(), f'Unhandled result types: {unhandled_result_types}'

    for res in [rr for rr in results if rr['result'] in [*to_search]]:
        if mut_id in res['mutation_ids']:
            return res
    return None

def collect_input_paths(workdir, fuzzer_name):
    queue_dir = FUZZERS[fuzzer_name]['queue_dir']
    queue_ignore_files = FUZZERS[fuzzer_name]['queue_ignore_files']
    crash_dir = FUZZERS[fuzzer_name]['crash_dir']
    crash_ignore_files = FUZZERS[fuzzer_name]['crash_ignore_files']

    found = [
        pp for pp in (workdir/queue_dir).glob("*")
        if pp.name not in queue_ignore_files
    ]
    crashes = [
        pp for pp in (workdir/crash_dir).glob("*")
        if pp.name not in crash_ignore_files
    ]
    return list(found) + list(crashes)

def copy_fuzzer_inputs(data):
    tmp_dir = Path(tempfile.mkdtemp(dir=SHARED_DIR/"mutator_tmp"))
    found_inputs = collect_input_paths(data['workdir'], data['fuzzer'])
    logger.warning(f"collect_input_paths: {found_inputs}")
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
def handle_run_result(stats, prepared_runs, active_mutants, run_future, data) -> None:
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
            multi_ids = set([tuple(sorted(mm['mutation_ids'])) for mm in multi if len(mm.get('mutation_ids', [])) > 1])
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

            killed_mutants: set[int] = set()
            for mut_id in all_mutation_ids:
                num_seed_covered = 1 if has_result(mut_id, results, ['covered_by_seed']) else 0
                num_timeout = 1 if has_result(mut_id, results, ['timeout_by_seed']) else None
                killed = has_result(mut_id, results, ['killed_by_seed'])

                if killed or num_timeout:
                    stats.new_seeds_executed(
                        EXEC_ID, prog, mut_id, data['run_ctr'], data['fuzzer'],
                        num_seed_covered, num_timeout, total_time)

                    if killed is not None:
                        stats.new_seed_crashing_inputs(EXEC_ID, prog, mut_id, data['fuzzer'], [killed])

                    killed_mutants |= set([mut_id])
                    stats.done_run('killed_by_seed', EXEC_ID, mut_data['prog'], mut_id, data['run_ctr'], data['fuzzer'])

            if len(killed_mutants) == 0:
                for rr in results:
                    if rr['result'] == "timout_by_seed" and len(rr['mutation_ids']) == 0:
                        chunk_1, chunk_2 = split_up_supermutant_by_distance(all_mutation_ids)
                        recompile_and_run(prepared_runs, data, stats.next_supermutant_id(), chunk_1)
                        recompile_and_run(prepared_runs, data, stats.next_supermutant_id(), chunk_2)
                    break
                else:  # no break
                    assert len(killed_mutants) >= 1, f"Expected at least one mutant to be killed.: {results} {all_mutation_ids}"
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

            def record_run_done(covered_time, total_time, prog, fuzzer, run_ctr, mut_id):
                stats.new_run_executed(
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
            results = sorted(run_result['data'].values(), key=lambda x: x['time'])
            del run_result

            record_supermutant_multi(stats, mut_data, results, data['fuzzer'], data['run_ctr'], 'killed')

            all_mutation_ids = set(int(mm) for mm in mut_data['mutation_ids'])
            assert len(all_mutation_ids) > 0
            for rr in results:
                assert 'mutation_ids' in rr, f"{results}"
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
                    killed_mutants = set(chain(*[rr['mutation_ids']
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
                        record_run_done(covered_time, total_time, prog, data['fuzzer'], data['run_ctr'], mut_id)

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
                                record_run_done(covered_time, total_time,
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
                        cur_mutations = set((int(m_id) for m_id in mut_data['mutation_ids']))
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
                    logger.info(f"= run ###:      {mut_data['prog']}:{printable_m_id(mut_data)}:{data['fuzzer']}")
                    logger.info(f"! rerunning in chunks (unexpected completion time: {actual_time}, expected: {expected_time})")

                    chunk_1, chunk_2 = split_up_supermutant_by_distance(mutation_ids)
                    recompile_and_run(prepared_runs, data, stats.next_supermutant_id(), chunk_1)
                    recompile_and_run(prepared_runs, data, stats.next_supermutant_id(), chunk_2)
                else:
                    mut_id = mutation_ids[0]
                    stats.run_crashed(EXEC_ID, mut_data['prog'], mut_id, data['run_ctr'], data['fuzzer'],
                    f"unexpected completion time\n\n{logs}")

                    stats.done_run('unexpected_completion_time', EXEC_ID, mut_data['prog'], mut_id, data['run_ctr'], data['fuzzer'])
                    logger.info(f"= run ###:      {mut_data['prog']}:{printable_m_id(mut_data)}:{data['fuzzer']}")
                    logger.info(f"! unexpected completion time: {actual_time}, expected: {expected_time}")
            else:
                logger.info(f"= run [+]:      {prog}:{printable_m_id(mut_data)}:{data['fuzzer']}")
                total_time = run_result['total_time']
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
    workdir = SHARED_DIR/"mutator"/mut_data['prog']/printable_m_id(mut_data)/data['fuzzer']/str(data['run_ctr'])
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
        workdir = SHARED_DIR/"mutator"/mut_data['prog']/printable_m_id(mut_data)/fr['fuzzer']/str(fr['run_ctr'])
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
    workdir = SHARED_DIR/"mutator"/mut_data['prog']/printable_m_id(mut_data)/data['fuzzer']/str(data['run_ctr'])
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


def wait_for_task(stats, tasks: tasks_type, cores: CpuCores, prepared_runs, active_mutants):
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

    covered_dir = SHARED_DIR/"covered"
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


    if WITH_ASAN:
        compile_args = "-fsanitize=address " + compile_args
    if WITH_MSAN:
        compile_args = "-fsanitize=memory " + compile_args

    # get path for covered file and rm the file if it exists
    covered = CoveredFile(Path("mut_base")/data['prog']/printable_m_id(data), time.time())

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
                    "--out-dir", str(shared_dir_to_docker(mut_base_dir)),
                    data['orig_bc']
            ])
        except Exception as exc:
            raise RuntimeError(f"Failed to compile mutation") from exc

        with open(prog_ll, 'rt') as f:
            ll_data = f.read()
            for mid in data['mutation_ids']:
                assert ll_data.find(f"signal_triggered_mutation(i64 {mid})") != -1, \
                    f"Did not find \"signal_triggered_mutation(i64 {mid})\" in {prog_ll}. " \
                    f"All expected mutation ids ({len(data['mutation_ids'])}): {data['mutation_ids']}"

        try:
            clang_args = [
                "/usr/bin/clang++-11",
                "-v",
                "-o", str(shared_dir_to_docker(mut_base_dir/"mut_base")),
                "/workdir/tmp/lib/libdynamiclibrary.so",
                str(shared_dir_to_docker(prog_bc)),
                *shlex.split(compile_args),
            ] 
            # compile the compare version of the mutated binary
            clang_res = run_exec_in_container(testing, True, clang_args)
        except Exception as exc:
            raise RuntimeError(f"Failed to compile mutation:\n{clang_args}\nrun_mutation output:\n{run_mut_res}\n") from exc





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
            "-f", f"dockerfiles/subjects/Dockerfile.{name}",
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
            "-f", "dockerfiles/fuzzers/Dockerfile.testing",
            "."
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode != 0:
        try:
            stdout = proc.stdout.decode()
        except:
            stdout = str(proc.stdout)
        logger.info(f"Could not build testing image.\n"
                f"{proc.args} -> {proc.returncode}\n"
                f"{stdout}")
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
            "-f", f"dockerfiles/fuzzers/{name}/Dockerfile",
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


def start_next_task(prepared_runs: PreparedRuns, all_runs, tasks: tasks_type, executor, stats, start_time, num_runs, core: int, ii: int):
    # Check if any runs are prepared
    while True:
        run_data = prepared_runs.get_next()
        if run_data is not None:
            break
        else:
            # No runs are ready, prepare a mutation and all corresponding runs.
            try:
                # Get the next mutant
                ii, (mut_data, fuzzer_runs) = next(all_runs)

                prepared_runs.add('mut', (mut_data, fuzzer_runs))

            except StopIteration:
                # Done with all mutations and runs, break out of this loop and finish eval.
                return False

    # A task is ready to start, get it and start the run.
    if run_data['type'] == 'fuzz':
        run_data = run_data['data']
        run_data = cast(Dict[str, Any], run_data)
        # update core, print message and submit task
        run_data['used_core'] = core
        print_run_start_msg(run_data)
        tasks[executor.submit(run_data['eval_func'], run_data, base_eval)] = ("run", core, run_data)
    elif run_data['type'] == 'check':
        run_data = run_data['data']
        run_data = cast(Dict[str, Any], run_data)
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


def run_eval(progs, fuzzers, timeout, num_repeats, seed_base_dir, rerun, rerun_mutations, fresh_images):
    global should_run

    if rerun_mutations is not None:
        assert rerun is not None, "To use the --rerun-mutations options the --rerun option is required."

    prepare_mutator_docker_image(fresh_images)
    prepare_shared_dir_and_tmp_dir()

    seed_base_dir = Path(seed_base_dir)
    execution_start_time = time.time()

    # prepare environment
    base_shm_dir = SHARED_DIR/"mutator"
    base_shm_dir.mkdir(parents=True, exist_ok=True)
    base_shm_dir = SHARED_DIR/"mutator_tmp"
    base_shm_dir.mkdir(parents=True, exist_ok=True)

    # Initialize the stats object
    stats = Stats(str(SHARED_DIR/"mutator/stats.db"))

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
    active_mutants: Dict[Path, Dict[str, Union[int, bool]]] = defaultdict(lambda: {'ref_cnt': 0, 'killed': False})

    # for each mutation and for each fuzzer do a run
    with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_CPUS) as executor:
        # keep a list of all tasks
        tasks: tasks_type = {}
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
                eval_func = FUZZERS[fuzzer]['eval_func']
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
                    dir=str(SHARED_DIR/"mutator_seed_gathering")))

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


def wait_for_seed_run(tasks: tasks_type, cores: CpuCores, all_runs):
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
            str(SHARED_DIR): {'bind': str(IN_DOCKER_SHARED_DIR), 'mode': 'rw'},
        },
        working_dir=str(shared_dir_to_docker(workdir)),
        mem_limit="10g",
        mem_swappiness=0,
        log_config=docker.types.LogConfig(type=docker.types.LogConfig.types.JSON,
            config={'max-size': '10m'}),
        detach=True
    )

    logs_queue: queue.Queue = queue.Queue()
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
                eval_func = FUZZERS[fuzzer]['eval_func']
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
            str(SHARED_DIR): {'bind': str(IN_DOCKER_SHARED_DIR), 'mode': 'rw'},
        },
        working_dir=str(workdir),
        mem_limit="10g",
        mem_swappiness=0,
        log_config=docker.types.LogConfig(type=docker.types.LogConfig.types.JSON,
            config={'max-size': '10m'}),
        detach=True
    )

    logs_queue: queue.Queue = queue.Queue()
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
    base_shm_dir = SHARED_DIR/"mutator_check_seeds"
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
    seed_coverage_base_shm_dir = SHARED_DIR/"mutator_seed_gathering"
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
    seed_runs: List[Dict[str, Any]] = []
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

        logger.debug(f"Collecting seeds from {seed_source} for {prog} {fuzzer} {instance}")
        found_seeds = collect_input_paths(seed_source, fuzzer)

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

    minimize_shm_dir = SHARED_DIR/"minimize_coverage_seeds"
    shutil.rmtree(minimize_shm_dir, ignore_errors=True, onerror=lambda *x: logger.warning(x))
    minimize_shm_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Minimizing seeds ...")
    for ii, sr in enumerate(seed_runs):
        logger.info(f"{ii+1} / {len(seed_runs)}")
        sr_fuzzer = sr['fuzzer']
        sr_prog = sr['prog']
        sr_seed_path = Path(sr['dir'])
        sr_minimized_dir = all_minimized_runs_dir.joinpath(sr_seed_path.relative_to(all_runs_dir))
        sr_minimized_dir.mkdir(parents=True)
        sr['minimized_dir'] = str(sr_minimized_dir)
        minimize_seeds_one(minimize_shm_dir, sr_prog, sr_fuzzer, sr_seed_path, sr_minimized_dir)
        minimized_files = list(Path(sr['minimized_dir']).glob("*"))
        sr['num_seeds_minimized'] = len(minimized_files)


    with start_mutation_container(None, None) as mutator:
        logger.info("Instrumenting progs ...")
        for prog in set(sr['prog'] for sr in seed_runs):
            logger.info(prog)
            prog_info = PROGRAMS[prog]
            instrument_prog(mutator, prog_info)

        kcov_res_dir = SHARED_DIR/"kcov_res"
        shutil.rmtree(kcov_res_dir, ignore_errors=True)
        kcov_res_dir.mkdir(parents=True)

        seed_coverage_base_shm_dir = SHARED_DIR/"seed_coverage"
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

    runs_by_prog_fuzzer: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
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
                for table in ['execution', 'all_runs', 'mutations', 'progs', 'executed_runs', 'executed_seeds', 
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
            str(shared_dir_to_docker(seeds_in)),
            str(shared_dir_to_docker(seeds_out)),
        ], # the arguments
        environment={
            **({'DICT_PATH': str(Path(IN_DOCKER_WORKDIR)/dictionary)} if dictionary is not None else {}),
        },
        init=True,
        auto_remove=True,
        volumes={
            str(HOST_TMP_PATH): {'bind': str(IN_DOCKER_WORKDIR)+"/tmp/", 'mode': 'ro'},
            str(SHARED_DIR): {'bind': str(IN_DOCKER_SHARED_DIR), 'mode': 'rw'},
        },
        working_dir=str(shared_dir_to_docker(workdir)),
        mem_swappiness=0,
        log_config=docker.types.LogConfig(type=docker.types.LogConfig.types.JSON,
            config={'max-size': '10m'}),
        detach=True
    )

    del seeds_in
    del seeds_out
    del workdir

    logs_queue: queue.Queue = queue.Queue()
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
        eval_func = FUZZERS[fuzzer]['eval_func']
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
    base_shm_dir = SHARED_DIR/"minimize_seeds"
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
    in_docker_workdir = shared_dir_to_docker(workdir)

    # get access to the docker client to start the container
    docker_client = docker.from_env()

    # Start and run the container
    container = docker_client.containers.run(
        docker_image, # the image
        [
            "/home/mutator/seed_coverage.py",
            "--prog", str(shared_dir_to_docker(orig_bin)),
            "--prog-args", str(args),
            "--seeds", str(shared_dir_to_docker(seed_path)),
            "--workdir", str(in_docker_workdir),
        ], # the arguments
        user=os.getuid(),
        privileged=True,
        init=True,
        auto_remove=True,
        volumes={
            str(HOST_TMP_PATH): {'bind': str(IN_DOCKER_WORKDIR)+"/tmp/", 'mode': 'ro'},
            str(SHARED_DIR): {'bind': str(IN_DOCKER_SHARED_DIR), 'mode': 'rw'},
        },
        working_dir=str(in_docker_workdir),
        mem_swappiness=0,
        log_config=docker.types.LogConfig(type=docker.types.LogConfig.types.JSON,
            config={'max-size': '10m'}),
        detach=True
    )

    logs_queue: queue.Queue = queue.Queue()
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

    with tempfile.TemporaryDirectory(dir=str(SHARED_DIR/"seed_coverage")) as ad:
        active_dir = Path(ad)

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
    base_shm_dir = SHARED_DIR/"seed_coverage"
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


def prepare_mutator_docker_image(fresh_images):
    """
    Prepare the docker image for the mutator.
    """
    def run_command(command):
        proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if proc.returncode != 0:
            try:
                stdout = proc.stdout.decode()
            except:
                stdout = str(proc.stdout)

            logger.error(f"Could not run command.\n"
                  f"{proc.args} -> {proc.returncode}\n"
                  f"{stdout}")
            raise ValueError("Could not run command.")

    # build llvm image
    logger.info("Building LLVM container.")
    run_command([
        "docker", "build",
        *(["--pull", "--no-cache"] if fresh_images else []),
        "-t", MUTATOR_LLVM_IMAGE_NAME,
        "-f", MUTATOR_LLVM_DOCKERFILE_PATH, "."
    ])

    logger.info("Building mutator container.")
    run_command([
        "docker", "build",
        *(["--no-cache"] if fresh_images else []),
        "-t", MUTATOR_MUATATOR_IMAGE_NAME,
        "-f", MUTATOR_MUTATOR_DOCKERFILE_PATH, "."
    ])

    # # build Mutator image
    # if proc.returncode != 0:
    #     print_fail("LLVM image was not properly built. Check output for details.")
    #     exit(1)
    # print("Building Mutator container.")
    # if args.no_cache:
    # else:
    #     proc = subprocess.run(["docker", "build", "-t", mutator_image, "-f", mutator_dockerfile, "."])
    # if proc.returncode != 0:
    #     print_fail("Mutator image was not properly built. Check output for details.")
    #     exit(1)
    # print_pass("Successfully built Mutator Docker container.")


def prepare_shared_dir_and_tmp_dir():
    """
    Prepare the shared dir and ./tmp dir for the evaluation containers.
    The shared dir will be deleted if it already exists.
    """

    # SHARED_DIR
    if SHARED_DIR.exists():
        if SHARED_DIR.is_dir():
            logger.info(f"Cleaning up already existing shared dir: {SHARED_DIR}.")
            try:
                shutil.rmtree(SHARED_DIR)
            except OSError as err:
                logger.info(f"Could not clean up {SHARED_DIR}: {err}")
        if SHARED_DIR.is_file():
            raise Exception(f"The specified location for shared dir is a file: {SHARED_DIR}.")

    SHARED_DIR.mkdir(parents=True)

    # ./tmp
    for td in ['lib', 'samples', 'unsolved_mutants']:
        tmp_dir = HOST_TMP_PATH/td
        if tmp_dir.exists():
            if tmp_dir.is_dir():
                logger.info(f"Cleaning up already existing tmp dir: {tmp_dir}.")
                try:
                    shutil.rmtree(tmp_dir)
                except OSError as err:
                    logger.info(f"Could not clean up {tmp_dir}: {err}")
            if tmp_dir.is_file():
                raise Exception(f"The specified location for tmp dir is a file: {tmp_dir}.")

        tmp_dir.mkdir(parents=True)
    

    proc = subprocess.run(f"""
        docker rm dummy || true
        docker create -ti --name dummy mutator_mutator bash
        docker cp dummy:/home/mutator/samples/ tmp/ && \
            docker cp dummy:/home/mutator/build/install/LLVM_Mutation_Tool/lib/ tmp/
        docker rm -f dummy
    """, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode != 0:
        logger.info(f"Could not extract mutator files.", proc)
        sys.exit(1)



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
    parser_eval.add_argument("--fresh-images", default=False, action="store_true",
        help='If the docker images should be rebuild from scratch. This will call pull on the base images, and build with --no-cache.')
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

    # # CMD: plot 
    # parser_plot = subparsers.add_parser('plot', help="Generate plots for the gathered data")
    # parser_plot.add_argument("--artifacts", default=False, action="store_true",
    #         help="If further detailed plots and latex tables should be written to disk.")
    # parser_plot.add_argument("--seed-dir", default=None,
    #         help="Will be used to generate stats regarding the seeds, if given.")
    # parser_plot.add_argument("--skip-script", default=False, action="store_true",
    #         help="If plot has already been called on the current db, so eval.sql script has been executed on the db. "
    #             "This option can be used to skip reevaluating the "
    #             "script, speeding up the plot process. Useful for debugging of plotting.")
    # parser_plot.add_argument("db_path", help="The sqlite database to plot.")
    # del parser_plot

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
                 args.seed_dir, args.rerun, args.rerun_mutations, args.fresh_images)
    elif args.cmd == 'coverage_fuzzing':
        raise NotImplementedError("Coverage fuzzing is not implemented yet.")
        coverage_fuzzing(args.progs, args.fuzzers, args.fuzz_time,
        args.seed_dir, args.result_dir, args.instances)
    elif args.cmd == 'check_seeds':
        raise NotImplementedError("Check seeds is not implemented yet.")
        check_seeds(args.progs, args.fuzzers)
    elif args.cmd == 'gather_seeds':
        raise NotImplementedError("Gather seeds is not implemented yet.")
        gather_seeds(args.progs, args.fuzzers, args.timeout, args.num_repeats,
        args.per_fuzzer, args.seed_dir, args.dest_dir)
    elif args.cmd == 'import_seeds':
        raise NotImplementedError("Import seeds is not implemented yet.")
        import_seeds(args.source, args.dest)
    # elif args.cmd == 'plot':
    #     generate_plots(args.db_path, args.seed_dir, args.artifacts, args.skip_script)
    elif args.cmd == 'merge':
        raise NotImplementedError("Merge is not implemented yet.")
        merge_dbs(args.out_db_path, args.in_db_paths)
    elif args.cmd == 'minimize_seeds':
        raise NotImplementedError("Minimize seeds is not implemented yet.")
        minimize_seeds(args.seed_path, args.res_path, args.fuzzers, args.progs, args.per_fuzzer)
    elif args.cmd == 'seed_coverage':
        raise NotImplementedError("Seed coverage is not implemented yet.")
        seed_coverage(args.seed_path, args.res_path, args.prog)
    else:
        parser.print_help(sys.stderr)

if __name__ == "__main__":
    main()




