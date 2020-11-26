#!/usr/bin/env python3
import os
import time
import subprocess
import csv
import sqlite3
import traceback
import datetime
import signal
import threading
import queue
import json
import shutil
import tempfile
import contextlib
import shlex
import concurrent.futures
from pathlib import Path

import docker

# set the number of concurrent runs
NUM_CPUS = os.cpu_count()

# If container logs should be shown
SHOW_CONTAINER_LOGS = False

# Timeout for the fuzzers in seconds
TIMEOUT = 60 * 60

# Time interval in which to check the results of a fuzzer
CHECK_INTERVAL = 5

# The path where eval data is stored outside of the docker container
HOST_TMP_PATH = Path(".").resolve()/"tmp/"

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
    # "re2": {
    #     "compile_args": [
    #         # {'val': "-v", 'action': None},
    #         # {'val': "-static", 'action': None},
    #         # {'val': "-std=c++11", 'action': None},
    #         {'val': "-lpthread", 'action': None},
    #         # {'val': "samples/re2/re2_fuzzer.cc", 'action': "prefix_workdir"},
    #         {'val': "-I", 'action': None},
    #         {'val': "samples/re2-code/", 'action': "prefix_workdir"},
    #         # {'val': "-lc++", 'action': None},
    #         # {'val': "-lstdc++", 'action': None},
    #         # {'val': "-D_GLIBCXX_USE_CXX11_ABI=0", 'action': None},
    #     ],
    #     "path": "samples/re2/",
    #     "args": "@@",
    # },
    "guetzli": {
        "compile_args": [
            # {'val': "-v", 'action': None},
            # {'val': "-static", 'action': None},
            # {'val': "-std=c++11", 'action': None},
            # {'val': "-lpthread", 'action': None},
            # {'val': "samples/re2/re2_fuzzer.cc", 'action': "prefix_workdir"},
            # {'val': "-I", 'action': None},
            # {'val': "samples/re2-code/", 'action': "prefix_workdir"},
            # {'val': "-lc++", 'action': None},
            # {'val': "-lstdc++", 'action': None},
            # {'val': "-D_GLIBCXX_USE_CXX11_ABI=0", 'action': None},
            # {'val': "samples/guetzli/fuzz_target.bc", 'action': "prefix_workdir"},
        ],
        "orig_bin": str(Path("tmp/samples/guetzli/fuzz_target").absolute()),
        "path": "samples/guetzli/",
        "seeds": "samples/guetzli_harness/seeds/",
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
        CREATE TABLE runs (
            prog,
            mutation_id,
            fuzzer,
            workdir,
            prog_bc,
            compile_args,
            args,
            seeds,
            orig_bin,
            mut_additional_info,
            mut_column,
            mut_directory,
            mut_file_path,
            mut_line,
            mut_type
        )''')

        c.execute('''
        CREATE TABLE aflpp_runs (
            prog,
            mutation_id,
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
            totals_execs,
            covered_file_seen,
            total_time
        )''')

        c.execute('''
        CREATE TABLE crashing_inputs (
            prog,
            mutation_id,
            fuzzer,
            path,
            crashing_input,
            orig_return_code,
            mut_return_code,
            orig_cmd,
            mut_cmd,
            orig_stdout,
            mut_stdout,
            orig_stderr,
            mut_stderr,
            num_triggered
        )''')

        c.execute('''
        CREATE TABLE run_crashed (
            prog,
            mutation_id,
            fuzzer,
            crash_trace
        )''')

        self.conn.commit()

    def commit(self):
        self.conn.commit()

    @connection
    def new_run(self, c, run_data):
        c.execute('INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                run_data['prog'],
                run_data['mutation_id'],
                run_data['fuzzer'],
                str(run_data['workdir']),
                str(run_data['prog_bc']),
                run_data['compile_args'],
                run_data['args'],
                str(run_data['seeds']),
                run_data['orig_bin'],
                json.dumps(run_data['mutation_data']['additionalInfo']),
                run_data['mutation_data']['column'],
                run_data['mutation_data']['directory'],
                run_data['mutation_data']['filePath'],
                run_data['mutation_data']['line'],
                run_data['mutation_data']['type'],
            )
        )
        self.conn.commit()

    @connection
    def new_aflpp_run(self, c, plot_data, prog, mutation_id, cf_seen, total_time):
        start_time = None
        for row in plot_data:
            cur_time = int(row['# unix_time'].strip())
            if start_time is None:
                start_time = cur_time
            cur_time -= start_time
            c.execute('INSERT INTO aflpp_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    prog,
                    mutation_id,
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
                    row[None][0].strip(),
                    cf_seen,
                    total_time,
                )
            )
        self.conn.commit()

    @connection
    def new_crashing_inputs(self, c, crashing_inputs, prog, mutation_id, fuzzer):
        for path, data in crashing_inputs.items():
            c.execute('INSERT INTO crashing_inputs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    prog,
                    mutation_id,
                    fuzzer,
                    path,
                    data['data'],
                    data['orig_returncode'],
                    data['mut_returncode'],
                    ' '.join((str(v) for v in data['orig_cmd'])),
                    ' '.join((str(v) for v in data['mut_cmd'])),
                    data['orig_res'][0],
                    data['mut_res'][0],
                    data['orig_res'][1],
                    data['mut_res'][1],
                    data['num_triggered']
                )
            )
        self.conn.commit()

    @connection
    def run_crashed(self, c, prog, mutation_id, fuzzer, trace):
        c.execute('INSERT INTO run_crashed VALUES (?, ?, ?, ?)',
            (
                prog,
                mutation_id,
                fuzzer,
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
        for line in self.container.logs(stream=True):
            line = line.decode()
            if SHOW_CONTAINER_LOGS:
                print(line.rstrip())
            self.q.put(line)
        self.q.put(None)

@contextlib.contextmanager
def start_testing_container(core_to_use):
    # get access to the docker client to start the container
    docker_client = docker.from_env()

    # build testing image
    proc = subprocess.run([
            "docker", "build",
            "-t", "mutator_testing",
            "-f", "eval/Dockerfile.testing",
            "."
        ],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        print("Could not build testing image.", proc)
        raise ValueError(proc)

    # Start and run the container
    container = docker_client.containers.run(
        "mutator_testing", # the image
        ["sleep", str(TIMEOUT * 2 + 120)], # the arguments
        init=True,
        ipc_mode="host",
        auto_remove=True,
        environment={
            'LD_LIBRARY_PATH': "/workdir/lib/",
        },
        volumes={str(HOST_TMP_PATH): {'bind': str(IN_DOCKER_WORKDIR),
                                      'mode': 'ro'}},
        working_dir=str(IN_DOCKER_WORKDIR),
        cpuset_cpus=str(core_to_use),
        detach=True
    )
    yield container
    container.stop()
        
def run_exec_in_testing_container(container, cmd):
    sub_cmd = ["docker", "exec", "-it",
        container.name,
        *cmd]
    return subprocess.run(sub_cmd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )

# returns true if a crashing input is found that only triggers for the
# mutated binary
def check_crashing_inputs(testing_container, crashing_inputs, crash_dir,
                          orig_bin, mut_bin, args):
    if not crash_dir.is_dir():
        return False

    for path in crash_dir.iterdir():
        if path.is_file() and path.name != "README.txt":
            if path not in crashing_inputs:
                # Check that does not crash on the original binary
                orig_cmd = ["/run_bin.sh", orig_bin]
                orig_cmd += args.replace("@@", str(path)).split(" ")
                proc = run_exec_in_testing_container(testing_container, orig_cmd)
                # proc = subprocess.Popen(orig_cmd,
                #     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                #     env={'LD_LIBRARY_PATH': "/workdir/lib/"})
                orig_res = (proc.stdout, proc.stderr)
                orig_returncode = proc.returncode

                # Check that does not crash on the original binary
                mut_cmd = ["/run_bin.sh", mut_bin]
                mut_cmd += args.replace("@@", str(path)).split(" ")
                proc = run_exec_in_testing_container(testing_container, mut_cmd)
                # proc = subprocess.Popen(mut_cmd,
                #     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                #     env={'LD_LIBRARY_PATH': "/workdir/lib/"})
                mut_res = (proc.stdout, proc.stderr)
                num_triggered = len(mut_res[0].split(TRIGGERED_STR))
                num_triggered += len(mut_res[1].split(TRIGGERED_STR))
                mut_res = (
                    mut_res[0].replace(TRIGGERED_STR, b""),
                    mut_res[1].replace(TRIGGERED_STR, b"")
                )
                mut_returncode = proc.returncode

                try:
                    crash_file_data = path.read_bytes()
                except Exception as exc:
                    crash_file_data = "{}".format(exc)

                crashing_inputs[str(path)] = {
                    'data': crash_file_data,
                    'orig_returncode': orig_returncode,
                    'mut_returncode': mut_returncode,
                    'orig_cmd': orig_cmd,
                    'mut_cmd': mut_cmd,
                    'orig_res': orig_res,
                    'mut_res': mut_res,
                    'num_triggered': num_triggered,
                }

                if (orig_returncode != mut_returncode or orig_res != mut_res):
                    return True
    return False


# Eval function for the afl plus plus fuzzer, compiles the mutated program
# and fuzzes it. Finally the plot data is returned
def aflpp_eval(run_data):
    global should_run
    # extract used values
    workdir = run_data['workdir']
    prog_bc = IN_DOCKER_WORKDIR/run_data['prog_bc'].relative_to(HOST_TMP_PATH)
    compile_args = run_data['compile_args']
    args = run_data['args']
    seeds = run_data['seeds']
    orig_bin = IN_DOCKER_WORKDIR/Path(run_data['orig_bin']).relative_to(HOST_TMP_PATH)
    core_to_use = run_data['used_core']
    docker_mut_bin = Path(workdir)/"testing"
    docker_mut_bin.parent.mkdir(parents=True, exist_ok=True)

    # start testing container
    with start_testing_container(core_to_use) as testing_container:

        # compile the compare version of the mutated binary
        compile_mut_bin_res = run_exec_in_testing_container(testing_container,
            [
                "/usr/bin/clang++-11",
                "-v",
                "-o", str(docker_mut_bin),
                "/workdir/lib/libdynamiclibrary.so",
                str(prog_bc)
            ]
        )
        if compile_mut_bin_res.returncode != 0:
            raise ValueError(compile_mut_bin_res)

        # get path for covered file and rm the file if it exists
        covered_file_seen = None
        covered_file = Path(workdir)/"covered"
        if covered_file.is_file():
            covered_file.unlink()
        # set up data for crashing inputs
        crashing_inputs = {}
        crash_dir = workdir/"output"/"crashes"
        # check if seeds are already crashing
        checked_seeds = {}
        # get start time for the eval
        start_time = time.time()
        # do an initial check to see if the seed files are already crashing
        if check_crashing_inputs(testing_container, checked_seeds, seeds,
                                 orig_bin, docker_mut_bin, args):
            # Check if covered file is seen
            if covered_file_seen is None and covered_file.is_file():
                covered_file_seen = time.time() - start_time
            return {
                'total_time': time.time() - start_time,
                'covered_file_seen': covered_file_seen,
                'plot_data': [],
                'crashing_inputs': checked_seeds,
            }
        # get access to the docker client to start the container
        docker_client = docker.from_env()
        # Start and run the container
        container = docker_client.containers.run(
            "mutator_aflpp", # the image
            [
                "/home/eval/start_aflpp.sh",
                str(compile_args),
                str(prog_bc),
                str(IN_DOCKER_WORKDIR/seeds),
                str(args)
            ], # the arguments
            environment={
                'TRIGGERED_OUTPUT': str(""),
                'TRIGGERED_FILE': str(workdir/'covered'),
            },
            init=True,
            cpuset_cpus=str(core_to_use),
            ipc_mode="host",
            auto_remove=True,
            volumes={str(HOST_TMP_PATH): {'bind': str(IN_DOCKER_WORKDIR),
                                          'mode': 'ro'}},
            working_dir=str(workdir),
            detach=True
        )

        logs_queue = queue.Queue()
        DockerLogStreamer(logs_queue, container).start()

        while time.time() < start_time + TIMEOUT and should_run:
            # Print the next lines outputted by the container

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
            if covered_file_seen is None and covered_file.is_file():
                covered_file_seen = time.time() - start_time

            # Check if a crashing input has already been found
            if check_crashing_inputs(testing_container, crashing_inputs,
                                     crash_dir, orig_bin, docker_mut_bin, args):
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
        
        total_time = time.time() - start_time

        all_logs = []
        while True:
            line = logs_queue.get()
            if line == None:
                break
            all_logs.append(line)

        try:
                
            # Get the final stats and report them
            with open(workdir/"output"/"plot_data") as csvfile:
                plot_data = list(csv.DictReader(csvfile))
                # only get last row, to reduce memory usage
                try:
                    plot_data = [plot_data[-2]]
                except IndexError:
                    plot_data = [plot_data[-1]]

            # Also collect all crashing outputs
            check_crashing_inputs(testing_container, crashing_inputs, crash_dir,
                                  orig_bin, docker_mut_bin, args)
                
            return {
                'total_time': total_time,
                'covered_file_seen': covered_file_seen,
                'plot_data': plot_data,
                'crashing_inputs': crashing_inputs,
            }

        except Exception as exc:
            raise ValueError(''.join(all_logs)) from exc

def build_compile_args(args, workdir):
    res = ""
    for arg in args:
        if arg['action'] is None:
            res += arg['val'] + " "
        elif arg['action'] == 'prefix_workdir':
            res += str(Path(workdir)/arg['val']) + " "
        else:
            raise ValueError("Unknown action: {}", arg)
    return res

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
}

# Generator that first collects all possible runs and adds them to stats.
# Then yields all information needed to start a eval run
def get_next_run(stats):
    all_runs = []
    # For all programs that can be done by our evaluation
    for prog, prog_info in PROGRAMS.items():
        # Get all mutations that are possible with that program
        mutations = list((HOST_TMP_PATH/prog_info['path']/"mutations").glob("*.mut.bc"))
        # get additional info on mutations
        mut_data_path = list(Path(HOST_TMP_PATH/prog_info['path'])
                                .glob('*.ll.mutationlocations'))
        assert(len(mut_data_path) == 1)
        mut_data_path = mut_data_path[0]
        with open(mut_data_path, 'rt') as f:
            mutation_data = json.load(f)
        # Go through the mutations
        for mutation in mutations:
            # For each fuzzer gather all information needed to start a eval run
            for fuzzer, eval_func in FUZZERS.items():
                # Get the mutation id from the file path
                mutation_id = str(mutation).split(".")[-3]
                # Get the working directory based on program and mutation id and
                # fuzzer, which is a unique path for each run
                workdir = Path("/dev/shm/mutator/")/prog/mutation_id/fuzzer
                # Get the bc file that should be fuzzed (and probably
                # instrumented).
                prog_bc = mutation
                # Get the path to the file that should be included during compilation
                compile_args = build_compile_args(prog_info['compile_args'], IN_DOCKER_WORKDIR)
                # Arguments on how to execute the binary
                args = prog_info['args']
                # Prepare seeds
                seeds = Path(prog_info['seeds'])
                # Original binary to check if crashing inputs also crash on
                # unmodified version
                orig_bin = prog_info['orig_bin']
                # gather all info
                run_data = {
                    'fuzzer': fuzzer,
                    'eval_func': eval_func,
                    'workdir': workdir,
                    'prog_bc': prog_bc,
                    'compile_args': compile_args,
                    'args': args,
                    'prog': prog,
                    'seeds': seeds,
                    'orig_bin': orig_bin,
                    'mutation_id': mutation_id,
                    'mutation_data': mutation_data[int(mutation_id)],
                }
                # Add that run to the database, so that we know it is possible
                stats.new_run(run_data)
                # Build our list of runs
                all_runs.append(run_data)

    # Yield the individual eval runs
    for run in all_runs:
        yield run

# Helper function to wait for the next eval run to complete.
# Also updates the stats and which cores are currently used.
# If `break_after_one` is true, return after a single run finishes.
def wait_for_runs(stats, runs, cores_in_use, break_after_one):
    # wait for the futures to complete
    for future in concurrent.futures.as_completed(runs):
        # get the associated data for that future
        data = runs[future]
        # we are not interested in this run anymore
        del runs[future]
        try:
            # if there was no exception get the data
            run_result = future.result()
        except Exception as exc:
            # if there was an exception print it
            prog_bc = data['prog_bc']
            trace = traceback.format_exc()
            stats.run_crashed(data['prog'], data['mutation_id'], data['fuzzer'],
                              trace)
            # print('='*50,
            #     '\n%r generated an exception: %s\n' %
            #         (prog_bc, trace), # exc
            #     '='*50)
        else:
            # if successful log the run
            # print("success")
            stats.new_aflpp_run(
                run_result['plot_data'],
                data['prog'],
                data['mutation_id'],
                run_result['covered_file_seen'],
                run_result['total_time'])
            stats.new_crashing_inputs(
                run_result['crashing_inputs'], data['prog'],
                data['mutation_id'], data['fuzzer'])
        # Set the core for this run to unused
        cores_in_use[data['used_core']] = False
        # If we only wanted to wait for one run, break here to return
        if break_after_one:
            break

def main():
    global should_run
    # prepare environment
    base_shm_dir = Path("/dev/shm/mutator")
    base_shm_dir.mkdir(parents=True, exist_ok=True)

    # set the number of allowed files, this is needed for larger numbers of
    # concurrent runs, this doesn't work here ..., needs to be done in shell
    # os.system("ulimit -n 50000")
    # also set number of available shared memory
    # sudo bash -c "echo 134217728 > /proc/sys/kernel/shmmni"
    # also set core pattern
    # sudo bash -c "echo core >/proc/sys/kernel/core_pattern"

    # set signal handler for keyboard interrupt
    signal.signal(signal.SIGINT, sigint_handler)
    # Initialize the stats object
    stats = Stats("/dev/shm/mutator/stats.db")

    # build the fuzzer docker images
    proc = subprocess.run([
        "docker", "build",
        "-t", "mutator_aflpp",
        "-f", "eval/Dockerfile.aflpp",
        "."])
    if proc.returncode != 0:
        print("Could not build aflpp image.", proc)
        exit(1)

    # for each mutation and for each fuzzer do a run
    with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_CPUS) as executor:
        # keep a list of all runs
        runs = {}
        # start time
        start_time = time.time()
        # Keep a list of which cores can be used
        cores_in_use = [False]*NUM_CPUS
        # Get each run
        for ii, run_data in enumerate(get_next_run(stats)):
            print("" + str(ii) + " @ " + str(int((time.time() - start_time)//60)),
                  end=', ', flush=True)
            # If we should stop, do so now to not create any new run.
            if not should_run:
                break
            # Get a free core, this will throw an exception if there is none
            used_core = cores_in_use.index(False)
            # Set the core as used
            cores_in_use[used_core] = True
            # Unpack the run_data
            # Add the run to the executor, this starts execution of the eval
            # function. Also associate some information with that run, this
            # is later used to record needed information.
            run_data['used_core'] = used_core
            runs[executor.submit(run_data['eval_func'], run_data)] = run_data
            # Do not wait for a run, if we can start more runs do so first and
            # only wait when all cores are in use.
            if False in cores_in_use:
                continue
            # Wait for a single run to complete, after which we can start another
            wait_for_runs(stats, runs, cores_in_use, True)
        # Wait for all remaining active runs
        print('waiting for the rest')
        wait_for_runs(stats, runs, cores_in_use, False)

if __name__ == "__main__":
    main()
