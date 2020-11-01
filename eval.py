#!/usr/bin/env python3
import os
import time
import subprocess
import csv
import sqlite3
import traceback
import signal
import concurrent.futures
from pathlib import Path

import docker

# If container logs should be shown
SHOW_CONTAINER_LOGS = False

# Timeout for the fuzzers in seconds
TIMEOUT = 60 * 60 * 4

# Time interval in which to check the results of a fuzzer
CHECK_INTERVAL = 5

# The path where eval data is stored outside of the docker container
HOST_TMP_PATH = Path(".").resolve()/"tmp/"

# The location where the eval data is mapped to inside the docker container
IN_DOCKER_WORKDIR = "/workdir/"

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

# Eval function for the afl plus plus fuzzer, compiles the mutated program
# and fuzzes it. Finally the plot data is returned
def aflpp_eval(workdir, prog_bc, args, core_to_use):
    global should_run
    # get access to the docker client to start the container
    docker_client = docker.from_env()
    # Get the string representing the mapping of the host and guest directory
    # which is used to share data.
    tmp_mapping = str(HOST_TMP_PATH) + ":" + IN_DOCKER_WORKDIR
    # Start and run the container
    container = docker_client.containers.run(
        "mutator_aflpp", # the image
        ["/home/eval/start_aflpp.sh", str(prog_bc), str(args)], # the argumetns
        init=True,
        cpuset_cpus=str(core_to_use),
        ipc_mode="host",
        auto_remove=True,
        volumes={str(HOST_TMP_PATH): {'bind': str(IN_DOCKER_WORKDIR), 'mode': 'rw'}},
        working_dir=str(workdir),
        detach=True)

    if SHOW_CONTAINER_LOGS:
        logs = container.logs(stream=True)

    start_time = time.time()
    while time.time() < start_time + TIMEOUT and should_run:
        # Print the next lines outputted by the container
        if SHOW_CONTAINER_LOGS:
            for output in logs:
                print(output)
        # check if the process stopped, this should only happen in an error case
        container.reload()
        if container.status not in ["running", "created"]:
            break

        # Sleep so we only check sometimes and do not busy loop 
        time.sleep(CHECK_INTERVAL)

    # Check if container is still running
    container.reload()
    if container.status in ["running", "created"]:

        # Send sigint to the process
        container.kill(2)

        # Wait up to 10 seconds then send sigkill
        container.stop()

    # Get the final stats and report them
    with open(workdir/"output"/"plot_data") as csvfile:
        plot_data = list(csv.DictReader(csvfile))[:-1]
    
    # Also collect all crashing outputs
    crashing_inputs = []
    for path in (workdir/"output"/"crashes").iterdir():
        if path.is_file():
            crashing_inputs.append((str(path), path.read_bytes()))
        
    return plot_data, crashing_inputs

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

# The programs that can be evaluated
PROGRAMS = {
    "objdump": {
        "path": "binutil/binutil/",
        "args": "--dwarf-check -C -g -f -dwarf -x @@",
    },
}

# Generator that first collects all possible runs and adds them to stats.
# Then yields all information needed to start a eval run
def get_next_run(stats):
    all_runs = []
    # For all programs that can be done by our evaluation
    for prog, prog_info in PROGRAMS.items():
        # Get all mutations that are possible with that program
        mutations = list((HOST_TMP_PATH/prog_info['path']/"mutations").glob("*.mut.bc"))
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
                prog_bc = IN_DOCKER_WORKDIR/mutation.relative_to(HOST_TMP_PATH)
                # Arguments on how to execute the binary
                args = prog_info['args']
                # Add that run to the database, so that we know it is possible
                stats.new_run(fuzzer, prog, mutation_id)
                # Build our list of runs
                all_runs.append((eval_func, workdir, prog_bc, args, prog, mutation_id))

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
            plot_data, crashing_inputs = future.result()
        except Exception as exc:
            # if there was an exception print it
            print('='*50,
                '\n%r generated an exception: %s' %
                    (data['prog_bc'], exc), # traceback.format_exc()
                '='*50)
        else:
            # if successful log the run
            stats.new_aflpp_run(plot_data, data['prog'], data['mutation_id'])
            stats.new_crashing_inputs(crashing_inputs, data['prog'], data['mutation_id'])
        # Set the core for this run to unused
        cores_in_use[data['used_core']] = False
        # If we only wanted to wait for one run, break here to return
        if break_after_one:
            break

def main():
    global should_run
    # prepare environment
    # set signal handler for keyboard interrupt
    signal.signal(signal.SIGINT, sigint_handler)
    # set the number of concurrent runs
    num_cpus = os.cpu_count()
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
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_cpus) as executor:
        # keep a list of all runs
        runs = {}
        # Keep a list of which cores can be used
        cores_in_use = [False]*num_cpus
        # Get each run
        for run_data in get_next_run(stats):
            # If we should stop, do so now to not create any new run.
            if not should_run:
                break
            # Get a free core, this will throw an exception if there is none
            used_core = cores_in_use.index(False)
            # Set the core as used
            cores_in_use[used_core] = True
            # Unpack the run_data
            eval_func, workdir, prog_bc, args, prog, mutation_id = run_data
            # Add the run to the executor, this starts execution of the eval
            # function. Also associate some information with that run, this
            # is later used to record needed information.
            runs[executor.submit(eval_func, workdir, prog_bc, args, used_core)] = {
                "prog_bc": prog_bc, "prog": prog, "mutation_id": mutation_id,
                "used_core": used_core
            }
            # Do not wait for a run, if we can start more runs do so first and
            # only wait when all cores are in use.
            if False in cores_in_use:
                continue
            # Wait for a single run to complete, after which we can start another
            wait_for_runs(stats, runs, cores_in_use, True)
        # Wait for all remaining active runs
        wait_for_runs(stats, runs, cores_in_use, False)

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
            fuzzer
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
            totals_execs
        )''')

        c.execute('''
        CREATE TABLE crashing_inputs (
            prog,
            mutation_id,
            path,
            crashing_input
        )''')

        self.conn.commit()

    def commit(self):
        self.conn.commit()

    @connection
    def new_run(self, c, fuzzer, prog, mutation_id):
        c.execute('INSERT INTO runs VALUES (?, ?, ?)',
            (
                prog,
                mutation_id,
                fuzzer,
            )
        )
        self.conn.commit()

    @connection
    def new_aflpp_run(self, c, plot_data, prog, mutation_id):
        start_time = None
        for row in plot_data:
            cur_time = int(row['# unix_time'].strip())
            if start_time is None:
                start_time = cur_time
            cur_time -= start_time
            c.execute('INSERT INTO aflpp_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
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
                )
            )
        self.conn.commit()

    @connection
    def new_crashing_inputs(self, c, crashing_inputs, prog, mutation_id):
        for crashing_input in crashing_inputs:
            crashing_input, path = crashing_input
            c.execute('INSERT INTO crashing_inputs VALUES (?, ?, ?, ?)',
                (
                    prog,
                    mutation_id,
                    path,
                    crashing_input,
                )
            )
        self.conn.commit()

if __name__ == "__main__":
    main()
