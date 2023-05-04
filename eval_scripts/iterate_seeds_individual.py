#!/usr/bin/env python3

import os
import shlex
import sys
import subprocess
import argparse
import json
import tempfile
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed


TRIGGERED_STR = b"Triggered!\r\n"
MAX_RUN_EXEC_IN_CONTAINER_TIME = 300
MAX_RETRY = 3


def run_cmd(cmd):
    proc = subprocess.Popen(cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        close_fds=True)
    try:
        proc.wait(timeout=MAX_RUN_EXEC_IN_CONTAINER_TIME)
    except subprocess.TimeoutExpired:
        print("timeout")
        proc.kill()
        proc.wait()
    return proc


def get_seed_coverage(all_args):
    binary, args, workdir, triggered_folder_base, seed = all_args
    seed = Path(seed)
    if seed.is_file():
        with tempfile.TemporaryDirectory(dir=triggered_folder_base) as triggered_folder:
            os.environ['TRIGGERED_FOLDER'] = triggered_folder # set folder
            input_args = args.replace("<WORK>/", workdir
                    ).replace("@@", str(seed)
                    ).replace("___FILE___", str(seed))

            # Run input on binary
            orig_cmd = ["/home/mutator/run_bin.sh", str(binary)] + shlex.split(input_args)
            retry = 0
            while True:
                proc = run_cmd(orig_cmd)
                orig_res = proc.stdout
                orig_returncode = proc.returncode
                if orig_returncode != 0:
                    if retry < MAX_RETRY:
                        # retry
                        retry += 1
                        continue
                    else:
                        raise ValueError(f"""
orig bin returncode != 0, crashing base bin:
args: {orig_cmd} returncode: {orig_returncode}
{orig_res.read()}
                        """)
                else:
                    # Successful run
                    mutation_ids = []
                    for pp in Path(triggered_folder).glob("*"):
                        assert pp.is_file()
                        mutation_ids.append(int(pp.stem))
                        pp.unlink()
                    assert len(list(Path(triggered_folder).glob("*"))) == 0
                    # seed_results[str(path)] = mutation_ids
                    return str(seed), mutation_ids
    else:
        raise ValueError("seed is not a file:", seed)


def run_seeds(seeds, binary, args, workdir, result_file):
    os.environ['TRIGGERED_OUTPUT'] = ""  # set OUTPUT
    triggered_folder = os.environ['TRIGGERED_FOLDER']  # get FOLDER
    print("triggered folder:", triggered_folder)
    seeds = Path(seeds)
    seed_results = {}
    seeds = list(str(pp) for pp in seeds.glob("**/*"))
    with ProcessPoolExecutor() as executor:
        args_list = list((binary, args, workdir, triggered_folder, seed) for seed in seeds)
        for path, mutation_ids in executor.map(
                get_seed_coverage, args_list):
            seed_results[path] = mutation_ids

    with open(result_file, 'wt') as f:
        json.dump(seed_results, f)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", required=True,
            help='The seeds to check.')
    parser.add_argument("--args", required=True,
            help="The args to execute with, where a @@ is replaced with the path to a seed file and <WORK>/ with --workdir.")
    parser.add_argument("--binary", required=True,
            help="The path to the original binary.")
    parser.add_argument("--workdir", required=True,
            help="The workdir, replaces <WORK>/ in args.")
    parser.add_argument("--results-file", required=True,
            help="The file where to write the results for each input as json.")
    args = parser.parse_args()
    run_seeds(args.seeds, args.binary, args.args, args.workdir, args.results_file)


if __name__ == "__main__":
    main()
