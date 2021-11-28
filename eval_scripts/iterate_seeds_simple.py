#!/usr/bin/env python3

import os
import shlex
import sys
import subprocess
import argparse
from pathlib import Path


TRIGGERED_STR = b"Triggered!\r\n"
MAX_RUN_EXEC_IN_CONTAINER_TIME = 30


def run_cmd(cmd):
    proc = subprocess.Popen(cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        close_fds=True)
    try:
        proc.wait(timeout=MAX_RUN_EXEC_IN_CONTAINER_TIME)
    except subprocess.TimeoutExpired:
        pass
    return proc


def run_seeds(seeds, binary, args, workdir):
    os.environ['TRIGGERED_OUTPUT'] = ""
    print("triggered folder:", os.environ['TRIGGERED_FOLDER'])
    seeds = Path(seeds)
    for path in list(str(pp) for pp in seeds.glob("**/*")):
        path = Path(path)
        if path.is_file():
            input_args = args.replace("<WORK>/", workdir
                    ).replace("@@", str(path)
                    ).replace("___FILE___", str(path))

            # Run input on binary
            orig_cmd = ["/home/mutator/run_bin.sh", str(binary)] + shlex.split(input_args)
            proc = run_cmd(orig_cmd)
            orig_res = proc.stdout
            orig_returncode = proc.returncode
            if orig_returncode != 0:
                print("orig bin returncode != 0, crashing base bin:")
                print("args:", orig_cmd, "returncode:", orig_returncode)
                print(orig_res)
                sys.exit(2)


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
    args = parser.parse_args()
    run_seeds(args.seeds, args.binary, args.args, args.workdir)


if __name__ == "__main__":
    main()
