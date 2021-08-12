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
    return subprocess.run(cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=MAX_RUN_EXEC_IN_CONTAINER_TIME,
        close_fds=True)


def run_seeds(seeds, orig_bin, mut_bin, args, workdir):
    os.environ['TRIGGERED_OUTPUT'] = ""
    print(os.environ['TRIGGERED_FOLDER'])
    seeds = Path(seeds)
    for path in list(str(pp) for pp in seeds.glob("**/*")):
        path = Path(path)
        if path.is_file() and path.name != "README.txt":
            input_args = args.replace("<WORK>/", workdir
                    ).replace("@@", str(path)
                    ).replace("___FILE___", str(path))

            # Run input on original binary
            orig_cmd = ["/run_bin.sh", str(orig_bin)] + shlex.split(input_args)
            proc = run_cmd(orig_cmd)
            orig_res = proc.stdout
            orig_returncode = proc.returncode
            if orig_returncode != 0:
                print("orig bin returncode != 0, crashing base bin:")
                print("args:", orig_cmd, "returncode:", orig_returncode)
                print(orig_res)
                sys.exit(2)

            # Run input on mutated binary
            mut_cmd = ["/run_bin.sh", str(mut_bin)] + shlex.split(input_args)
            proc = run_cmd(mut_cmd)
            mut_res = proc.stdout

            mut_res = mut_res.replace(TRIGGERED_STR, b"")
            mut_res = mut_res
            mut_returncode = proc.returncode

            if (orig_returncode != mut_returncode):
                if proc.returncode != 0:
                   print("seed finds mutation: =======================",
                         f"returncode orig: {orig_returncode} != mut: {mut_returncode}",
                           args,
                           "orig out:",
                           orig_res,
                           "======",
                           "mut out:",
                           mut_res,
                           sep="\n")
                   sys.exit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", required=True,
            help='The seeds to check.')
    parser.add_argument("--args", required=True,
            help="The args to execute with, where a @@ is replaced with the path to a seed file and <WORK>/ with --workdir.")
    parser.add_argument("--orig", required=True,
            help="The path to the original binary.")
    parser.add_argument("--mut", required=True,
            help="The path to the mutated binary.")
    parser.add_argument("--workdir", required=True,
            help="The workdir, replaces <WORK>/ in args.")
    args = parser.parse_args()
    run_seeds(args.seeds, args.orig, args.mut, args.args, args.workdir)


if __name__ == "__main__":
    main()
