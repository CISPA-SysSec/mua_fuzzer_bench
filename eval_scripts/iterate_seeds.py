#!/usr/bin/env python3

import os
import shlex
import sys
import subprocess
import argparse
import json
import tempfile
from pathlib import Path


TRIGGERED_STR = b"Triggered!\r\n"
MAX_RUN_EXEC_IN_CONTAINER_TIME = 30


def run_cmd(cmd):
    return subprocess.run(cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=MAX_RUN_EXEC_IN_CONTAINER_TIME,
        close_fds=True)


def run_seeds(seeds, orig_bin, mut_bin, args, workdir, result_dir):
    os.environ['TRIGGERED_OUTPUT'] = ""
    triggered_folder = os.environ.get("TRIGGERED_FOLDER")
    assert triggered_folder, "Expected to have a triggered folder."
    triggered_folder = Path(triggered_folder)
    print("triggered folder:", triggered_folder)
    covered = set()
    killed = set()
    seeds = Path(seeds)
    for path in list(str(pp) for pp in seeds.glob("**/*")):
        path = Path(path)
        if path.is_file():
            # clean up triggered folder dir
            for tf in triggered_folder.glob("*"):
                tf.unlink()

            input_args = args.replace("<WORK>/", workdir
                    ).replace("@@", str(path)
                    ).replace("___FILE___", str(path))

            # Run input on original binary
            orig_cmd = ["/run_bin.sh", str(orig_bin)] + shlex.split(input_args)
            proc = run_cmd(orig_cmd)
            orig_res = proc.stdout
            orig_returncode = proc.returncode
            if orig_returncode != 0:
                with tempfile.NamedTemporaryFile(mode="wt", dir=result_dir, suffix=".json", delete=False) as f:
                    json.dump({
                        'result': 'orig_crash',
                        'path': str(path),
                        'args': orig_cmd,
                        'returncode': orig_returncode,
                        'orig_res': str(orig_res),
                    }, f)

            # Run input on mutated binary
            mut_cmd = ["/run_bin.sh", str(mut_bin)] + shlex.split(input_args)
            proc = run_cmd(mut_cmd)
            mut_res = proc.stdout

            mut_res = mut_res.replace(TRIGGERED_STR, b"")
            mut_res = mut_res
            mut_returncode = proc.returncode

            if (orig_returncode != mut_returncode):
                if proc.returncode != 0:
                    mutation_ids = set((int(ff.name) for ff in triggered_folder.glob("*")))
                    new_killed = mutation_ids - killed
                    killed |= mutation_ids
                    if new_killed:
                        with tempfile.NamedTemporaryFile(mode="wt", dir=result_dir, suffix=".json", delete=False) as f:
                            json.dump({
                                'result': 'killed',
                                'mutation_ids': list(new_killed),
                                'path': str(path),
                                'args': args,
                                'orig_cmd': orig_cmd,
                                'mut_cmd': mut_cmd,
                                'orig_returncode': orig_returncode,
                                'mut_returncode': mut_returncode,
                                'orig_res': str(orig_res),
                                'mut_res': str(mut_res),
                                'num_triggered': len(mutation_ids),
                            }, f)

            # Write out mutations that are covered
            mutation_ids = set((int(ff.name) for ff in triggered_folder.glob("*")))
            new_covered = mutation_ids - covered

            if new_covered:
                with tempfile.NamedTemporaryFile(mode="wt", dir=result_dir, suffix=".json", delete=False) as f:
                    json.dump({
                        'result': 'covered',
                        'path': str(path),
                        'mutation_ids': list(new_covered),
                    }, f)

            covered |= mutation_ids


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
    parser.add_argument("--results", required=True,
            help="Directory where to put the results.")
    args = parser.parse_args()
    run_seeds(args.seeds, args.orig, args.mut, args.args, args.workdir, args.results)


if __name__ == "__main__":
    main()
