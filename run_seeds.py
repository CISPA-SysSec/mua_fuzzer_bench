#!/usr/bin/env python3
"""
A python script for orchestrating the mutation of subjects.
"""
import sys
import subprocess
import argparse
import os
from typing import List
from pathlib import Path

def main(prog: str, seeds: List[str]):
    """
    Takes the program as argument, checks if it is in a compilable form, converts it to an .ll file if necessary and
    then performs the actual mutation.
    :param prog:
    :param seeds
    :return:
    """
    # TODO also delete the trigger-signal folder first to avoid incorrect results
    base_dir = Path(os.getcwd()).absolute()
    # compile the original file for printing trigger locations
    if args.cpp:
        subprocess.run(["python3", "run_mutation.py", "-cpp", "-ll", prog])
    else:
        subprocess.run(["python3", "run_mutation.py", "-ll", prog])

    abs_seeds = []
    for seed in seeds:
        abs_seeds.append(Path(seed).absolute())
    prog_parent = Path(prog).parent
    os.chdir(prog_parent)
    progname = Path(prog).name
    # bc files are converted to ll files
    progname = progname.replace(".bc",".ll")
    print(progname)
    # get the initial mutation id's
    subprocess.call(["chmod", "+x", f"./{progname}.opt_mutate"])
    for seed in abs_seeds:
        try:
            if seed:
                subprocess.run([f"./{progname}.opt_mutate", seed], timeout=10, input=b"12")
            else:
                subprocess.run([f"./{progname}.opt_mutate"], timeout=10, input=b"12")
        except subprocess.TimeoutExpired:
            pass
    # iterate the initial mutation id's printed by the trigger signal file
    with open(f"found_mutations.csv", "w", buffering=1) as found_file:
        for file in sorted(int(el) for el in os.listdir("trigger_signal")):
            os.chdir(base_dir)
            # compile the respective mutation
            if args.cpp:
                subprocess.run(["python3", "run_mutation.py", "-cpp", "-bn", prog, "-m", str(file)])
            else:
                subprocess.run(["python3", "run_mutation.py", "-bn", prog, "-m", str(file)])
            # go to the mutation folder and run the subject
            os.chdir(f"{prog_parent}/mutations")
            exec_name = f"./{progname}.{file}.mut"
            if not os.path.exists(exec_name):
                found_file.write(f"{file}, Crashed\n")
                continue
            subprocess.call(["chmod", "+x", exec_name])
            for seed in abs_seeds:
                try:
                    if seed:
                        subprocess.run([exec_name, seed], timeout=10, input=b"12")
                    else:
                        subprocess.run([exec_name], timeout=10, input=b"12")
                except subprocess.TimeoutExpired:
                    found_file.write(f"{file}, Timeout\n")
            if os.path.exists("trigger_signal") and os.path.exists(f"trigger_signal/{file}"):
                found_file.write(f"{file}, True\n")
            else:
                found_file.write(f"{file}, False\n")





if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script to find and mutate patterns. \
            Need at least one of the arguments [-bc, -ll, -bn] to get resulting files.")
    parser.add_argument("-s", "--seeds", type=str, default="",
                        help="Comma separated list of seed inputs that will be given to the program under test.")
    parser.add_argument('-cpp', "--cpp", action='store_true',
                        help="Uses clang++ instead of clang for compilation.")
    parser.add_argument("program", type=str,
                        help="Path to the source file that will be mutated.")

    args = parser.parse_args(sys.argv[1:])

    main(args.program, args.seeds.split(","))
