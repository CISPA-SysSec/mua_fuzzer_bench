#!/usr/bin/env python3

import argparse
import os
import sys
import subprocess
import shutil
import json
from pathlib import Path
from typing import List, Tuple, Set
import xml.etree.ElementTree as ET
from multiprocessing import Process


def run_under_kcov(counter: int, prog: str, args, abs_seed: str):
    """
    Takes all necessary information for running the subject and then runs it.
    Can be used to run several seeds on the same subject in parallel.
    :param counter:
    :param target:
    :param abs_seed:
    :return:
    """
    args = args.replace("@@", str(abs_seed))
    subprocess.run(["kcov", f"cov/tmp_{counter}", f"{prog}", f"{args}"])


def main(prog, prog_args, seeds, workdir):
    """
    Takes the target and runs all seeds on the prog, collects coverage with kcov (first one folder per run),
    then merges the coverage folders and deletes the temp folders. Finally, writes all covered lines to workdir/result.json
    :return:
    """
    workdir = Path(workdir)
    os.chdir(workdir)

    prog = Path(prog)
    seeds = Path(seeds)

    # collect seeds
    collected_seeds = list()
    seed_splitted: List[str] = list(seeds.glob("*"))
    while seed_splitted:
        seed = seed_splitted.pop(0)
        if os.path.exists(seed):
            if os.path.isdir(seed):
                raise ValueError("Did not expect a directory in seed dir: {seed}")
            else:
                collected_seeds.append(seed)

    cov_dir = workdir/"cov"

    # run the collected seeds
    counter = 0
    cores = os.cpu_count() - 1  # keep one cpu open for to keep some computing power free
    while counter < len(collected_seeds):
        cov_dir.mkdir()
        to_join: List[Process] = list()
        # collect all processes to run in parallel and start them
        to_run = min(cores, len(collected_seeds) - counter)
        for process_id in range(to_run):
            abs_seed = collected_seeds[counter + process_id]
            # print(f"Running {counter + 1 + process_id} of {len(collected_seeds)} {str(abs_seed)}.")
            proc = Process(target=run_under_kcov, args=(counter + process_id, prog, prog_args, abs_seed))
            to_join.append(proc)
            proc.start()

        # join the started processes
        for proc in to_join:
            proc.join()

        # collect information and prepare for next run
        for process_id in range(to_run):
            abs_seed = collected_seeds[counter + process_id]
            cov_folder = [el for el in os.listdir(f'cov/tmp_{counter + process_id}/')
                            if not el.startswith(f'data') and
                            not el.startswith(f'kcov') and
                            os.path.isdir(f'cov/tmp_{counter + process_id}/{el}')][0]
            # print(f"Covered lines for {abs_seed}: {len(lines_covered(f'cov/tmp_{counter + process_id}/{cov_folder}/cov.xml'))}")

        # merge into result folder and delete old folder to avoid immense amounts of disk and inode usage
        print(f"Merging coverage results into result and deleting temporary coverage folders. "
                f"May take some time ...")
        subprocess.run(["kcov", "--merge", "result"] +
                        [f"cov/tmp_{counter + process_id}" for process_id in range(to_run)]
                        )
        subprocess.run(["rm", "-rf", str(cov_dir)])

        counter += to_run

    # write out final result.json
    covered, total = lines_covered(f"result/kcov-merged/cov.xml")
    print(f"Total: {len(total)}, covered: {len(covered)}")
    with open("result.json", "wt") as f:
        json.dump({ 'covered_lines': list(covered), 'all_lines': list(total) }, f)


def lines_covered(xml_file: str) -> Set[Tuple[str, str]]:
    """
    Extracts from the given xml coverage file the covered lines.
    :param xml_file:
    :return:
    """
    tree = ET.parse(xml_file)
    covered = set()
    total = set()
    for package in tree.getroot().find("packages").findall("package"):
        for cl in package.find("classes").findall("class"):
            for line in cl.find("lines").findall("line"):
                total.add((cl.get("filename"), line.get("number")))
                if int(line.get("hits")) > 0:
                    covered.add((cl.get("filename"), line.get("number")))

    return covered, total


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script to measure coverage of seed files on a program.")
    parser.add_argument("--prog", type=str, required=True,
                        help=f"Path to the program to measure coverage for.")
    parser.add_argument("--prog-args", type=str, required=True,
                        help=f"Arguments to the program to measure coverage for.")
    parser.add_argument("--seeds", type=str, required=True,
                        help=f"Directory containing seed files.")
    parser.add_argument("--workdir", type=str, required=True,
                        help=f"Directory to operate in, results will be stored here.")

    args = parser.parse_args()
    main(args.prog, args.prog_args, args.seeds, args.workdir)
