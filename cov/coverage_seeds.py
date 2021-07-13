#!/usr/bin/env python3
import argparse
import os
import sys
import subprocess
import shutil
from typing import List, Tuple, Set
import xml.etree.ElementTree as ET
from multiprocessing import Process

run = {
    "guetzli": ["/home/mutator/samples/guetzli/fuzz_target"],
    "libjpeg": ["/home/mutator/samples/libjpeg-turbo/libjpeg_turbo_fuzzer"],
    "aspell": ["/home/mutator/samples/aspell/aspell-fuzz/aspell_fuzzer"],
    "cares_parse_reply": ["/home/mutator/samples/c-ares/out/ares_parse_reply_fuzzer"],
    "cares_name": ["/home/mutator/samples/c-ares/out/ares_create_query_fuzzer"],
    "vorbis": ["/home/mutator/samples/vorbis/out/decode_fuzzer"],
    "woff2_base": ["/home/mutator/samples/woff2/out/convert_woff2ttf_fuzzer/convert_woff2ttf_fuzzer"],
    "woff2_new": ["/home/mutator/samples/woff2/out/convert_woff2ttf_fuzzer_new_entry/convert_woff2ttf_fuzzer_new_entry"],
    "re2": ["/home/mutator/samples/re2-code/re2_fuzzer"],
}

seeds = {
    "guetzli": ["/cov/fuzzed-seeds/fuzzed_seeds/guetzli"],
    "libjpeg": ["/cov/fuzzed-seeds/fuzzed_seeds/libjpeg"],
    "aspell": ["/cov/fuzzed-seeds/fuzzed_seeds/aspell"],
    "cares_parse_reply": ["/cov/fuzzed-seeds/fuzzed_seeds/cares_parse_reply"],
    "cares_name": ["/cov/fuzzed-seeds/fuzzed_seeds/cares_name"],
    "vorbis": ["/cov/fuzzed-seeds/fuzzed_seeds/vorbis"],
    "woff2_base": ["/cov/fuzzed-seeds/fuzzed_seeds/woff2_base"],
    "woff2_new": ["/cov/fuzzed-seeds/fuzzed_seeds/woff2_new"],
    "re2": ["/cov/fuzzed-seeds/fuzzed_seeds/re2"],
}


def run_under_kcov(counter: int, target: str, abs_seed: str):
    """
    Takes all necessary information for running the subject and then runs it.
    Can be used to run several seeds on the same subject in parallel.
    :param counter:
    :param target:
    :param abs_seed:
    :return:
    """
    subprocess.run(["kcov", f"{target}_tmp_{counter}"] + run[target] + [abs_seed])


def main():
    """
    Takes the target and runs all seeds of the target on the target, collects coverage with kcov (first one folder per run),
    then merges the coverage folders and deletes the temp folders.
    :return:
    """
    target = args.target
    if target in seeds and target in run:
        os.chdir("/home/mutator")

        # collect seeds
        collected_seeds = list()
        seed_splitted: List[str] = seeds[target]
        while seed_splitted:
            seed = seed_splitted.pop(0)
            if os.path.exists(seed):
                if os.path.isdir(seed):
                    seed_splitted += [os.path.join(seed, el) for el in os.listdir(seed)]
                else:
                    collected_seeds.append(seed)
        os.chdir("/cov")

        # run the collected seeds
        subprocess.run(["rm", "-rf"] + [f for f in os.listdir("/cov") if f.startswith(f"{target}")])
        subprocess.run(["rm", "-rf", f"/cov/minimized_seeds_cov_{target}"])
        seed_store = list()
        counter = 0
        os.mkdir(target)
        cores = os.cpu_count() - 1  # keep one cpu open for to keep some computing power free
        while counter < len(collected_seeds):
            to_join: List[Process] = list()
            # collect all processes to run in parallel and start them
            to_run = min(cores, len(collected_seeds) - counter)
            for process_id in range(to_run):
                abs_seed = collected_seeds[counter + process_id]
                print(f"Running {counter + 1 + process_id} of {len(collected_seeds)} {' '.join(run[target] + [abs_seed])}.")
                proc = Process(target=run_under_kcov, args=(counter + process_id, target, abs_seed))
                to_join.append(proc)
                proc.start()

            # join the started processes
            for proc in to_join:
                proc.join()

            # collect information and prepare for next run
            for process_id in range(to_run):
                abs_seed = collected_seeds[counter + process_id]
                cov_folder = [el for el in os.listdir(f'{target}_tmp_{counter + process_id}/')
                              if not el.startswith(f'data') and
                              not el.startswith(f'kcov') and
                              os.path.isdir(f'{target}_tmp_{counter + process_id}/{el}')][0]
                print(f"Covered lines for {abs_seed}:")
                seed_store.append((abs_seed, lines_covered(f"{target}_tmp_{counter + process_id}/{cov_folder}/cov.xml")))

            # merge into target folder and delete old folder to avoid immense amounts of disk and inode usage
            print(f"Merging coverage results into {target} and deleting temporary coverage folders. "
                  f"May take some time ...")
            os.rename(os.path.join("/cov", target), os.path.join("/cov", f"{target}_tmp"))
            subprocess.run(["kcov", "--merge", target] +
                           [f"{target}_tmp"] +
                           [f"{target}_tmp_{counter + process_id}" for process_id in range(to_run)]
                           )
            subprocess.run(["rm", "-rf"] +
                           [f"{target}_tmp"] +
                           [f"{target}_tmp_{counter + process_id}" for process_id in range(to_run)]
                           )

            counter += to_run

        # all coverages are collected, now we can see which seeds to take for minimalization
        minimized_seeds = list()
        while seed_store:
            max_val = max(seed_store, key=lambda x: (len(x[1]), x[0]))
            minimized_seeds.append(max_val)
            seed_store.remove(max_val)
            seed_store = update_coverage_list(seed_store, max_val)

        # now we put the minimized seeds into a new folder
        result_folder = f"/cov/minimized_seeds_cov_{target}"
        shutil.rmtree(result_folder, ignore_errors=True)
        os.mkdir(result_folder)
        counter = 0
        sum_lines = 0
        for min_seed in minimized_seeds:
            min_seed_path = min_seed[0]
            sum_lines += len(min_seed[1])
            print(f"Taking seed with {len(min_seed[1])} additional lines found: {min_seed_path}")
            shutil.copyfile(min_seed_path, os.path.join(result_folder, str(counter)))
            counter += 1
        print(f"Total number of lines is: {sum_lines}")


def update_coverage_list(coverage_list, to_delete: Tuple[str, str]):
    """
    Takes a list of signal tuples and updates the set s.t. all
    :param coverage_list:
    :param to_delete:
    :return:
    """
    result = list()
    for val in coverage_list:
        new_set = val[1] - to_delete[1]
        # do a diff on the value and then check if there are still unseen signals, if so put the value
        # with the updated set back into the return list
        if new_set:
            result.append((val[0], new_set))
    return result


def lines_covered(xml_file: str) -> Set[Tuple[str, str]]:
    """
    Extracts from the given xml coverage file the covered lines.
    :param xml_file:
    :return:
    """
    tree = ET.parse(xml_file)
    summary = set()
    for package in tree.getroot().find("packages").findall("package"):
        for cl in package.find("classes").findall("class"):
            for line in cl.find("lines").findall("line"):
                if int(line.get("hits")) > 0:
                    summary.add((cl.get("filename"), line.get("number")))

    print(f"\t{len(summary)}")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script to find and mutate patterns. \
            Need at least one of the arguments [-bc, -ll, -bn] to get resulting files.")
    parser.add_argument("-t", "--target", type=str, default="", required=True,
                        help=f"Runs the pipeline for the chosen subject. Possible subjects are: {', '.join(run.keys())}")

    args = parser.parse_args(sys.argv[1:])
    main()


