#!/usr/bin/env python3
import argparse
import os
import sys
import subprocess
import shutil
from typing import List, Tuple, Set

run = {
    "guetzli": ["/home/mutator/samples/guetzli/fuzz_target"],
    "libjpeg": ["/home/mutator/samples/libjpeg-turbo/libjpeg_turbo_fuzzer"],
    "aspell": ["/home/mutator/samples/aspell/aspell-fuzz/aspell_fuzzer"],
    "caresparse": ["/home/mutator/samples/c-ares/out/ares_parse_reply_fuzzer"],
    "caresquery": ["/home/mutator/samples/c-ares/out/ares_create_query_fuzzer"],
    "carestest": ["/home/mutator/samples/c-ares/out/test"],
    "vorbis": ["/home/mutator/samples/vorbis/out/decode_fuzzer"],
    "woff2base": ["/home/mutator/samples/woff2/out/convert_woff2ttf_fuzzer/convert_woff2ttf_fuzzer"],
    "woff2new": ["/home/mutator/samples/woff2/out/convert_woff2ttf_fuzzer_new_entry/convert_woff2ttf_fuzzer_new_entry"],
    "re2": ["/home/mutator/samples/re2-code/re2_fuzzer"],
}

seeds = {
    "guetzli": ["/home/mutator/samples/guetzli_harness/seeds"],
    "libjpeg": ["/home/mutator/samples/libjpeg-turbo_harness/seeds"],
    "aspell": ["/home/mutator/samples/aspell_harness/seeds"],
    "caresparse": ["/home/mutator/samples/c-ares_harness/seeds"],
    "caresquery": ["/home/mutator/samples/c-ares_harness/seeds"],
    "carestest": ["/home/mutator/samples/c-ares_harness/seeds"],
    "vorbis": ["/home/mutator/samples/vorbis_harness/seeds"],
    "woff2base": ["/home/mutator/samples/woff2_harness/seeds"],
    "woff2new": ["/home/mutator/samples/woff2_harness/seeds"],
    "re2": ["/home/mutator/samples/re2_harness/seeds"],
}


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
        counter = 1
        for abs_seed in collected_seeds:
            print(f"Running {counter} of {len(collected_seeds)} {' '.join(run[target] + [abs_seed])}.")
            subprocess.run(["kcov", f"{target}_tmp_{counter}"] + run[target] + [abs_seed])
            counter += 1

        subprocess.run(["kcov", "--merge", target] + [f for f in os.listdir("/cov") if f.startswith(f"{target}_tmp_")])
        subprocess.run(["rm", "-rf"] + [f for f in os.listdir("/cov") if f.startswith(f"{target}_tmp_")])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script to find and mutate patterns. \
            Need at least one of the arguments [-bc, -ll, -bn] to get resulting files.")
    parser.add_argument("-t", "--target", type=str, default="", required=True,
                        help=f"Runs the pipeline for the chosen subject. Possible subjects are: {', '.join(run.keys())}")

    args = parser.parse_args(sys.argv[1:])
    main()
