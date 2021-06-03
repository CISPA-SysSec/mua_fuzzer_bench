#!/usr/bin/env python3
import argparse
import os
import sys
import subprocess
import shutil
from typing import List, Tuple, Set

instrument = {
    "guetzli": ["./run_mutation.py", "samples/guetzli/fuzz_target.bc", "-cpp", "-bn"],
    "libjpeg": ["./run_mutation.py", "samples/libjpeg-turbo/libjpeg_turbo_fuzzer.bc", "-cpp", "-bn"],
    "aspell": ["./run_mutation.py", "samples/aspell/aspell-fuzz/aspell_fuzzer.bc", "-cpp", "-bn"],
    "caresparse": ["./run_mutation.py", "samples/c-ares/out/ares_parse_reply_fuzzer.bc", "-cpp", "-bn"],
    "caresquery": ["./run_mutation.py", "samples/c-ares/out/ares_create_query_fuzzer.bc", "-cpp", "-bn"],
    "woff2base": ["./run_mutation.py", "samples/woff2/out/convert_woff2ttf_fuzzer/convert_woff2ttf_fuzzer.bc", "-cpp", "-bn"],
    "woff2new": ["./run_mutation.py", "samples/woff2/out/convert_woff2ttf_fuzzer_new_entry/convert_woff2ttf_fuzzer_new_entry.bc", "-cpp", "-bn"],
    "re2": ["./run_mutation.py", "samples/re2-code/re2_fuzzer.bc", "-cpp", "-bn", '--bin-args="-lpthread"'],
}


run = {
    "guetzli": ["/home/mutator/samples/guetzli/fuzz_target.ll.opt_mutate"],
    "libjpeg": ["/home/mutator/samples/libjpeg-turbo/libjpeg_turbo_fuzzer.ll.opt_mutate"],
    "aspell": ["/home/mutator/samples/aspell/aspell-fuzz/aspell_fuzzer.ll.opt_mutate"],
    "caresparse": ["/home/mutator/samples/c-ares/out/ares_parse_reply_fuzzer.ll.opt_mutate"],
    "caresquery": ["/home/mutator/samples/c-ares/out/ares_create_query_fuzzer.ll.opt_mutate"],
    "vorbis": ["/home/mutator/samples/vorbis/out/decode_fuzzer.ll.opt_mutate"],
    "woff2base": ["/home/mutator/samples/woff2/out/convert_woff2ttf_fuzzer/convert_woff2ttf_fuzzer.ll.opt_mutate"],
    "woff2new": ["/home/mutator/samples/woff2/out/convert_woff2ttf_fuzzer_new_entry/convert_woff2ttf_fuzzer_new_entry.ll.opt_mutate"],
    "re2": ["/home/mutator/samples/re2-code/re2_fuzzer.ll.opt_mutate"],
}

seeds = {
    "guetzli": ["/home/mutator/samples/guetzli_harness/seeds"],
    "libjpeg": ["/home/mutator/samples/libjpeg-turbo_harness/seeds"],
    "aspell": ["/home/mutator/samples/aspell_harness/seeds"],
    "caresparse": ["/home/mutator/samples/c-ares_harness/seeds"],
    "caresquery": ["/home/mutator/samples/c-ares_harness/seeds"],
    "vorbis": ["/home/mutator/samples/vorbis_harness/seeds"],
    "woff2base": ["/home/mutator/samples/woff2_harness/seeds"],
    "woff2new": ["/home/mutator/samples/woff2_harness/seeds"],
    "re2": ["/home/mutator/samples/re2_harness/seeds"],
}

def main():
    target = args.target
    if target in instrument and target in run:
        os.chdir("/home/mutator")
        subprocess.run(instrument[target])

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

        # gives for each seed input the triggered signals
        signal_list: List[Tuple[str, List[str]]] = list()
        signal_folder = "trigger_signal"
        counter = 1
        for abs_seed in collected_seeds:
            print(f"Running {counter} of {len(collected_seeds)} {' '.join(run[target] + [abs_seed])}.")
            shutil.rmtree(signal_folder, ignore_errors=True)
            subprocess.run(run[target] + [abs_seed])
            signal_list.append((abs_seed, set(os.listdir(signal_folder))))
            counter += 1
        shutil.rmtree(signal_folder, ignore_errors=True)

        # all signals are collected, now we can see which seeds to take for minimalization
        minimized_seeds = list()
        while signal_list:
            max_val = max(signal_list, key=lambda x: (len(x[1]), x[0]))
            minimized_seeds.append(max_val)
            signal_list.remove(max_val)
            signal_list = update_signal_list(signal_list, max_val)

        # now we put the minimized seeds into a new folder
        result_folder = f"/cov/minimized_seeds_{target}"
        shutil.rmtree(result_folder, ignore_errors=True)
        os.mkdir(result_folder)
        counter = 0
        for min_seed in minimized_seeds:
            min_seed_path = min_seed[0]
            print(f"Taking seed with {len(min_seed[1])} additional signals found: {min_seed_path}")
            shutil.copyfile(min_seed_path, os.path.join(result_folder, str(counter)))
            counter += 1


def update_signal_list(signal_list, to_delete: Set[str]):
    """
    Takes a list of signal tuples and updates the set s.t. all
    :param signal_list:
    :param to_delete:
    :return:
    """
    result = list()
    for val in signal_list:
        new_set = val[1] - to_delete[1]
        # do a diff on the value and then check if there are still unseen signals, if so put the value
        # with the updated set back into the return list
        if new_set:
            result.append((val[0], new_set))
    return result




if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script to find and mutate patterns. \
            Need at least one of the arguments [-bc, -ll, -bn] to get resulting files.")
    parser.add_argument("-t", "--target", type=str, default="", required=True,
                        help=f"Runs the pipeline for the chosen subject. Possible subjects are: {', '.join(instrument.keys())}")

    args = parser.parse_args(sys.argv[1:])
    main()
