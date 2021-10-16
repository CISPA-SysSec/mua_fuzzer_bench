#!/usr/bin/env python3

import json
from collections import defaultdict
from pathlib import Path


def get_prog_results(base_dir):
    results = defaultdict(dict)

    for cov_res in (base_dir/"result").glob("*"):
        with open(cov_res, "rt") as f:
            data = json.load(f)
        results[cov_res.stem]['covered_lines'] = len({tuple(x) for x in data['covered_lines']})
        results[cov_res.stem]['total_lines'] = len({tuple(x) for x in data['all_lines']})

    for prog in (base_dir/"seeds").glob("*"):
        results[prog.stem]['files'] = len(list(prog.glob('*')))

    return results


def get_prog_fuzzer_results(base_dir):
    results = defaultdict(dict)

    for seed_dir in (base_dir/"seeds").glob("*/*"):
        prog = seed_dir.parent.stem
        fuzzer = seed_dir.stem
        key = f"{prog}-{fuzzer}"

        results[key]['files'] = len(list(seed_dir.glob('*')))

        with open(base_dir/"result"/f"{key}.json", "rt") as f:
            data = json.load(f)
        results[key]['covered_lines'] = len({tuple(x) for x in data['covered_lines']})
        results[key]['total_lines'] = len({tuple(x) for x in data['all_lines']})

    return results


def print_results(results):
    for name, data in results.items():
        print(f"{name}: {data['covered_lines']} / {data['total_lines']} with {data['files']} files")


def main():
    print("initial")
    print_results(get_prog_results(Path("tmp/seed_coverage/initial")))
    print()
    print("fuzzed")
    print_results(get_prog_results(Path("tmp/seed_coverage/fuzzed")))
    print()
    print("final")
    print_results(get_prog_fuzzer_results(Path("tmp/seed_coverage/final")))
    print()


if __name__ == "__main__":
    main()
