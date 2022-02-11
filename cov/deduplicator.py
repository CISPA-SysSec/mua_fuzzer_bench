#!/usr/bin/env python3
"""
Takes a mutationlocations file and checks how many non-unique locations exist, prints those with
their number and generates a deduplicated locations file.
"""
import json
import multiprocessing.pool
import os


def find_duplicates(args):
    arg_value = args[0]
    locs = args[1]
    result = [el_key for el_key, el_value in locs[arg_value["funname"]].items() if el_value == arg_value]
    if len(result) > 1:
        # print(result)
        return result


def main(mutationlocations_filepath: str):
    new_locs = dict()
    with open(mutationlocations_filepath, "r") as ml_file:
        locations = json.load(ml_file)
        to_check = list()
        for loc in locations:
            funloc = new_locs.setdefault(loc["funname"], dict())
            funloc[loc["UID"]] = loc
            loc["UID"] = 0
            to_check.append((loc, new_locs))
        with multiprocessing.pool.Pool(os.cpu_count()) as pool:
            duplicates = {tuple(el) for el in pool.map(find_duplicates, to_check) if el}
        print(duplicates)
        print(len(duplicates))


if __name__ == "__main__":
    # main(sys.argv[1])
    main("convert_woff2ttf_fuzzer_new_entry.ll.mutationlocations")
    counter = 1
    while os.path.exists(f"woff2{counter}.mutationlocations"):
        main(f"woff2{counter}.mutationlocations")
        print(f"woff2{counter}.mutationlocations")
        counter += 1
