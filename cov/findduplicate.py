#!/usr/bin/env python3
"""
Takes a mutationlocations file and checks how many non-unique locations exist, prints those with
their number and generates a deduplicated locations file.
"""
import json
import multiprocessing.pool
import os
import sys

new_locs1 = dict()
new_locs2 = dict()

def find_duplicates(args):
    arg_key = args[0]
    arg_value = args[1]
    locs = args[2]
    result = [(arg_key, el_key) for el_key, el_value in locs.items() if el_value == arg_value]
    if len(result) != 1:
        print(result)
        return result
    # else:
    #     print(result)


def main(mutationlocations_filepath1: str, mutationlocations_filepath2: str):
    with open(mutationlocations_filepath1, "r") as ml1_file:
        with open(mutationlocations_filepath2, "r") as ml2_file:
            locations1 = json.load(ml1_file)
            locations2 = json.load(ml2_file)
            for loc in locations1:
                new_locs1[loc["UID"]] = loc
                loc["UID"] = 0
            for loc in locations2:
                new_locs2[loc["UID"]] = loc
                loc["UID"] = 0
            to_check = [(key, value, new_locs2) for key, value in new_locs1.items()]
            with multiprocessing.pool.Pool(os.cpu_count()) as pool:
                duplicates = {tuple(el) for el in pool.imap(find_duplicates, to_check, chunksize=100) if el}
            print(duplicates)
        print(len(duplicates))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
