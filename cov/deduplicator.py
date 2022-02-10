#!/usr/bin/env python3
"""
Takes a mutationlocations file and checks how many non-unique locations exist, prints those with
their number and generates a deduplicated locations file.
"""
import json
import multiprocessing.pool
import os
import sys

new_locs = dict()

def find_duplicates(args):
    arg_value = args[0]
    locs = args[1]
    result = [el_key for el_key, el_value in locs.items() if el_value == arg_value]
    if len(result) > 1:
        print(result)
        return result

def main(mutationlocations_filepath: str):
    with open(mutationlocations_filepath, "r") as ml_file:
        locations = json.load(ml_file)
        for loc in locations:
            new_locs[loc["UID"]] = loc
            loc["UID"] = 0
        to_check = [(value, new_locs) for key, value in new_locs.items()]
        with multiprocessing.pool.Pool(os.cpu_count()) as pool:
            duplicates = {tuple(el) for el in pool.imap(find_duplicates, to_check, chunksize=100) if el}
        print(duplicates)
        print(len(duplicates))


if __name__ == "__main__":
    main(sys.argv[1])
