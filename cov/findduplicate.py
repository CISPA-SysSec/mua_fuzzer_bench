#!/usr/bin/env python3
"""
Takes two mutationlocations files and checks if there is exactly one matching location for each mutation both files.
I.e. for each location in one file there must be exactly one other location in the other file.
"""
import json
import multiprocessing.pool
import os
import sys
from typing import Dict, Any


def find_duplicates(args):
    arg_key = args[0]
    arg_value = args[1]
    locs = args[2]
    result = [(arg_key, el_key) for el_key, el_value in locs[arg_value["funname"]].items() if el_value == arg_value]
    # if len(result) != 1 or (len(result) == 1 and result[0][0] == result[0][1]):
    if len(result) != 1:
        if len(result) > 1:
            print(f"More than one found: {result}")
        elif len(result) == 0:
            print(f"None found: {arg_key} \n {arg_value} \n\n")

        # print(result)
        return result
    # else:
    #     print(result)

def replace_funnames(el: Dict[str, Any]):
    if "." in el["funname"]:
        el["funname"] = el["funname"].split(".")[0]
    if el["additionalInfo"] and "funname" in el["additionalInfo"] and "." in el["additionalInfo"]["funname"]:
        el["additionalInfo"]["funname"] = el["additionalInfo"]["funname"].split(".")[0]


def main(mutationlocations_filepath1: str, mutationlocations_filepath2: str):
    new_locs1 = dict()
    new_locs2 = dict()
    with open(mutationlocations_filepath1, "r") as ml1_file:
        with open(mutationlocations_filepath2, "r") as ml2_file:
            locations1 = json.load(ml1_file)
            for loc in locations1:
                replace_funnames(loc)
            locations2 = json.load(ml2_file)
            for loc in locations2:
                replace_funnames(loc)

            for loc in locations1:
                funloc = new_locs1.setdefault(loc["funname"], dict())
                funloc[loc["UID"]] = loc
                loc["UID"] = 0
            for loc in locations2:
                new_locs2[loc["UID"]] = loc
                loc["UID"] = 0
            to_check = [(key, value, new_locs1) for key, value in new_locs2.items()]
            with multiprocessing.pool.Pool(os.cpu_count()) as pool:
                duplicates = {tuple(el) for el in pool.map(find_duplicates, to_check) if el}
            print(duplicates)
        print(len(duplicates))


if __name__ == "__main__":
    counter = 1
    main("ares-name-local.ll.mutationlocations", "ares-name-server.ll.mutationlocations")
    # while os.path.exists(f"woff2{counter}.mutationlocations"):
    #     main(f"woff21.mutationlocations", f"woff2{counter}.mutationlocations")
    #     print(f"woff2{counter}.mutationlocations")
    #     counter += 1
