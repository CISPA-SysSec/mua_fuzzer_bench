"""
Given a call-graph, maps the unknown functions to possible call locations.
It returns a new call-graph
"""
import sys
import json
from typing import Dict, List

UNKNOWN_FUNCTION_IDENTIFIER = ":unnamed:"
SPLITTER = " | "

def augment_graph(orig_graph: Dict[str,List[str]]):
    """
    Takes the graph and augments it by replacing unknown function calls with all possible calls.
    :param orig_graph:
    :return:
    """
    result = dict()
    mapping = dict()
    # first get an initial mapping of the result set and collect all known functions
    for key in orig_graph.keys():
        key_splitted = key.split(SPLITTER)[:-1]
        funname = key_splitted[0]
        result[funname] = list()
        mapped_head = mapping.setdefault(tuple(key_splitted[1:]), list())
        mapped_head.append(funname)

    #then go over all call locations and look for replacements for unknown calls and just add known calls
    for function, call_locations in orig_graph.items():
        new_locations = set()
        for call_location in call_locations:
            call_splitted = call_location.split(SPLITTER)[:-1]
            called_funname = call_splitted[0]
            if called_funname == UNKNOWN_FUNCTION_IDENTIFIER:
                call_types = tuple(call_splitted[1:])
                if call_types in mapping:
                    for fun in mapping[call_types]:
                        new_locations.add(fun)
            else:
                new_locations.add(called_funname)

        result[function.split(SPLITTER)[0]] = list(new_locations)

    return result

def main(path: str) -> Dict[str,List[str]]:
    """
    Takes a path to a graph file and returns a graph as dictionary containing resolved unnamed calls.
    :param path:
    :return:
    """
    with open(path, "r") as graph_file:
        orig_graph = json.load(graph_file)
    return augment_graph(orig_graph)

if __name__ == "__main__":
    main(sys.argv[1])