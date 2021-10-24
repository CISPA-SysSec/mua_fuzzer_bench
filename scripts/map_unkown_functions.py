"""
Given a call-graph, maps the unknown functions to possible call locations.
It returns a new call-graph
"""
import sys
import json
from typing import Dict, List, Set, Tuple

UNKNOWN_FUNCTION_IDENTIFIER = ":unnamed:"
SPLITTER = " | "


def augment_graph(orig_graph: Dict[str, List[str]]) -> Dict[str, List[str]]:
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
                if called_funname in result:
                    new_locations.add(called_funname)

        result[function.split(SPLITTER)[0]] = list(new_locations)

    return result


def has_component(vertex: str, components: List[Set[str]]):
    """
    Checks if the given vertex is in any SCC.
    :param vertex:
    :param components:
    :return:
    """
    for comp in components:
        if vertex in comp:
            return True
    return False


def compute_scc(
        vertex: str,
        graph: Dict[str, List[str]],
        preorder: Dict[str, int],
        stack_s: List[str],
        stack_p: List[str],
        components: List[Set[str]],
        preorder_number: int):
    """
    Recursively builds strongly connected components.
    :param vertex:
    :param graph:
    :param preorder:
    :param stack_s:
    :param stack_p:
    :param components:
    :param preorder_number:
    :return:
    """
    stack_s.append(vertex)
    stack_p.append(vertex)
    preorder[vertex] = preorder_number
    preorder_number += 1
    for neighbor in graph.get(vertex, []):
        if neighbor not in preorder:
            compute_scc(neighbor, graph, preorder, stack_s, stack_p, components, preorder_number)
        elif not has_component(neighbor, components):
            neighbor_preorder_number = preorder[neighbor]
            while preorder[stack_p[-1]] > neighbor_preorder_number:
                stack_p.pop()
    if stack_p[-1] == vertex:
        popped = stack_s.pop()
        new_component = set()
        while popped != vertex:
            new_component.add(popped)
            popped = stack_s.pop()
        new_component.add(popped)
        stack_p.pop()
        components.append(new_component)


def build_scc_edges(sccs: Dict[str, int], graph: Dict[str, List[str]]):
    """
    Takes the sccs and builds a new graph based on them.
    :param sccs:
    :return:
    """
    # build the scc DAG
    scc_dag = {}
    for vert, uid in sccs.items():
        vert_scc = scc_dag.setdefault(sccs[vert], set())
        vert_scc.add(uid)
        for neighbor in graph[vert]:
            vert_scc.add(sccs[neighbor])
        # add itself as a scc is reachable from itself

    # compute for any scc the reachable scc's
    reachable_dict = {}
    for uid in scc_dag:
        reachable = {uid}
        neighbors: Set[int] = set(scc_dag[uid])
        while neighbors:
            neighbor = neighbors.pop()
            reachable.add(neighbor)
            neighbors.update({el for el in scc_dag[neighbor] if el not in reachable})
        reachable_dict[uid] = reachable
    return reachable_dict


def compute_sccs(graph: Dict[str, List[str]]) -> Dict[str, int]:
    # use Dijkstra's SCC algorithm: https://en.wikipedia.org/wiki/Path-based_strong_component_algorithm
    components = []
    preorders = {}
    compute_scc("main", graph, preorders, [], [], components, 0)
    print(components, preorders)

    result = {}
    uid = 0
    for comp in components:
        for vert in comp:
            result[vert] = uid
        uid += 1
    return result


def main(path: str):
    """
    Takes a path to a graph file and returns a graph as dictionary containing resolved unnamed calls.
    :param path:
    :return:
    """
    with open(path, "r") as graph_file:
        orig_graph = json.load(graph_file)
    augmented_graph = augment_graph(orig_graph)
    sccs = compute_sccs(augmented_graph)
    build_scc_edges(sccs, augmented_graph)


if __name__ == "__main__":
    main(sys.argv[1])
