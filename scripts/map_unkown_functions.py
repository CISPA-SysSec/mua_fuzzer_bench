"""
Given a call-graph, maps the unknown functions to possible call locations.
It returns a new call-graph
"""
import os
import sys
import json
import graphviz
from typing import Dict, List, Set, Tuple

UNKNOWN_FUNCTION_IDENTIFIER = ":unnamed:"
SPLITTER = " | "

def build_scc_graph_pdf(location: str, uid_to_scc: Dict[int, str], forward_dag: Dict[int, Set[int]]):
    tmp_uid_to_scc = dict()
    for uid, scc in uid_to_scc.items():
        tmp_uid_to_scc[uid] = tuple(scc)
    graph_dict = dict()
    for node, targets in forward_dag.items():
        target_list = [str(tmp_uid_to_scc[target]) for target in targets if target != node]
        graph_dict[str(tmp_uid_to_scc[node])] = target_list
    # print(graph_dict)
    build_graph_pdf(location, graph_dict)


def build_graph_pdf(location: str, graph: Dict[str, List[str]]):
    """
    Takes a graph as dictionary and builds a pdf which shows the graph as generated from graphviz.
    :param location: file to save the graph to
    :param graph: the graph as dictionary
    :return:
    """
    dot = graphviz.Digraph()
    for node in graph.keys():
        dot.node(node, label=node)
    for node, targets in graph.items():
        for target in targets:
            dot.edge(node, target)
    dot.render(location)


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


def build_scc_reachability_mapping(sccs: Dict[str, int], graph: Dict[str, List[str]]):
    """
    Takes the sccs and builds a mapping showing which scc can be reached or can reach any other SCC.
    :param sccs:
    :return:
    """
    # build the scc DAG
    scc_forward_dag = {}
    for vert, uid in sccs.items():
        vert_scc = scc_forward_dag.setdefault(sccs[vert], set())
        vert_scc.add(uid)
        for neighbor in graph[vert]:
            vert_scc.add(sccs[neighbor])


    scc_backward_dag = {}
    for vert, uid in sccs.items():
        vert_scc = scc_backward_dag.setdefault(sccs[vert], set())
        vert_scc.add(uid)
        for neighbor in graph[vert]:
            child_scc = scc_backward_dag.setdefault(sccs[neighbor], set())
            child_scc.add(sccs[vert])

    # compute for any scc the reachable scc's
    reachable_dict = {}
    for uid in scc_forward_dag:
        reachable = {uid}
        children: Set[int] = set(scc_forward_dag[uid])
        while children:
            child = children.pop()
            reachable.add(child)
            children.update({el for el in scc_forward_dag[child] if el not in reachable})
        reachable_dict[uid] = reachable

    for uid in scc_backward_dag:
        reachable = {uid}
        parents: Set[int] = set(scc_backward_dag[uid])
        while parents:
            parent = parents.pop()
            reachable.add(parent)
            parents.update({el for el in scc_backward_dag[parent] if el not in reachable})
        reachable_dict[uid].update(reachable)
    return reachable_dict, scc_forward_dag


def compute_non_reaching_set_random(reachability_dict: Dict[int, Set[int]]):
    """
    Takes a reachability dictionary and greedily grows unreachable sets of SCCs.
    :param reachability_dict:
    :return:
    """
    # to_compute = {el for el in range(len(reachability_dict))}
    to_compute = set(reachability_dict.keys())
    exclusion_list = list()
    while to_compute:
        seed_value = to_compute.pop()
        tmp_exclusion_set = {seed_value}
        tmp_reachability_set = set(reachability_dict[seed_value])
        for el in to_compute:
            if el not in tmp_reachability_set:
                tmp_exclusion_set.add(el)
                tmp_reachability_set.update(reachability_dict[el])
        to_compute.difference_update(tmp_exclusion_set)
        exclusion_list.append(tmp_exclusion_set)
    return exclusion_list


def compute_sccs(graph: Dict[str, List[str]]) -> Tuple[Dict[str, int], Dict[int, str]]:
    """
    Computing Strongly Connected Components with Dijkstra algorithm (linear in edges+nodes).
    :param graph:
    :return:
    """
    # use Dijkstra's SCC algorithm: https://en.wikipedia.org/wiki/Path-based_strong_component_algorithm
    components = []
    preorders = {}
    compute_scc("main", graph, preorders, [], [], components, 0)
    # print(components, preorders)

    sccs = {}
    sccs_uid_to_name = {}
    uid = 0
    for comp in components:
        sccs_uid_to_name[uid] = comp
        for vert in comp:
            sccs[vert] = uid
        uid += 1
    return sccs, sccs_uid_to_name

def read_mutation_locations(path: str):
    """
    Reads in the locations and maps them to the according functions and vice versa.
    :param path:
    :return:
    """
    with open(path, "r") as locations_file:
        locations = json.load(locations_file)
    location_function_mapping = dict()
    function_location_mapping = dict()
    for location in locations:
        funname = location["funname"]
        uid = location["UID"]
        location_function_mapping[uid] = funname
        uid_set = function_location_mapping.setdefault(funname, set())
        uid_set.add(uid)
    return location_function_mapping, function_location_mapping


def build_supermutants(scc_reachability_mapping, sccs, sccs_uid_to_vert, location_function_mapping, function_location_mapping):
    """
    Builds a list of sets which represent the different supermutants that can be built.
    :param scc_reachability_mapping:
    :param sccs_uid_to_vert:
    :param location_function_mapping:
    :param function_location_mapping:
    :return:
    """
    # first compute for each mutation the excluded mutations
    excluding_mutations = dict()
    for location, function in location_function_mapping.items():
        if function in sccs:
            reachable_mutations = set()
            for scc_reachable in scc_reachability_mapping[sccs[function]]:
                for scc_fun in sccs_uid_to_vert[scc_reachable]:
                    if scc_fun in function_location_mapping:
                        reachable_mutations |= function_location_mapping[scc_fun]
            excluding_mutations[location] = reachable_mutations
    supermutants = compute_non_reaching_set_random(excluding_mutations)
    print(f"Reachable reduction rate: {sum(len(mutations) for mutations in supermutants) / len(supermutants)}")
    unreachable_mutations: Dict[int, Set[int]] = dict()
    for fun, locations in function_location_mapping.items():
        if fun not in sccs:
            unreachable_mutations[fun] = locations
    # now fill the supermutants with unreachable mutations randomly
    # prefer mutants with a smaller number of mutations
    for mutant in sorted(supermutants, key=lambda x: len(x)):
        for unreachable in set(unreachable_mutations.keys()):
            unreachable_value = unreachable_mutations[unreachable]
            if unreachable_value:
                mutant.add(unreachable_value.pop())
            if not unreachable_value:
                unreachable_mutations.pop(unreachable)
            if len(mutant) >= 100: # make sure that no more than 100 mutations are in the mutant set for compilation issues
                break
    # if there are even more unreachables, put them in additional mutants
    if unreachable_mutations:
        while unreachable_mutations:
            mutant = set()
            for unreachable in set(unreachable_mutations.keys()):
                unreachable_value = unreachable_mutations[unreachable]
                if unreachable_value:
                    mutant.add(unreachable_value.pop())
                if not unreachable_value:
                    unreachable_mutations.pop(unreachable)
                if len(mutant) >= 100: # make sure that no more than 100 mutations are in the mutant set for compilation issues
                    break
            supermutants.append(mutant)
    print(f"Including unreachable reduction rate: {sum(len(mutations) for mutations in supermutants) / len(supermutants)}")
    # check if the number of mutations matches with the number of locations
    assert len(location_function_mapping) == sum(len(mutations) for mutations in supermutants)
    # check that all mutations are assigned exactly once
    for location in location_function_mapping:
        found = False
        for mutations in supermutants:
            if location in mutations:
                assert not found
                found = True
        assert found
    return supermutants

def main(path: str):
    """
    Takes a path to a graph file and returns a list of lists of mutually exclusive function sets.
    That is: pick any list from the root list, then pick from every function set at most one function.
    The picked functions are not reachable by each other.
    :param path:
    :return: The list of mutually exclusive functions plus a list of functions that is unreachable from the main function.
    """
    with open(path, "r") as graph_file:
        orig_graph = json.load(graph_file)
    augmented_graph = augment_graph(orig_graph)
    build_graph_pdf(path + ".digraph", augmented_graph)
    sccs, sccs_uid_to_vert = compute_sccs(augmented_graph)
    scc_reachability_mapping, scc_forward_dag = build_scc_reachability_mapping(sccs, augmented_graph)
    build_scc_graph_pdf(path + ".scc.digraph", sccs_uid_to_vert, scc_forward_dag)
    location_function_mapping, function_location_mapping = read_mutation_locations(path.replace(".graph", ""))
    supermutants = build_supermutants(scc_reachability_mapping, sccs, sccs_uid_to_vert, location_function_mapping, function_location_mapping)

    return supermutants
    # exclusion_list = compute_non_reaching_set_random(scc_reachability_mapping)
    # final_list = []  # will contain a list of lists containing mutually exclusive
    # for excl_set in exclusion_list:
    #     tmp_exclusion_list = list()
    #     for scc in excl_set:
    #         tmp_exclusion_list.append(set(sccs_uid_to_vert[scc]))
    #     final_list.append(tmp_exclusion_list)
    # reachable_functions = set(sccs.keys())
    # unreachable_functions = set(augmented_graph) - reachable_functions
    # return final_list , unreachable_functions


if __name__ == "__main__":
    # print(main(sys.argv[1]))
    main(sys.argv[1])
