import sqlite3
import json
import networkx as nx
from collections import defaultdict
from itertools import combinations, chain

from networkx.exception import NetworkXNoPath


def import_graph(incident_dict):
    graph = nx.Graph()

    graph.add_nodes_from(incident_dict.keys())

    for node, to_list in incident_dict.items():
        for to_node in to_list:
            graph.add_edge(node, to_node)

    return graph


def distance(graph, fun1, fun2):
    try:
        return nx.shortest_path_length(graph, fun1, fun2)
    except NetworkXNoPath:
        return None


db = sqlite3.connect('data/hi_there/stats_all.db')
c = db.cursor()

data = {}
for prog, sgi in c.execute('select prog, supermutant_graph_info from progs'):
    graph_info = json.loads(sgi)
    graph = import_graph(graph_info['graph'])
    data[prog] = {
        'graph_info': graph_info,
        'graph': graph,
        'mutations': {},
        'multi': defaultdict(lambda: defaultdict(set)),
        'initial': defaultdict(list),
        'mut_in_multi': defaultdict(list),
    }

for prog, funname, mut_id, covered in c.execute("""
    select run_results.prog, funname, mut_id, covered_file_seen from run_results
    inner join mutations on run_results.prog = mutations.prog and run_results.mut_id = mutations.mutation_id
"""):
    data[prog]['mutations'][mut_id] = (funname, covered)

for prog, sm_id, mut_id in c.execute(
        "select prog, super_mutant_id, mutation_id from initial_super_mutants"):
    is_covered = data[prog]['mutations'][mut_id][1]
    if is_covered is not None:
        data[prog]['initial'][sm_id].append((mut_id, is_covered))

for prog, sm_id, group_id, multi_id in c.execute(
        "select prog, super_mutant_id, group_id, multi_ids from super_mutants_multi"):
    data[prog]['multi'][sm_id][group_id].add(multi_id)
    data[prog]['mut_in_multi'][multi_id].append((sm_id, group_id))

stats = {
    'normal_depths': [],
    'normal_distances': [],
    'multi_depths': [],
    'multi_distances': [],
}

for prog, prog_data in data.items():
    prog_graph = prog_data['graph']
    for sm_id, mutations in prog_data['initial'].items():
        mut_ids = tuple(set(sorted([mm[0] for mm in mutations])))
        covered = [mm[1] for mm in mutations]
        multies = set()
        for m_id in mut_ids:
            in_multies = prog_data['mut_in_multi'][m_id]
            for multi in in_multies:
                multies.add(tuple(sorted(prog_data['multi'][multi[0]][multi[1]])))

        mut_ids = set(mut_ids) - set(chain(*multies))

        # print('normal')
        normal_fun = [prog_data['mutations'][mm][0] for mm in mut_ids]
        stats['normal_depths'].extend([distance(prog_graph, 'LLVMFuzzerTestOneInput', mm) for mm in normal_fun])
        stats['normal_distances'].extend([distance(prog_graph, mm1, mm2) for mm1, mm2 in combinations(normal_fun, 2)])

        # print('multi')
        for multi in multies:
            multi_fun = [prog_data['mutations'][mm][0] for mm in multi]
            stats['multi_depths'].extend([distance(prog_graph, 'LLVMFuzzerTestOneInput', mm) for mm in multi_fun])
            stats['multi_distances'].extend([distance(prog_graph, mm1, mm2) for mm1, mm2 in combinations(multi_fun, 2)])

print('normal depth:', 'count:', len(stats['normal_depths']), 'min:', min(stats['normal_depths']), 'max:', max(stats['normal_depths']), 'avg:', sum(stats['normal_depths']) / len(stats['normal_depths']))
print('normal distance:', 'count:', len(stats['normal_distances']), 'min:', min(stats['normal_distances']), 'max:', max(stats['normal_distances']), 'avg:', sum(stats['normal_distances']) / len(stats['normal_distances']))
print('multi depth:', 'count:', len(stats['multi_depths']), 'min:', min(stats['multi_depths']), 'max:', max(stats['multi_depths']), 'avg:', sum(stats['multi_depths']) / len(stats['multi_depths']))
print('multi distance:', 'count:', len(stats['multi_distances']), 'min:', min(stats['multi_distances']), 'max:', max(stats['multi_distances']), 'avg:', sum(stats['multi_distances']) / len(stats['multi_distances']))
