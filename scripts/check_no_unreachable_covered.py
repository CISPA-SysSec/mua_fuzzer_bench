import sqlite3
import json

db = sqlite3.connect('data/hi_there/stats_all.db')
c = db.cursor()

data = {}
for prog, sgi in c.execute('select prog, supermutant_graph_info from progs'):
    data[prog] = {
        'graph_info': json.loads(sgi),
        'mutations': [],
    }

for prog, funname, mut_id, covered in c.execute("""
    select run_results.prog, funname, mut_id, covered_file_seen from run_results
    inner join mutations on run_results.prog = mutations.prog and run_results.mut_id = mutations.mutation_id
"""):
    data[prog]['mutations'].append((funname, mut_id, covered))

for prog, data in data.items():
    unreach = data['graph_info']['unreachable']
    reach = [ff for fs in data['graph_info']['disjunct'] for fs2 in fs for ff in fs2]
    # print(unreach)
    # print(reach)
    for funname, mut_id, covered in data['mutations']:
        if covered is not None:
            if funname in unreach:
                print('in unreach', funname, mut_id, covered)
            if funname not in reach:
                print('not in reach', funname, mut_id, covered)
