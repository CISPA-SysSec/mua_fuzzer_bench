from subprocess import run
from pathlib import Path
from collections import defaultdict
import re
import time
import pydot
import networkx as nx


def get_dot_file_graph(path):
    graphs = pydot.graph_from_dot_file(path)
    return graphs[0]


def label_lines(label):
    lines =  [
        re.sub(' #[0-9]+,?', '', ll)
        for ll 
        in label[1:-1].replace('\\l...', '').replace("\\l", "\n").replace("\\", "").splitlines()
    ]

    joined_lines = []
    for ii, ll in enumerate(lines):
        if ll.endswith(" ["):
            bracket_start = ii
            for ii, ll in enumerate(lines[ii:]):
                if ll.startswith("  ]"):
                    bracket_end = bracket_start + ii + 1
                    joined_line = [lines[bracket_start]] + [ll.strip() for ll in lines[bracket_start+1:bracket_end]]
                    joined_line = ' '.join(joined_line)
                    joined_lines.append((bracket_start, bracket_end, joined_line))
    if joined_lines:
        for a, b in zip(joined_lines[:-1], joined_lines[1:]):
            assert a[0] < a[1] < b[0]

        for start, end, content in reversed(joined_lines):
            lines = lines[:start] + [content] + lines[end:]

    return lines

    

def add_function_cfg(cfg_graph, path):
    graph_dot = get_dot_file_graph(path)

    nodes = graph_dot.get_nodes()
    edges = graph_dot.get_edges()
    name = graph_dot.get_name()
    type_ = graph_dot.get_type()

    function_name = name.split("'")[1]
    # print(function_name)
    assert type_ == "digraph", type_

    new_nodes = []
    for ii, nn in enumerate(nodes):
        if nn.get_name() == '"\\n"':
            continue

        nn_label = nn.get_label()
        bb_label = label_lines(nn_label)[0][1:-1]
        bb_lines = label_lines(nn_label)[1:-1]

        if ii == 0:
            bb_node_name = f"{function_name}"
            bb_entry_name = f"{function_name}-{bb_label}"
        else:
            bb_node_name = f"{function_name}-{bb_label}"

        for ll in bb_lines:
            if '#' in ll:
                print(ll)
            cfg_graph.graph['instr'][function_name][ll] = bb_node_name
        new_nodes.append((bb_node_name, {'bb_lines': bb_lines}))

    cfg_graph.add_nodes_from(new_nodes)
    cfg_graph.graph['func_nodes'][function_name] = set((nn[0] for nn in new_nodes))
    for (nn_name, *_) in new_nodes:
        assert nn_name not in cfg_graph.graph['node_to_func']
        cfg_graph.graph['node_to_func'][nn_name] = function_name

    new_edges = []
    for ee in edges:
        source = ee.get_source()
        destination = ee.get_destination()

        source_node = graph_dot.get_node(source.split(":")[0])[0]
        dest_node = graph_dot.get_node(destination.split(":")[0])[0]

        source_label = label_lines(source_node.get_label())[0][1:-1]
        dest_label = label_lines(dest_node.get_label())[0][1:-1]

        source_label = f"{function_name}-{source_label}"
        if source_label == bb_entry_name:
            source_label = f"{function_name}"
        dest_label = f"{function_name}-{dest_label}"
        if dest_label == bb_entry_name:
            dest_label = f"{function_name}"

        new_edges.append((source_label, dest_label))

    cfg_graph.add_edges_from(new_edges)


def create_initial_graph(path):
    bitcode = (Path(path)/"bitcode.ll").read_text()
    cfg_graph = nx.DiGraph()
    cfg_graph.graph['instr'] = defaultdict(dict)
    cfg_graph.graph['func_nodes'] = defaultdict(list)
    cfg_graph.graph['node_to_func'] = {}
    cfg_graph.graph['nodes_calling_func'] = {}
    cfg_graph.graph['callsites_in_func'] = defaultdict(list) # list: cs_bb, cs_instr, called_func
    cfg_graph.graph['bb_calls'] = defaultdict(set)
    cfg_graph.graph['func_instr_calls'] = defaultdict(set)
    cfg_graph.graph['node_to_muts'] = defaultdict(list)
    cfg_graph.graph['mut_to_node'] = {}
    cfg_graph.graph['mut_to_instr'] = {}
    cfg_graph.graph['mut_failed'] = set()

    for pp in Path(path).glob("*.dot"):
        add_function_cfg(cfg_graph, pp)

    return cfg_graph, bitcode


def add_function_call_edges(cfg_graph, call_info):
    # Callgraph
    call_graph = nx.DiGraph()

    # need to add edges after all are found to avoid confusing edges
    all_edges_to_add = []

    # def get_terminator(nn):
    #     last_instr = cfg_graph.nodes[nn]['bb_lines'][-1]
    #     if last_instr.startswith("  br "):
    #         pass
    #     elif last_instr.startswith("  ret "):
    #         pass
    #     elif last_instr.startswith("  switch "):
    #         pass
    #     elif last_instr.startswith("  indirectbr "):
    #         print(last_instr)
    #         raise NotImplementedError()
    #     elif last_instr.startswith("  invoke "):
    #         print(last_instr)
    #         raise NotImplementedError()
    #     elif last_instr.startswith("  callbr "):
    #         print(last_instr)
    #         raise NotImplementedError()
    #     elif last_instr.startswith("  resume "):
    #         print(last_instr)
    #         raise NotImplementedError()
    #     elif last_instr.startswith("  catchswitch "):
    #         print(last_instr)
    #         raise NotImplementedError()
    #     elif last_instr.startswith("  catchret "):
    #         print(last_instr)
    #         raise NotImplementedError()
    #     elif last_instr.startswith("  cleanupret "):
    #         print(last_instr)
    #         raise NotImplementedError()
    #     elif last_instr.startswith("  unreachable "):
    #         print(last_instr)
    #         raise NotImplementedError()
    #     else:
    #         print(cfg_graph.nodes[nn]['bb_lines'])
    #         raise NotImplementedError()

    def add_edges(func_name, nn, instr):
        # check if function is known
        cfg_graph.nodes[func_name] # raises key error if not known
        
        cur_func = cfg_graph.graph['node_to_func'][nn]

        cfg_graph.graph['bb_calls'][nn].add(func_name)
        cfg_graph.graph['func_instr_calls'][(cur_func, instr)].add(func_name)
        cfg_graph.graph['callsites_in_func'][cur_func].append((nn, instr, func_name)) # list: cs_bb, cs_instr, called_func
        call_graph.add_edge(cfg_graph.graph['node_to_func'][nn], func_name)
            
    for nn in cfg_graph.nodes:
        for ll in cfg_graph.nodes[nn]['bb_lines']:
            if " call " in ll or " invoke " in ll:
                # static calls
                if mm := re.match(".*(?:call|invoke) .*@(\S+)(\(.*| to )", ll):
                    func_name = mm.group(1)
                    if func_name.startswith("llvm."):
                        continue
                    try:
                        add_edges(func_name, nn, ll)
                    except KeyError:
                        # print(f"not found {func_name}")
                        pass
                elif mm := re.match(".*(?:call|invoke) .*?(\S+) %(?:\S+)\((.*)\)", ll): # dynamic calls
                    if "!callees" in ll:
                        print("has callees:", ll)
                    return_type = mm.group(1)
                    args = mm.group(2)
                    func_args = (return_type, *(aa.strip().split(' ')[0] for aa in args.split(',')))
                    for func_name in call_info[func_args]:
                        try:
                            add_edges(func_name, nn, ll)
                        except KeyError:
                            raise ValueError("Expected to only work with known functions in cfg.")
                elif mm := re.match(".*(?:call|invoke) .* asm ", ll): # assembly calls
                    # ignore assembly calls
                    print("asm:", ll)
                else: # something is wrong
                    print(cfg_graph.nodes[nn]['bb_lines'])
                    print("#", mm, nn, ll)
                    import pdb; pdb.set_trace()
                    raise ValueError("Could not match call instruction.")

    cfg_graph.add_edges_from(all_edges_to_add)

    return call_graph


def load_mutations(cfg_graph, mutations):
    for rr in mutations:
        mutation_id, funname, instr = rr
        instr = re.sub(' #[0-9]+,?', '', instr)
        if instr not in cfg_graph.graph['instr'][funname]:
            cfg_graph.graph['mut_failed'].add(mutation_id)
            continue
        node = cfg_graph.graph['instr'][funname][instr]
        cfg_graph.graph['node_to_muts'][node].append(mutation_id)
        cfg_graph.graph['mut_to_node'][mutation_id] = node 
        cfg_graph.graph['mut_to_instr'][mutation_id] = instr


def get_reachable_mutants(cfg_graph, call_graph, entry_node):
    full_graph = cfg_graph.copy()
    for (in_e, out_e) in call_graph.edges():
        assert in_e in full_graph
        assert out_e in full_graph
        full_graph.add_edge(in_e, out_e)

    full_graph = nx.transitive_closure(full_graph, reflexive=None)

    # Get all mutations that are reachable from the entry node.
    reachable_muts = []
    nodes_with_muts = set()
    for nn in full_graph.out_edges(entry_node):
        mut_node = nn[1]
        muts = full_graph.graph['node_to_muts'][mut_node]
        # print(mut_node, muts)
        reachable_muts.extend(muts)
        if len(muts) > 0:
            nodes_with_muts.add(mut_node)
    
    return reachable_muts


def compute_static_slice(tc_cfg_graph, tc_call_graph, to_bb, to_instr):
    static_slice = set()

    current_function = tc_cfg_graph.graph['node_to_func'][to_bb]

    callsites = set()
    callsites.add(((current_function, to_bb, to_instr)))
    full_called_functions = set()

    # get all functions that reach current function from entry function
    reaching_functions = set((ii for (ii, _) in tc_call_graph.in_edges(current_function)))
    # get all callsites in each function that calls the next in the graph
    for rf in reaching_functions:
        for (cs_bb, cs_instr, called_func) in tc_cfg_graph.graph['callsites_in_func'][rf]:
            if called_func in reaching_functions or called_func == current_function:
                callsites.add((rf, cs_bb, cs_instr))

    # for each callsite + to_bb as until_node:
    for func, bb, instr in callsites:
        # get first part of until_node and get bb nodes from calls there
        for potential_call_instr in tc_cfg_graph.nodes[bb]['bb_lines']:
            # Stop at callsite instr / mutation instr
            if potential_call_instr == instr:
                break
            # Record all full reachable functions
            called_funcs = tc_cfg_graph.graph['func_instr_calls'][(func, potential_call_instr)]
            if called_funcs:
                full_called_functions |= called_funcs

        # go through all bbs in func that reach until_node add them and their called funcs if they have one
        for before_bb, _ in tc_cfg_graph.in_edges(bb):
            # add node to slice
            static_slice.add(before_bb)

            # and get bb nodes from calls there
            called_funcs = tc_cfg_graph.graph['bb_calls'][before_bb]
            if called_funcs:
                full_called_functions |= called_funcs

    # extend full_called_functions to include the functions they can reach
    for fcf in full_called_functions.copy():
        for (_, reachable_function) in tc_call_graph.out_edges(fcf):
            full_called_functions.add(reachable_function)

    # add all nodes from all called functions
    for fcf in full_called_functions:
        static_slice |= tc_cfg_graph.graph['func_nodes'][fcf]

    return static_slice


def get_static_slice(cache, tc_cfg_graph, tc_call_graph, bb, instr):
    assert bb in tc_cfg_graph
    if bb in cache:
        return cache[bb]
    else:
        slice = compute_static_slice(tc_cfg_graph, tc_call_graph, bb, instr)
        cache[bb] = slice
        return slice


def is_reachable(tc_cfg_graph, tc_call_graph, cur_supermutants, candidate, cache):
    candidate_node = tc_cfg_graph.graph['mut_to_node'][candidate]
    candidate_instr = tc_cfg_graph.graph['mut_to_instr'][candidate]
    candidate_slice = get_static_slice(cache, tc_cfg_graph, tc_call_graph, candidate_node, candidate_instr)
    for cs in cur_supermutants:
        supermutant_node = tc_cfg_graph.graph['mut_to_node'][cs]
        supermutant_instr = tc_cfg_graph.graph['mut_to_instr'][cs]
        
        supermutant_slice = get_static_slice(cache, tc_cfg_graph, tc_call_graph, supermutant_node, supermutant_instr)

        if candidate_node == supermutant_node or \
            candidate_node in supermutant_slice or \
                supermutant_node in candidate_slice:
            return True

    return False


def transitive_closure(cfg_graph):
    return nx.transitive_closure(cfg_graph, reflexive=None)


def get_supermutants(tc_cfg_graph, tc_call_graph, reachable_muts):
    # Go through all mutants and get those that can be combined into supermutants.
    muts_todo = reachable_muts.copy()
    muts_static_slice_cache = {}
    assert len(set(muts_todo) & set(tc_cfg_graph.graph['mut_failed'])) == 0
    supermutants = []
    while len(muts_todo) > 0:
        # Start with a mutation and go through all other mutations to see if they are not reachable.
        # If they are not reachable add them to the supermutant.
        cur_supermutant = [muts_todo.pop()]
        for candidate in muts_todo:
            if not is_reachable(tc_cfg_graph, tc_call_graph, cur_supermutant, candidate, muts_static_slice_cache):
                cur_supermutant.append(candidate)

        # Remove all mutations in the supermutant from the todo muts and cache, they are done.
        # print("supermutant:")
        for cs in cur_supermutant:
            # print(cs, tc_cfg_graph.graph['mut_to_node'][cs])
            try:
                muts_todo.remove(cs)
            except:
                pass
            try:
                muts_static_slice_cache.remove(cs)
            except:
                pass
        
        supermutants.append(cur_supermutant)
    
    # For those mutations where we could not get info include them as one mutation supermutants.
    for mm in tc_cfg_graph.graph['mut_failed']:
        supermutants.append([mm])

    return supermutants
