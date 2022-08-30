#%%
import json

with open("info_guetzli.json", "rt") as f:
    data = json.load(f)

#%%
from collections import defaultdict
print(data[0].keys())

res = defaultdict(lambda: {
    'cov': []
})

for elem in data:
    prog = elem['prog']
    fuzzer = elem['fuzzer']
    res[(prog, fuzzer)]['cov'].append(len(elem['covered_mutations']))

for kk, dd in res.items():
    print(kk, sorted(dd['cov']))