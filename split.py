"""
Dirty script to get the most even split of programs based on number of mutations.
"""

progs = [
    #  ('aspell', 2756),
    #  ('cares_name', 94),
    #  ('cares_parse_reply', 791),
    #  ('guetzli', 1282),
    #  ('libjpeg', 908),
    #  ('re2', 300),
    #  ('vorbis', 3534),
    #  ('woff2_base', 6419),
    # ('woff2_new', 6418),

    ('aspell', 217775),
    ('cares_name', 26595),
    ('cares_parse_reply', 26595),
    ('guetzli', 89960),
    ('libjpeg', 174275),
    ('re2', 85940),
    ('vorbis', 80035),
    ('woff2_base', 206410),
    ('woff2_new', 206420),
]

import itertools

buckets = [52, 52, 52, 52, 52]
NUM_BUCKETS = len(buckets)

combinations = []

cur_best = []
for _ in range(NUM_BUCKETS):
    cur_best.append([])

for p in progs:
    cur_best[0].append(p)

def calc_val(comb):
    bucket_sums = [sum((p[1])/buckets[b_idx] for p in comb[b_idx]) for b_idx in range(NUM_BUCKETS)]

    diffs = list(abs(bucket_sums[0] - bucket_sums[ii])**2 for ii in range(1, NUM_BUCKETS))

    val = sum(diffs)
    return val

cur_best_val = calc_val(cur_best)

combinations = itertools.product(range(NUM_BUCKETS), repeat=len(progs))
for cur_comb_indices in combinations:
    cur_comb = []
    for _ in range(NUM_BUCKETS):
        cur_comb.append([])
    for idx, prog in zip(cur_comb_indices, progs):
        cur_comb[idx].append(prog)

    val = calc_val(cur_comb)
    if val < cur_best_val:
        print(val, [[p[0] for p in bucket] for bucket in cur_comb ])
        bucket_sums = [sum(p[1] for p in cur_comb[b_idx]) for b_idx in range(NUM_BUCKETS)]
        print(bucket_sums)
        bucket_sums = [sum((p[1])/buckets[b_idx] for p in cur_comb[b_idx]) for b_idx in range(NUM_BUCKETS)]
        print(bucket_sums)
        cur_best_val = val
        cur_best = cur_comb

