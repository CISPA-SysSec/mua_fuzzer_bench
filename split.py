"""
Dirty script to get the most even split of programs based on number of mutations.
"""

progs = [
    ("aspell", 43555, 12809, 774),
    ("cares_name", 5319, 5319, 94),
    ("cares_parse_reply", 5319, 5319, 1100),
    ("guetzli", 17992, 12495, 7370),
    ("libjpeg", 34855, 20933, 3253),
    ("re2", 17188, 14641, 4327),
    ("vorbis", 16007, 12583, 3481),
    ("woff2_base", 41282, 24006, 3941),
    ("woff2_new", 41284, 24008, 3874),
]

import itertools

NUM_BUCKETS = 3

combinations = []

cur_best = []
for _ in range(NUM_BUCKETS):
    cur_best.append([])

for p in progs:
    cur_best[0].append(p)

def calc_val(comb):
    bucket_sums = [sum(p[3] for p in comb[b_idx]) for b_idx in range(NUM_BUCKETS)]

    diffs = list(abs(bucket_sums[0] - bucket_sums[ii]) for ii in range(1, NUM_BUCKETS))

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
        bucket_sums = [sum(p[3] for p in cur_comb[b_idx]) for b_idx in range(NUM_BUCKETS)]
        print(bucket_sums)
        cur_best_val = val
        cur_best = cur_comb

