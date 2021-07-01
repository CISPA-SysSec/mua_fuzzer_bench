from pathlib import Path
import shutil
import hashlib


BLOCK_SIZE = 1024*4


# Based on: https://stackoverflow.com/a/44873382
def hash_file(file_path):
    h = hashlib.sha512()
    b  = bytearray(BLOCK_SIZE)
    mv = memoryview(b)
    with open(file_path, 'rb', buffering=0) as f:
        for n in iter(lambda : f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()


def collect_honggfuzz(path):
    found = path.glob("output/*")
    return list(found)


def collect_afl(path):
    found = [pp for pp in path.glob("**/queue/*") if pp.name != '.state']
    return list(found)


SEED_HANDLERS = {
        'honggfuzz': collect_honggfuzz,
        'fairfuzz': collect_afl,
        'aflpp_rec': collect_afl,
        'aflpp_det': collect_afl,
        'afl': collect_afl,
}

source = Path("/home/pgoerz/cur_queue_bak")
dest = Path("/home/pgoerz/llvm-mutation-tool/tmp/fuzzed_seeds")

print(source)
print(dest)

for seed_source in source.glob("*"):
    if not seed_source.is_dir():
        continue

    seed_base_dir_parts = str(seed_source.name).split('__')
    prog = seed_base_dir_parts[0]
    fuzzer = seed_base_dir_parts[1]
    prog_dir = dest/prog
    prog_dir.mkdir(parents=True, exist_ok=True)

    collector = SEED_HANDLERS[fuzzer]

    found_seeds = collector(seed_source)
    print(prog, fuzzer, len(found_seeds))
    for fs in found_seeds:
        file_hash = hash_file(fs)
        dest_path = prog_dir/file_hash
        shutil.copyfile(fs, dest_path)


