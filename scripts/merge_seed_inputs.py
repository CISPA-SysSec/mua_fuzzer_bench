# Merge median run seed inputs for each subject / fuzzer pair into one subject folder.

from pathlib import Path
from shutil import rmtree, copy2

SRC_DIR = Path('seeds/seeds_coverage/median_runs')
DEST_DIR = Path('seeds/seeds_merged')

def main():
    if DEST_DIR.is_dir():
        rmtree(DEST_DIR)

    progs = set()
    progs_fuzzer = set()
    for src in Path(SRC_DIR).glob('*/*/*'):
        progs.add(src.parent.parent.name)
        progs_fuzzer.add((src.parent.parent.name, src.parent.name))
        # print(src.parent)

    for src in Path(SRC_DIR).glob('*/*/*'):
        if src.is_file():
            src_prog = src.parent.parent.name

            for (dst_prog, dst_fuzzer) in progs_fuzzer:
                if dst_prog == src_prog:
                    dest = (DEST_DIR / dst_prog / dst_fuzzer / f'{src.parent.name}-{src.name}')
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    copy2(src, dest)

if __name__ == '__main__':
    main()