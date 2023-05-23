import hashlib
from inspect import getframeinfo, stack
import logging
from pathlib import Path
import shutil
import time

from constants import BLOCK_SIZE, IN_DOCKER_SHARED_DIR, SHARED_DIR

logger = logging.getLogger(__name__)

def dbg(*args, **kwargs):
    caller = getframeinfo(stack()[1][0])
    logger.debug(f"{caller.filename}:{caller.lineno}: {args} {kwargs}")
    return args


def fuzzer_container_tag(name):
    return f"mutation-testing-fuzzer-{name}"


def subject_container_tag(name):
    return f"mutation-testing-subject-{name}"


def mutation_locations_path(prog_info):
    orig_bc = Path(prog_info['orig_bc'])
    return orig_bc.with_suffix('.ll.mutationlocations')


def mutation_locations_graph_path(prog_info):
    orig_bc = Path(prog_info['orig_bc'])
    return orig_bc.with_suffix('.ll.mutationlocations.graph')


def mutation_detector_path(prog_info):
    orig_bc = Path(prog_info['orig_bc'])
    return  orig_bc.with_suffix(".ll.opt_mutate")


def mutation_prog_source_path(prog_info):
    orig_bc = Path(prog_info['orig_bc'])
    return orig_bc.with_suffix('.ll.ll')


def printable_m_id(mut_data):
    return f"S{mut_data['supermutant_id']}"


def get_mut_base_dir(data: dict) -> Path:
    return SHARED_DIR/"mut_base"/data['prog']/printable_m_id(data)


def get_mut_base_bin(mut_data: dict) -> Path:
    "Get the path to the bin that is the mutated base binary."
    return get_mut_base_dir(mut_data)/"mut_base"


def hash_file(file_path):
    h = hashlib.sha512()
    b  = bytearray(BLOCK_SIZE)
    mv = memoryview(b)
    with open(file_path, 'rb', buffering=0) as f:
        for n in iter(lambda : f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()


def shared_dir_to_docker(dir: Path) -> Path:
    rel_path = dir.relative_to(SHARED_DIR)
    res = IN_DOCKER_SHARED_DIR/rel_path
    return res


def get_seed_dir(seed_base_dir, prog, fuzzer):
    """
    Gets the seed dir inside of seed_base_dir based on the program name.
    Further if there is a directory inside with the name of the fuzzer, that dir is used as the seed dir.
    Example:
    As a sanity check if seed_base_dir/<prog> contains files and directories then an error is thrown.
    seed_base_dir/<prog>/<fuzzer> exists then this dir is taken as the seed dir.
    seed_base_dir/<prog> contains only files, then this dir is the seed dir.
    """
    prog_seed_dir = seed_base_dir/prog
    seed_paths = list(prog_seed_dir.glob("*"))
    has_files = any(sp.is_file() for sp in seed_paths)
    has_dirs = any(sp.is_dir() for sp in seed_paths)
    if has_files and has_dirs:
        raise ValueError(f"There are files and directories in {prog_seed_dir}, either the dir only contains files, "
              f"in which case all files are used as seeds for every fuzzer, or it contains only directories. "
              f"In the second case the content of each fuzzer directory is used as the seeds for the respective fuzzer.")

    if has_dirs:
        # If the fuzzer specific seed dir exists, return it.
        prog_fuzzer_seed_dir = prog_seed_dir/fuzzer
        if not prog_fuzzer_seed_dir.is_dir():
            logger.warning(f"WARN: Expected seed dir to exist {prog_fuzzer_seed_dir}, using full dir instead: {prog_seed_dir}")
            return prog_seed_dir
        return prog_fuzzer_seed_dir

    elif has_files:
        # Else just return the prog seed dir.
        return prog_seed_dir

    # Has no content
    else:
        raise ValueError(f"Seed dir has not content. {prog_seed_dir}")


class CoveredFile:
    def __init__(self, workdir, start_time) -> None:
        super().__init__()
        self.found: dict = {}
        self.host_path = SHARED_DIR/"covered"/workdir
        self.host_path.mkdir(parents=True)
        self.docker_path = IN_DOCKER_SHARED_DIR/"covered"/workdir
        self.start_time = start_time

    def check(self):
        cur_time = time.time() - self.start_time
        cur = set(int(cf.stem) for cf in self.host_path.glob("*"))
        new = cur - self.found.keys()
        new = {nn: cur_time for nn in new}
        self.found = {**self.found, **new}
        return new

    def file_path(self):
        return self.path

    def __del__(self):
        shutil.rmtree(self.host_path)