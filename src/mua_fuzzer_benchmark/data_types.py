from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union, cast

from constants import SHARED_DIR


@dataclass
class Fuzzer:
    name: str
    queue_dir: str
    queue_ignore_files: List[str]
    crash_dir: str
    crash_ignore_files: List[str]


@dataclass
class CompileArg:
    val: str
    action: Optional[str]


@dataclass
class Program:
    name: str
    bc_compile_args: List[CompileArg]
    bin_compile_args: List[CompileArg]
    is_cpp: bool
    dict_path: Path
    orig_bin: Path
    orig_bc: Path
    omit_functions: List[str]
    dir_name: str
    san_is_built: bool = field(default=False, init=False)


@dataclass
class InitialSuperMutant:
    exec_id: int
    prog: str
    super_mutant_id: int
    mutation_id: int


@dataclass
class MutationType:
    pattern_name: str
    type_id: int
    pattern_location: str
    pattern_class: str
    description: str
    procedure: str


@dataclass
class Mutation:
    mutation_id: int
    prog: Program
    type_id: str
    directory: str
    filePath: str
    line: int
    column: int
    instr: str
    funname: str
    additional_info: str


@dataclass
class MutationDataTodo:
    pass


@dataclass
class SuperMutantUninitialized:
    mutation_ids: List[int]
    prog: Program
    mutation_data: List[MutationDataTodo]


@dataclass
class SuperMutant:
    supermutant_id: int
    mutation_ids: set[int]
    mutation_data: List[MutationDataTodo]
    prog: Program
    compile_args: List[CompileArg]
    args: str
    seed_base_dir: Path
    previous_supermutant_ids: List[int] = field(default_factory=list)


    def printable_m_id(self) -> str:
        return f"S{self.supermutant_id}"


    def get_mut_base_dir(self) -> Path:
        return SHARED_DIR/"mut_base"/self.prog.name/self.printable_m_id()


    def get_mut_base_bin(self) -> Path:
        "Get the path to the bin that is the mutated base binary."
        return self.get_mut_base_dir()/"mut_base"


@dataclass(frozen=True, eq=True)
class RunResultKey:
    name: str
    mutation_ids: Tuple[int, ...]


@dataclass
class CrashingInput:
    time: float
    path: Path
    orig_returncode: Optional[int]
    mut_returncode: Optional[int]
    orig_cmd: List[str]
    mut_cmd: List[str]
    orig_res: Optional[object]
    mut_res: Optional[object]
    orig_timeout: Optional[bool]
    timeout: Optional[int]
    num_triggered: Optional[int]


# @dataclass
# class RunResultData:
#     result: str
#     mutation_ids: Set[int]
#     time: float
#     path: Optional[Path] = field(default=None)
#     # killed, ..
#     crash_input: Optional[CrashingInput] = field(default=None)
#     # timeout
#     args: Optional[List[str]] = field(default=None)


def gen_key(result_type: str, mutation_ids: Set[int]) -> RunResultKey:
    return RunResultKey(
        name=result_type,
        mutation_ids=tuple(sorted(mutation_ids))
    )


@dataclass
class CheckResultCovered:
    path: Path
    mutation_ids: Set[int]
    cur_time: float

    def generate_key(self) -> RunResultKey:
        return gen_key("covered", self.mutation_ids)

    def get_mutation_ids(self) -> Set[int]:
        return self.mutation_ids


@dataclass
class CheckResultOrigTimeout:
    path: Path
    orig_cmd: List[str]
    cur_time: float

    def generate_key(self) -> RunResultKey:
        return gen_key("orig_timeout", self.mutation_ids)

    def get_mutation_ids(self) -> Set[int]:
        return set()


@dataclass
class CheckResultOrigCrash:
    path: Path
    args: List[str]
    returncode: int
    orig_res: str
    cur_time: float

    def generate_key(self) -> RunResultKey:
        return gen_key("orig_crash", self.mutation_ids)

    def get_mutation_ids(self) -> Set[int]:
        return set()


@dataclass
class CheckResultTimeout:
    path: Path
    args: List[str]
    mutation_ids: Set[int]
    cur_time: float

    def generate_key(self) -> RunResultKey:
        return gen_key("timeout", self.mutation_ids)

    def get_mutation_ids(self) -> Set[int]:
        return self.mutation_ids


@dataclass
class CheckResultKilled:
    mutation_ids: Set[int]
    path: Path
    args: List[str]
    orig_cmd: List[str]
    mut_cmd: List[str]
    orig_returncode: int
    mut_returncode: int
    orig_res: str
    mut_res: str
    num_triggered: int
    cur_time: float

    def generate_key(self) -> RunResultKey:
        return gen_key("killed", self.mutation_ids)

    def get_mutation_ids(self) -> Set[int]:
        return self.mutation_ids


check_results_union = CheckResultCovered | CheckResultTimeout | \
                      CheckResultKilled | CheckResultOrigTimeout | CheckResultOrigCrash


@dataclass
class CrashCheckResult:
    result: str
    results: List[check_results_union] = field(default_factory=list)
    total_time: Optional[float] = field(default=None)
    returncode: Optional[int] = field(default=None)
    covered_file_seen: Optional[float] = field(default=None)
    timed_out: bool = field(default=False)
    all_logs: str = field(default_factory=str)
    out: str = field(default_factory=str)


@dataclass
class RunResult:
    result: str
    total_time: float
    all_logs: List[str]
    data: Dict[RunResultKey, check_results_union]
    unexpected_completion_time: Optional[Tuple[float, float]] = field(default=None)


@dataclass
class CoveredResult:
    supermutants: List[List[int]]
    covered_mutations: List[int]
    covered_supermutants: List[List[int]]
    not_covered: List[int]
    not_covered_supermutants: List[List[int]]


@dataclass
class FuzzerRun:
    mut_data: SuperMutant
    fuzzer: Fuzzer
    run_ctr: int
    timeout: int
    core: Optional[int] = field(default=None)
    workdir: Optional[Path] = field(default=None)
    prog_bc: Optional[Path] = field(default=None)

    def set_core(self, core: int) -> None:
        assert self.core is None
        self.core = core


@dataclass
class CheckRun:
    check_run_input_dir: Path
    timeout: int
    mut_data: SuperMutant
    run_ctr: int
    fuzzer: Fuzzer
    core: Optional[int] = field(default=None)
    workdir: Optional[Path] = field(default=None)
    prog_bc: Optional[Path] = field(default=None)

    def set_core(self, core: int) -> None:
        assert self.core is None
        self.core = core


@dataclass
class ResultingRun:
    run: FuzzerRun | CheckRun


@dataclass
class MutationRun:
    mut_data: SuperMutant
    resulting_runs: List[ResultingRun]
    check_run: bool
    core: Optional[int] = field(default=None)
    prog_bc: Optional[Path] = field(default=None)

    def set_core(self, core: int) -> None:
        assert self.core is None
        self.core = core


@dataclass
class SeedRunResult:
    all_logs: List[str]
    restart: Optional[bool] = field(default=None)
    file_error: Optional[Path] = field(default=None)


@dataclass
class SeedRun:
    workdir: Path
    seed_base_dir: Path
    orig_bc: Path
    compile_args: List[CompileArg]
    fuzzer: str
    timeout: int
    prog: Program
    core: Optional[int] = field(default=None)


@dataclass
class KCovResult:
    covered_lines: List[Tuple[str, str]]
    all_lines: List[Tuple[str, str]]


@dataclass
class GatherSeedRun:
    prog: str
    fuzzer: str
    instance: str
    seed_dir: Path
    num_seeds: int
    minimized_dir: Path
    num_seeds_minimized: Optional[int] = field(default=None)
    covered_mutations: Optional[Set[int]] = field(default=None)
    kcov_res: Optional[KCovResult] = field(default=None)


@dataclass
class GatheredSeedsRun:
    prog: str
    fuzzer: str
    instance: str
    seed_dir: Path
    num_seeds: int
    minimized_dir: Path
    num_seeds_minimized: int
    covered_mutations: Set[int]
    kcov_res: KCovResult


@dataclass
class KCovRun:
    workdir: Path
    orig_bin: Path
    seed_path: Path
    orig_bc: Path
    compile_args: str
    args: str
    prog: Program


@dataclass
class MinimizeSeedRun:
    fuzzer: str
    workdir: Path
    seed_in_dir: Path
    seed_out_dir: Path
    orig_bc: Path
    compile_args: str
    args: str
    prog: Program


@dataclass
class CommonRun:
    run_type: str
    data: FuzzerRun | MutationRun | CheckRun | SeedRun

    def get_fuzz_run(self) -> FuzzerRun:
        assert self.run_type == 'fuzz'
        assert isinstance(self.data, FuzzerRun)
        return self.data

    def get_mut_run(self) -> MutationRun:
        assert self.run_type == 'mut'
        assert isinstance(self.data, MutationRun)
        return self.data

    def get_check_run(self) -> CheckRun:
        assert self.run_type == 'check'
        assert isinstance(self.data, CheckRun)
        return self.data

    def get_seed_run(self) -> SeedRun:
        assert self.run_type == 'seed'
        assert isinstance(self.data, SeedRun)
        return self.data


@dataclass
class ActiveMutants:
    mutants: Dict[Path, Dict[str, Union[int, bool]]] = \
        field(default_factory=lambda: defaultdict(lambda: {'ref_cnt': 0, 'killed': False}))

    def increase_ref_cnt(self, path: Path, amount: int) -> None:
        self.mutants[path]['ref_cnt'] += amount

    def decrement_ref_cnt(self, path: Path) -> bool:
        self.mutants[path]['ref_cnt'] -= 1

        if self.mutants[path]['ref_cnt'] < 0:
            raise ValueError(f"ref_cnt for {path} is negative")

        return self.mutants[path]['ref_cnt'] == 0

    def set_killed(self, path: Path) -> None:
        self.mutants[path]['killed'] = True

    def is_killed(self, path: Path) -> bool:
        return cast(bool, self.mutants[path]['killed'])