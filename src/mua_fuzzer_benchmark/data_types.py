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
    mutation_ids: List[int]


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


@dataclass
class RunResultData:
    result: str
    mutation_ids: Set[int]
    time: float
    path: Optional[Path] = field(default=None)
    # killed, ..
    crash_input: Optional[CrashingInput] = field(default=None)
    # timeout
    args: Optional[List[str]] = field(default=None)

    def generate_key(self) -> RunResultKey:
        if self.result in ['orig_crash', 'orig_timeout', 'orig_timeout_by_seed']:
            key = RunResultKey(name=self.result, mutation_ids=list())
        else:
            try:
                m_ids = sorted(self.mutation_ids)
            except KeyError as e:
                raise ValueError(f"{e} {self}")
            key = RunResultKey(name=self.result, mutation_ids=m_ids)

        return key


@dataclass
class CrashCheckResult:
    result: str
    results: List[RunResultData] = field(default_factory=list)
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
    data: Dict[RunResultKey, RunResultData]
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