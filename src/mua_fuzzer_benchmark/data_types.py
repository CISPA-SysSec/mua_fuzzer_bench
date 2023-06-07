from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union, cast

from constants import SHARED_DIR


@dataclass
class RerunMutations:
    prog: str
    mutation_ids: List[int]
    mode: str

    def to_dict(self) -> Dict[str, Union[str, List[int]]]:
        return {
            "prog": self.prog,
            "mutation_ids": self.mutation_ids,
            "mode": self.mode
        }


@dataclass
class DoneMutation:
    untried: bool
    covered: bool
    crashed: bool
    timeout: bool
    killed: bool
    mut_id: int


@dataclass(eq=True, order=True)
class Fuzzer:
    name: str
    queue_dir: str
    queue_ignore_files: List[str]
    crash_dir: str
    crash_ignore_files: List[str]


@dataclass(eq=True, order=True)
class CompileArg:
    val: str
    action: Optional[str]


@dataclass(eq=True, order=True)
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
    exec_id: str
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
class SuperMutantUninitialized:
    mutation_ids: List[int]
    prog: Program


@dataclass(eq=True, order=True)
class SuperMutant:
    supermutant_id: int
    mutation_ids: set[int]
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


@dataclass(frozen=True, eq=True)
class CheckResultCovered:
    path: Optional[Path]
    mutation_ids: Set[int]
    time: float
    by_seed: bool

    def id(self) -> str:
        if self.by_seed:
            return f"covered_by_seed"
        else:
            return f"covered"

    def generate_key(self) -> RunResultKey:
        return gen_key(self)

    def get_mutation_ids(self) -> Set[int]:
        return self.mutation_ids


@dataclass(frozen=True, eq=True)
class CheckResultOrigTimeout:
    path: Path
    orig_cmd: List[str]
    time: float
    by_seed: bool

    def id(self) -> str:
        if self.by_seed:
            return f"orig_timeout_by_seed"
        else:
            return f"orig_timeout"

    def generate_key(self) -> RunResultKey:
        return gen_key(self)

    def get_mutation_ids(self) -> Set[int]:
        return set()


@dataclass(frozen=True, eq=True)
class CheckResultOrigCrash:
    path: Path
    args: List[str]
    returncode: int
    orig_res: str
    time: float
    by_seed: bool

    def id(self) -> str:
        if self.by_seed:
            return f"orig_crash_by_seed"
        else:
            return f"orig_crash"

    def generate_key(self) -> RunResultKey:
        return gen_key(self)

    def get_mutation_ids(self) -> Set[int]:
        return set()


@dataclass(frozen=True, eq=True)
class CheckResultTimeout:
    path: Path
    args: List[str]
    mutation_ids: Set[int]
    time: float
    by_seed: bool

    def id(self) -> str:
        if self.by_seed:
            return f"timeout_by_seed"
        else:
            return f"timeout"

    def generate_key(self) -> RunResultKey:
        return gen_key(self)

    def get_mutation_ids(self) -> Set[int]:
        return self.mutation_ids


@dataclass(frozen=True, eq=True)
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
    time: float
    by_seed: bool = field(default=False)

    def id(self) -> str:
        if self.by_seed:
            return f"killed_by_seed"
        else:
            return f"killed"

    def generate_key(self) -> RunResultKey:
        return gen_key(self)

    def get_mutation_ids(self) -> Set[int]:
        return self.mutation_ids


check_results_union = CheckResultCovered | CheckResultTimeout | \
                      CheckResultKilled | CheckResultOrigTimeout | CheckResultOrigCrash


def gen_key(elem: check_results_union) -> RunResultKey:
    return RunResultKey(
        name=elem.id(),
        mutation_ids=tuple(sorted(elem.get_mutation_ids()))
    )


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


@dataclass(eq=True, order=True)
class FuzzerRun:
    mut_data: SuperMutant
    fuzzer: Fuzzer
    run_ctr: int
    timeout: int
    retry: int
    _core: Optional[int] = field(default=None)
    _workdir: Optional[Path] = field(default=None)
    _prog_bc: Optional[Path] = field(default=None)

    def get_core(self) -> int:
        assert self._core is not None, self
        return self._core

    def set_core(self, core: int) -> None:
        assert self._core is None, self
        self._core = core

    def unset_core(self) -> None:
        assert self._core is not None, self
        self._core = None

    def get_workdir(self) -> Path:
        assert self._workdir is not None, self
        return self._workdir

    def set_workdir(self, workdir: Path) -> None:
        assert self._workdir is None, self
        self._workdir = workdir

    def unset_workdir(self) -> None:
        assert self._workdir is not None, self
        self._workdir = None

    def get_prog_bc(self) -> Path:
        assert self._prog_bc is not None, self
        return self._prog_bc

    def set_prog_bc(self, prog_bc: Path) -> None:
        assert self._prog_bc is None, self
        self._prog_bc = prog_bc

    def unset_prog_bc(self) -> None:
        assert self._prog_bc is not None, self
        self._prog_bc = None


@dataclass(eq=True, order=True)
class CheckRun:
    check_run_input_dir: Path
    timeout: int
    mut_data: SuperMutant
    run_ctr: int
    fuzzer: Fuzzer
    by_seed: bool
    time_took: float
    covered_time: float
    seed_covered_time: Optional[float]
    retry: int
    _core: Optional[int] = field(default=None)
    _workdir: Optional[Path] = field(default=None)
    _prog_bc: Optional[Path] = field(default=None)

    def get_core(self) -> int:
        assert self._core is not None, self
        return self._core

    def set_core(self, core: int) -> None:
        assert self._core is None, self
        self._core = core

    def unset_core(self) -> None:
        assert self._core is not None, self
        self._core = None

    def get_workdir(self) -> Path:
        assert self._workdir is not None, self
        return self._workdir

    def set_workdir(self, workdir: Path) -> None:
        assert self._workdir is None, self
        self._workdir = workdir

    def unset_workdir(self) -> None:
        assert self._workdir is not None, self
        self._workdir = None

    def get_prog_bc(self) -> Path:
        assert self._prog_bc is not None, self
        return self._prog_bc

    def set_prog_bc(self, prog_bc: Path) -> None:
        assert self._prog_bc is None, self
        self._prog_bc = prog_bc

    def unset_prog_bc(self) -> None:
        assert self._prog_bc is not None, self
        self._prog_bc = None


@dataclass(eq=True, order=True)
class ResultingRun:
    run: FuzzerRun | CheckRun


@dataclass(eq=True, order=True)
class MutationRun:
    mut_data: SuperMutant
    resulting_runs: List[ResultingRun]
    check_run: bool
    _core: Optional[int] = field(default=None)
    _prog_bc: Optional[Path] = field(default=None)

    def get_core(self) -> int:
        assert self._core is not None, self
        return self._core

    def set_core(self, core: int) -> None:
        assert self._core is None, self
        self._core = core

    def unset_core(self) -> None:
        assert self._core is not None, self
        self._core = None

    def get_prog_bc(self) -> Path:
        assert self._prog_bc is not None, self
        return self._prog_bc

    def set_prog_bc(self, prog_bc: Path) -> None:
        assert self._prog_bc is None, self
        self._prog_bc = prog_bc

    def unset_prog_bc(self) -> None:
        assert self._prog_bc is not None, self
        self._prog_bc = None


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

    def to_dict(self) -> Dict[str, List[Tuple[str, str]]]:
        return {
            "covered_lines": self.covered_lines,
            "all_lines": self.all_lines,
        }


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

    def to_dict(self) -> Dict[str, None | str | int | List[int] | Dict[str, List[Tuple[str, str]]]]:
        return {
            "prog": self.prog,
            "fuzzer": self.fuzzer,
            "instance": self.instance,
            "seed_dir": str(self.seed_dir),
            "num_seeds": self.num_seeds,
            "minimized_dir": str(self.minimized_dir),
            "num_seeds_minimized": self.num_seeds_minimized,
            "covered_mutations": list(self.covered_mutations),
            "kcov_res": self.kcov_res.to_dict(),
        }


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


@dataclass(eq=True, order=True)
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