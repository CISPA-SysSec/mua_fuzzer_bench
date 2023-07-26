import os
from pathlib import Path
import uuid

import psutil


EXEC_ID = str(uuid.uuid4())

# set the number of concurrent runs
NUM_CPUS = int(os.getenv("MUT_NUM_CPUS", psutil.cpu_count(logical=True)))  # type: ignore[misc]

# If the detector binary should be build with ASAN
WITH_ASAN = os.getenv("MUT_BUILD_ASAN", "0") == "1"

# If the detector binary should be build with MSAN
WITH_MSAN = os.getenv("MUT_BUILD_MSAN", "0") == "1"

# If container logs should be shown
SHOW_CONTAINER_LOGS = os.getenv("MUT_LOGS", "0") == "1"

# Remove the working directory after a run
RM_WORKDIR = os.getenv("MUT_RM_WORKDIR", "1") == "1"

# If true filter out those mutations that are not covered by seed files, using the detector version.
FILTER_MUTATIONS = os.getenv("MUT_FILTER_MUTS", "0") == "1"

# If true only run the seed inputs and dont do any fuzzing.
JUST_SEEDS = os.getenv("MUT_JUST_SEEDS", "0") == "1"

# If true stop fuzzing when multiple mutations are covered, otherwise only when a crash is found.
STOP_ON_MULTI = os.getenv("MUT_STOP_ON_MULTI", "0") == "1"

SKIP_LOCATOR_SEED_CHECK = os.getenv("MUT_SKIP_LOCATOR_SEED_CHECK", "0") == "1"

# The maximum number of mutants to include in one supermutant
MAX_SUPERMUTANT_SIZE = int(os.getenv("MUT_MAX_SUPERMUTANT_SIZE", "100"))

# Flag if the fuzzed seeds should be used
USE_GATHERED_SEEDS = False

# Time interval in seconds in which to check the results of a fuzzer
CHECK_INTERVAL = 5

# The path where eval data is stored outside of the docker container
HOST_TMP_PATH = Path(".").resolve()/"tmp/"

# Directy where unsolved mutants are collected
UNSOLVED_MUTANTS_DIR = HOST_TMP_PATH/"unsolved_mutants"

# The location where the eval data is mapped to inside the docker container
IN_DOCKER_WORKDIR = "/workdir/"

TRIGGERED_STR = "Triggered!\r\n"

MAX_RUN_EXEC_IN_CONTAINER_TIME = 60*15

SHARED_DIR = Path(os.getenv("MUT_SHARED_DIR", "/dev/shm/mua_fuzzer_benchmark/")).absolute()
TMP_PROG_DIR = HOST_TMP_PATH/"programs"

IN_DOCKER_SHARED_DIR = Path("/shared/")

# How often a fuzzing run should be retried, this value is only increased if the
# reported crash is not confirmed during a check run.
MAX_RETRY_COUNT = 3

MUTATOR_LLVM_DOCKERFILE_PATH = "dockerfiles/mutator/Dockerfile.llvm"
MUTATOR_MUTATOR_DOCKERFILE_PATH = "dockerfiles/mutator/Dockerfile.mutator"
MUTATOR_LLVM_IMAGE_NAME = "mutator_deps:2004"
MUTATOR_MUATATOR_IMAGE_NAME = "mutator_mutator:latest"

BLOCK_SIZE = 1024*4

PRIO_MUTANT = 5
PRIO_FUZZ_RUN = 4
PRIO_RECOMPILE_MUTANT = 3
PRIO_CHECK_MUTANT = 2
PRIO_CHECK_RUN = 1
