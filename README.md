# mua-fuzzer-benchmark

This project contains the source code used for the evaluation of the
"Systematic Assessment of Fuzzers using Mutation Testing" paper. Note that
this framework only supports Linux systems at the moment.

The goal of this project is to provide a framework to compare fuzzers using
mutation analysis. Fuzzers are tools that implement fuzzing / fuzz testing to
find bugs in software. Fuzzing can be likened to generating lots of random
inputs to run on the program under test.

Mutation testing is an approach to judge how well testing methods perform
in finding bugs. The basic idea is to add (small) modifications to a program
and check if a modification is detected by the testing method. The modifications
that are not killed can be used to judge the performance of the testing method.

Both fuzzing and mutation testing are known for their high computation
requirements, this framework implements two methods to reduce this requirement.
One method is to reduce the number of mutations that need to be evaluated, this
is done by combining mutations that do not interfere with each other into one
"supermutant". This allows evaluation of all mutations contained in a
supermutant in one fuzzing run (Stage 1). The other method is to reduce the time
needed that fuzzers require to get results. This is done by splitting fuzzing
into two parts, one longer session on the unmutated executable, to give the
fuzzer as much of a head start as it can get. This allows shorter sessions for
each supermutant that needs to be evaluated (Stage 2).

# Installation

To run this framework two dependencies are required.

First, the required Python packages are managed using
[hatch](https://hatch.pypa.io/latest/install/).
The configuration can be found in [pyproject.toml](pyproject.toml).

The other requirement is [docker](https://docs.docker.com/engine/install/)
and that the user is a member of the `docker` group.

# Usage

The entry point for all commands is `src/mua_fuzzer_benchmark/eval.py` and the
working directory is expected to be the project root directory. All commands
and arguments to them are documented, for help use:
`src/mua_fuzzer_benchmark/eval.py -h`

After [preparing the environment](#preparing-the-environment) the usual steps
for an evaluation are first to do [coverage fuzzing](#coverage-fuzzing) (Stage 1)
and then [evaluating on supermutants](#supermutant-evaluation) (Stage 2).

## Preparing the Environment

Fuzzing requires some specific configurations, the recommended configuration
can be found in the `set_proc_sys_parameters.sh` file. Please check the
file to see if those changes are acceptable and modify if not.

Additionally, the framework requires a few python packages. The python
environment is managed through [hatch](https://hatch.pypa.io/latest/).
All that needs to be installed is hatch, then `hatch shell` will set up the
packages.

```bash
source ./set_proc_sys_parameters.sh  # source the script to allow ulimit to work
hatch shell  # enter the python environment
```

Once these two lines have been executed, the following commands can be run in
this shell session.


## Coverage Fuzzing (Stage 1)

The first step for the comparison is to create a seed corpus covering as much
of the program under test as the fuzzer can achieve. Once this seed corpus
has been established, it is reasonable to require shorter runs to evaluate
on the mutants.

To start a coverage fuzzing run the `coverage_fuzzing` command can be used.
See below for an example. See `src/mua_fuzzer_benchmark/eval.py coverage_fuzzing -h`
for help. For a description on environment variables see the file:
`src/mua_fuzzer_benchmark/constants.py`.

Note that an initial set of seeds are required, they are expected to be placed
the in a folder identical to the prog variant name, so for the following
command the seed files would be placed under:
`tmp/seeds/seeds_minimal/woff2_new`.

Also, note that the `fuzz-time` is in minutes. Of the instances, the median run
based on covered mutations will be moved into a separate directory.

```bash
src/mua_fuzzer_benchmark/eval.py coverage_fuzzing \
    --fuzzers libfuzzer aflpp honggfuzz \
    --progs woff2_new \
    --fuzz-time $((60 * 48)) \
    --seed-dir tmp/seeds/minimal \
    --result-dir tmp/coverage \
    --instances 13
```

## Supermutant Evaluation (Stage 2)

The second step for the comparison is evaluating how many mutants are killed
by a fuzzer. This can be done using the `eval` command,
see `src/mua_fuzzer_benchmark/eval.py coverage_fuzzing -h` for help.

In the remaining part of this section, the commands for the main experiments of
the paper are repeated to show some example usages.

### Basic Evaluation

As said, the `eval` command provides the entry point to evaluate mutations.
See below for an example. Note that the `seed-dir` now points to the median
run created by the `coverage_fuzzing` command.

```bash
src/mua_fuzzer_benchmark/eval.py eval \
    --fuzzers libfuzzer aflpp honggfuzz \
    --progs woff2_new \
    --fuzz-time $((60 * 1)) \
    --seed-dir tmp/coverage/median_runs/ \
    --result-path data/basic/stats_all.db
```

After the evaluation, the result database will be copied to `result-path`.

### ASan

Based on the results of the initial evaluation, the bitcode files and
supermutants can be reused by using the rerun arguments to `eval`.
If only a subset of mutations should be retried, this requires a file specifying
mutations, which can be created using the `generate_rerun_file` command.
See below for an example:

```bash
src/mua_fuzzer_benchmark/eval.py generate_rerun_file \
    --db data/basic/stats_all.db \
    --out-file rerun_file_for_asan.json \
    --untried no \
    --covered yes \
    --skip-timeout yes \
    --skip-killed no \
    --skip-crashed yes \
    --mode keep
```

The following command shows how to start a rerun eval, this time building the
program with ASan. (To be clear: `MUT_BUILD_ASAN` can also be used without
`--rerun`. Also, `--rerun` ensures that the same supermutants that have been
generated for the `--rerun <db>` will be started again.)

```bash
MUT_BUILD_ASAN=1 src/mua_fuzzer_benchmark/eval.py eval \
    --fuzzers libfuzzer aflpp honggfuzz \
    --progs woff2_new \
    --fuzz-time $((60 * 1)) \
    --seed-dir tmp/coverage/median_runs/ \
    --rerun data/basic/stats_all.db \
    --rerun-mutations rerun_file_for_asan.json \
    --result-path data/asan/stats_all.db
```

### 24 Hours (with ASan)

Just to complete the experiments of the paper, this example shows how to run
the mutations still not killed after the ASan experiment again (for 24 hours).

```bash
src/mua_fuzzer_benchmark/eval.py generate_rerun_file \
    --db data/asan/stats_all.db \
    --out-file rerun_file_24_hours.json \
    --untried no \
    --covered yes \
    --skip-timeout yes \
    --skip-killed yes \
    --skip-crashed yes \
    --mode single
```

```bash
MUT_BUILD_ASAN=1 src/mua_fuzzer_benchmark/eval.py eval \
    --fuzzers libfuzzer aflpp honggfuzz \
    --progs woff2_new \
    --fuzz-time $((60 * 24)) \
    --seed-dir tmp/coverage/median_runs/ \
    --rerun data/asan/stats_all.db \
    --rerun-mutations rerun_file_24_hours.json \
    --result-path data/24_hours/stats_all.db
```

## Getting the Results

The plots as shown in the paper can be reproduced using the Makefile.
This requires that the databases are prepared for plotting first using:
`src/mua_fuzzer_benchmark/eval.py prepare_db --db <db>`

This needs to be done for all three databases previously created:

```bash
src/mua_fuzzer_benchmark/eval.py prepare_db --db data/basic/stats_all.db
src/mua_fuzzer_benchmark/eval.py prepare_db --db data/asan/stats_all.db
src/mua_fuzzer_benchmark/eval.py prepare_db --db data/24_hours/stats_all.db
```

Note that the Makefile expects all the databases at exactly those locations and
the seeds to be under `tmp/coverage` just as the previous commands set up.
Finally, to generate the plots just run `make` from the project root.

This part of the usage will likely be changed after artifact evaluation.

# Extending the Tool

There are three expected ways to extend the current state of the framework.
Adding new fuzzers, adding new programs, and adding or changing mutations.

## Adding New Fuzzers

All fuzzers are located in the directory `dockerfiles/fuzzers/`, each fuzzer
is located in a separate directory, and the directory name is used to identify
the fuzzer. It is recommended to look at existing fuzzer configurations and
follow their setup when adding a new fuzzer.
Note that `dockerfiles/fuzzers/system/` is used as the base image.
Four files need to be provided to use a fuzzer (under `dockerfiles/fuzzers/<fuzzer name>/`):

- **Dockerfile**: The docker build command is run from the project root dir.
    This Dockerfile is used to compile the fuzzer and copy the following two
    files into the created image. The image will be used to create the
    containers used for fuzzing.
- **eval.sh**: Run inside the docker container for coverage fuzzing and
    evaluating on mutants. This script builds the instrumented binary and
    executes the fuzzing run. Arguments are path to the bitcode file in the
    docker container, compile arguments, and path to the seed corpus directory.
    Additionally, environment variables are passed: `DICT_PATH` contains the
    path to the dictionary for the program if available. Also `MUT_WITH_ASAN`
    or `MUT_WITH_MSAN` have the value `"1"` if ASan or MSan should be used.
- **minimize.sh**: Similar to `eval.sh` this script is run inside the docker
    container to use the fuzzers minimization algorithm. Arguments are: the path
    to the bitcode file, compile arguments, path to the directory containing the
    inputs that should be minimized, and the path to the output directory.
- **config.json**: Additional information about the fuzzer used to decide which
    queue inputs and crash inputs the fuzzer generates and should be used during evaluation.

## Adding New Programs

All programs are located in the directory `dockerfiles/programs/`, each program
is located in a separate directory, and the directory name is part of the
identifier for a program variant. A program variant is one configuration for
a program, see the description of the **config.json** file for details.
Two files are required to add a program (additional files are allowed, see
**Dockerfile** for details):

- **Dockerfile**: In the Dockerfile the program is built for all variants.
    Note that other than for the fuzzers, the `docker build` command is run in
    the program folder. The contents of the `/home/mutator/sample/` dir inside
    the docker image are copied to `tmp/programs/<program name>` and shared
    with the containers using docker's volume flag. Two files are required
    to be generated during the build process, a bitcode file of the program
    without a main function (or with a weakly linked main function, though
    this is untested). The other file is the bitcode file compiled to an
    executable binary included a main function, this file is used as the
    unmutated original binary (this file could also be generated by the
    framework using the bitcode file and a common main function, though
    this is not implemented yet).
- **config.json**: This file contains the configurations for the different
    variants of a program. It contains a dictionary with the variant name
    mapping to a dictionary of configuration parameters. The program variant
    name is created as follows: `<folder name> + "_" + <variant name>`.
    Following configuration parameters are expected:
        - `bc_compile_args`: Compiler arguments that should be used for
            compilation for all artifacts.
            Each argument is a dictionary containing: `val`: the string of the
            argument and `action`: none or "prefix_workdir" if the path to the
            workdir should be added as a prefix to the `val`.
        - `bin_compile_args`: Compiler arguments that should be used for
            compilation of the binary. Each argument follows the same rules
            as for `bc_compile_args`.
        - `is_cpp`: If the compilation should be done with a C++ compiler
            (clang++).
        - `dict`: Path to a dictionary file that is passed to the fuzzers, none
            if no dictionary should be provided. The path is relative to the
            `/home/mutator/sample/` dir.
        - `orig_bin`: Path to the original unmutated binary. The path is
            relative to the `/home/mutator/sample/` dir.
        - `orig_bc`: Path to the bitcode file. The path is
            relative to the `/home/mutator/sample/` dir.
        - `omit_functions`: Names of functions that should be excluded from
            being mutated, usually ["LLVMFuzzerTestOneInput"].

## Adding or Modifying Mutations

The file [mutation_doc.json](mutation_doc.json) contains documentation about
the different mutation types implemented in this project as a machine-readable
JSON file.

## Install

Changing mutations requires additional setup shown below.

### Docker Install

```shell script
# use the python script mutator-docker-wrapper.py

# first build the docker containers
python3 mutator-docker-wrapper.py -b

# then connect to the container
python3 mutator-docker-wrapper.py -a

# [optional] consult the script's help output for rebuilding and similar
# (will be faster than the initial build)
python3 mutator-docker-wrapper.py -h
```


### Local Install (only recommended for local development!)

```shell script
# run from root directory

# llvm installation on Mac:
brew install llvm@11

# llvm installation on linux:
echo deb http://apt.llvm.org/focal/ llvm-toolchain-focal-11 main >> /etc/apt/sources.list && \
    wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -

apt-get update && apt-get upgrade -y

apt-get install -y gcc-10 g++-10 gcc-10-plugin-dev gcc-10-multilib \
    libc++-10-dev gdb lcov

apt-get install -y clang-11 clang-tools-11 libc++1-11 libc++-11-dev \
    libc++abi1-11 libc++abi-11-dev libclang1-11 libclang-11-dev \
    libclang-common-11-dev libclang-cpp11 libclang-cpp11-dev liblld-11 \
    liblld-11-dev liblldb-11 liblldb-11-dev libllvm11 libomp-11-dev \
    libomp5-11 lld-11 lldb-11 llvm-11 llvm-11-dev llvm-11-runtime llvm-11-tools

update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-10 0
update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-10 0

rm -rf /var/cache/apt/archives/*

ln /bin/clang-11 /bin/clang
ln /bin/clang++-11 /bin/clang++
ln /bin/opt-11 /bin/opt
ln /bin/llvm-config-11 /bin/llvm-config
ln /bin/llvm-ar-11 /bin/llvm-ar



# compiles the project and installs it under build/install
export LD_LIBRARY_PATH=${mutation_tool_home}/build/install/LLVM_Mutation_Tool/lib/
gradle build
```


## Invoke Generation of Mutation Files

General invoke:

```shell script
# invokes the mutation pipeline, check for details on how to invoke the project in detail
./run_mutation.py [-bc] [-ll] [-bn] [-cpp] [-m <int>] [-ml <int>*] <path-to-subject.c> (e.g. ./samples/simple_malloc/malloc.c) 
```

Explanation of optional arguments (at least one must be chosen, otherwise the output would be empty):

```text
-bc: Keeps the mutated bitcode files.
-ll: Keeps the mutated bitcode files in human readable form.
-bn: Generates runnable binaries if possible.
-m <int>: Defines the mutation ID that should be applied, -1 for all mutations, 
    -2 or left out for just generation the mutationlocations file and a binary that prints
    covered mutations to the defined folder.
-m <int>: Defines a list of mutation IDs that should be applied at once, 
    left out for just generation the mutationlocations file and a binary that prints
    covered mutations to the defined folder.
-cpp: Uses clang++ for compilation instead of clang.
```

**If a new mutant is generated all already generated mutants are deleted!**

## Running Mutated Programs

The mutated programs have code injected which prints if the mutation was triggered.
It is possible to influence the output by defining environment variables:

```shell
export TRIGGERED_OUTPUT="Some output." # can contain any string which will be printed to the command line 
    and written to the file TRIGGERED_FILE if it is defined and could be created; a default value is printed if
    this environment variable is not defined

export TRIGGERED_FOLDER="some/file/to/report/mutation/trigger_signal" # a path to a folder which will for each mutation UID
contain a file which indicates that the mutation was triggered. If not defined the files will be written to ./triggered_signal
```

Also, if one wants to test which mutations could be covered, a binary is generated when producing the mutants 
which will print all covered mutation locations:
Invoke the binary ```*.opt_mutate``` (e.g. [samples/simple_malloc/malloc.c.opt_mutate](samples/simple_malloc/malloc.c.opt_mutate)) in the respective subject folder, it will print all found locations during
the run as explained above.

## Clean

```shell script
# run in root directory to delete all build products
# can also be used if the build does not correctly update or another strange behavior is observed

gradle clean
```

```shell script
# run in root directory to delete all generated mutation files in samples

sh clean_mutations_in_samples.sh
```

# License

`mua-fuzzer-benchmark` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.
