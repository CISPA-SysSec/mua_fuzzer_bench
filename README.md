# llvm-mutation-tool

## Install

### Docker Install
```shell script
# use the python script mutator-docker-wrapper.py

# first build the docker containers
python3 mutator-docker-wrapper.py -b

# then connect to the container
python3 mutator-docker-wrapper.py -a

# [optional] constul the script's help output for rebuilding and similar (will be faster than the initial build)
python3 mutator-docker-wrapper.py -h
```

### Local Install

```shell script
# run both from root directory

# setting up llvm takes some time and space (llvm is fully compiled including clang)
./scripts/setup_llvm_clang.sh



# compiles the project and installs it under build/install
gradle build
```


## Invoke Generation of Mutation Files
General invoke:
```shell script
# invokes the mutation pipeline, check for details on how to invoke the project in detail
./run_mutation.py -p <path-to-subject.c> (e.g. ./samples/simple_malloc/malloc.c) [-bc] [-ll] [-bn]
```
Explanation of optional arguments (at least one must be chosen, otherwise the output would be empty):
```
-bc: Keeps the mutated bitcode files.
-ll: Keeps the mutated bitcode files in human readable form.
-bn: Generates runnable binaries if possible.
```

## Running Mutated Programs

The mutated programs have code injected which prints if the mutation was triggered.
It is possible to influence the output by defining environment variables:

```shell
export TRIGGERED_OUTPUT="Some output." # can contain any string which will be printed to the command line 
    and written to the file TRIGGERED_FILE if it is defined and could be created; a default value is printed if
    this environment variable is not defined

export TRIGGERED_FILE="some/file/to/report/mutation/trigger" # a path to a file which will be either created or 
    overwritten if existing and is filled with the TRIGGERED_OUTPUT value or some default string if TRIGGERED_OUTPUT is not defined
```

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