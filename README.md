# llvm-mutation-tool

## Install

```shell script
# run both from root directory

# setting up llvm takes some time and space (llvm is fully compiled including clang)
./scripts/setup_llvm_clang.sh



# compiles the project and installs it under build/install
gradle build
```


## Invoke
```shell script
# invokes the mutation pipeline, check for details on how to invoke the project in detail
./run_mutation.sh <path-to-subject.c> (e.g. ./samples/simple_malloc/malloc.c)
```

## Clean
```shell script
# run in root directory to delete all build products
# can also be used if the build does not correctly update or another strange behavior is observed

gradle clean
```
