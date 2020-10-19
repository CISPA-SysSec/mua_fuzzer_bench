#!/usr/bin/env python3
"""
Script for building, running and deleting the lFuzzer docker container.
"""
import subprocess
import sys
import argparse
import os


llvm_dockerfile = "Dockerfile.llvm"
mutator_dockerfile = "Dockerfile.mutator"
llvm_image = "mutator_llvm:901"
mutator_image = "mutator_mutator:latest"
container_name = "mutator_container"


def print_fail(message):
    """
    Prints the message in red to the error console.
    :param message:
    :return:
    """
    sys.stderr.write('\x1b[1;31m' + message + '\x1b[0m\n\n')


def print_pass(message):
    """
    Prints the message in green to stdout.
    :param message:
    :return:
    """
    sys.stdout.write('\x1b[1;32m' + message + '\x1b[0m\n\n')


def build():
    """
    Builds the container by first building the llvm container and then consecutively building the lFuzzer container
    :return:
    """
    proc = subprocess.run(["docker", "image", "inspect", llvm_image], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        # build llvm image
        proc = subprocess.run(["docker", "build", "--no-cache", "-t", llvm_image, "-f", llvm_dockerfile, "."])

    # build Mutator image
    if proc.returncode != 0:
        print_fail("LLVM image was not properly built. Check output for details.")
        exit(1)
    print("Building Mutator container.")
    # proc = subprocess.run(["docker", "build", "--no-cache", "-t", mutator_image, "-f", mutator_dockerfile, "."])
    proc = subprocess.run(["docker", "build", "-t", mutator_image, "-f", mutator_dockerfile, "."])
    if proc.returncode != 0:
        print_fail("Mutator image was not properly built. Check output for details.")
        exit(1)
    print_pass("Successfully built Mutator Docker container.")


def rebuild():
    """
        Deletes the Mutator images including all containers and data and rebuilds it from scratch.
        """
    inpt = input(
        "Do you want to delete the Mutator image including all "
        "containers and experiment data and rebuild it? [yes/no]: ")
    if inpt == "yes":
        proc = subprocess.run(["docker", "rm", container_name])
        if proc.returncode != 0:
            print_fail("Mutator container was not properly deleted. Check output for details.")
        proc = subprocess.run(["docker", "image", "rm", mutator_image])
        if proc.returncode != 0:
            print_fail("Mutator image was not properly deleted. Check output for details.")
        build()
    else:
        print("No image will be deleted. Stopping...")
        exit(0)


def start():
    """
    Starts the Mutator container.
    :return:
    """
    proc = subprocess.run(["docker", "image", "inspect", mutator_image], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        inpt = input("Mutator image does not exist. Do you want to build it now (takes around an hour)? [y/n]: ")
        if inpt == "y":
            build()
        else:
            print("No image will be built. Stopping...")
            exit(0)
    print("Starting lFuzzer docker container.")
    # TODO check if container is already running
    is_there = container_name in str(subprocess.run(["docker", "ps", "-a"],
                                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout)
    is_running = container_name in str(subprocess.run(["docker", "ps"],
                                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout)
    if not is_there:
        print_pass("Container does not exist. Container will be created and started and bash will be attached.")
        subprocess.run(["docker", "run", "-dt", "--name", container_name, mutator_image])
        subprocess.run(["docker", "start", container_name])
        subprocess.run(["docker", "exec", "-it", container_name, "/bin/bash"])
        return
    elif is_there and not is_running:
        # if the container exists but is not running
        print_pass("Already existing container will be started and bash will be attached.")
        subprocess.run(["docker", "start", container_name])
        subprocess.run(["docker", "exec", "-it", container_name, "/bin/bash"])
        return
    elif is_there and is_running:
        print_pass("Container is already running! Attached second bash to running container.")
        subprocess.run(["docker", "exec", "-it", container_name, "/bin/bash"])
    else:
        print_fail("Docker claims the container does not exist but is running. Something is going wrong.")
        exit(1)


def delete():
    """
    Deletes the Mutator and llvm images including all containers and data.
    """
    inpt = input("Do you want to delete the Mutator and llvm image including "
                 "all containers and experiment data? [yes/no]: ")
    if inpt == "yes":
        proc = subprocess.run(["docker", "rm", container_name])
        if proc.returncode != 0:
            print_fail("lFuzzer container was not properly deleted. Check output for details.")
        proc = subprocess.run(["docker", "image", "rm", mutator_image])
        if proc.returncode != 0:
            print_fail("lFuzzer image was not properly deleted. Check output for details.")
        proc = subprocess.run(["docker", "image", "rm", llvm_image])
        if proc.returncode != 0:
            print_fail("llvm image was not properly deleted. Check output for details.")
    else:
        print("No image will be deleted. Stopping...")
        exit(0)


def stop():
    """
    Stops the lFuzzer docker container.
    :return:
    """
    inpt = input("Container will be stopped, all running experiments will be aborted "
                 "(already generated data should will not be deleted). Are you sure? [y/n]: ")
    if inpt == "y":
        print("Stopping container...")
        proc = subprocess.run(["docker", "stop", container_name])
        if proc.returncode != 0:
            print_fail("Could not stop the container. Check output.")
            exit(1)
        print_pass("Stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mutator Docker Wrapper")
    parser.add_argument('-b', "--build", action='store_true',
                        help="Builds the llvm image and consecutively the lFuzzer image. Takes about an hour.")
    parser.add_argument('-a', "--attach", action='store_true',
                        help="Runs the built container. Builds it on demand if not existing "
                             "(takes about an hour to build).",)
    parser.add_argument('-d', "--delete", action='store_true',
                        help="Deletes the containers and the images. Containers must be stopped before deleting.")
    parser.add_argument('-s', "--stop", action='store_true',
                        help="Stops the running container, stopping all running experiments.")
    parser.add_argument('-r', "--rebuild", action='store_true',
                        help="Deleted the lFuzzer image and container including all experiment "
                             "data and builds it from scratch. The LLVM image will be kept.")
    args = parser.parse_args(sys.argv[1:])

    if args.build:
        build()
    elif args.attach:
        start()
    elif args.delete:
        delete()
    elif args.stop:
        stop()
    elif args.rebuild:
        rebuild()
    else:
        print("Exactly one flag must be set.")
        parser.print_help()
        exit(1)
