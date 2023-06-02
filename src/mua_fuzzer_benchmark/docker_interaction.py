import contextlib
import logging
import os
from queue import Queue
import signal
import subprocess
import threading
import time
import traceback
from typing import Any, Dict, Generator, Iterable, List, Optional, ParamSpec, Union, no_type_check, cast

import docker

from constants import HOST_TMP_PATH, IN_DOCKER_SHARED_DIR, IN_DOCKER_WORKDIR, MAX_RUN_EXEC_IN_CONTAINER_TIME, SHARED_DIR, SHOW_CONTAINER_LOGS
from helpers import CoveredFile

logger = logging.getLogger(__name__)


class Container:
    inner: docker.models.containers.Container # type: ignore[no-any-unimported]
    
    def __init__(self,
        image: str,
        args: List[str],
        /,
        log_config: Dict[str, str],
        **kwargs: object
    ) -> None:
        
        docker_client = docker.from_env() # type: ignore[misc]

        docker_log_config = docker.types.LogConfig( # type: ignore[misc]
            type=docker.types.LogConfig.types.JSON, # type: ignore[misc]
            config=log_config
        )

        self.inner = docker_client.containers.run(  # type: ignore[misc]
            image=image,
            args=args,
            log_config=docker_log_config, # type: ignore[misc]
            **kwargs
        )

    @property
    def name(self) -> str:
        return self.inner.name # type: ignore[no-any-return, misc]

    @property
    def status(self) -> str:
        return self.inner.status # type: ignore[no-any-return, misc]

    def kill(self, signal: int = 9) -> None:
        # default signal: SIGKILL
        self.inner.kill(signal) # type: ignore[misc]

    def stop(self, timeout: int = 10) -> None:
        self.inner.stop(timeout) # type: ignore[misc]

    def reload(self) -> None:
        self.inner.reload() # type: ignore[misc]

    def stream_logs(self) -> List[bytes]:
        return self.inner.logs(stream=True) # type: ignore[no-any-return, misc]

class DockerClient:
    pass


class DockerLogStreamer(threading.Thread):
    def __init__(self, q: Queue[str], container: Container):
        self.q = q
        self.container = container
        super().__init__()

    def run(self) -> None:
        def add_lines(lines: List[bytes]) -> None:
            for ll in lines:
                line = ll.decode()
                if SHOW_CONTAINER_LOGS:
                    logger.info(line.rstrip())
                if "Fuzzing test case #" in line:
                    continue
                self.q.put(line)

        try:
            # keep getting logs
            add_lines(self.container.stream_logs())
        except Exception:
            error_message = traceback.format_exc()
            for line in error_message.splitlines():
                self.q.put(line)
        # self.q.put(None)


@contextlib.contextmanager
def start_testing_container(core_to_use: int, trigger_file: CoveredFile, timeout: int) -> Generator[Container, None, None]:
    # Start and run the container
    container = Container(
        "mutator_testing", # the image
        ["sleep", str(timeout)], # the arguments, give a max uptime for containers
        init=True,
        ipc_mode="host",
        auto_remove=True,
        user=os.getuid(),
        environment={
            'LD_LIBRARY_PATH': "/workdir/tmp/lib/",
            'TRIGGERED_FOLDER': str(trigger_file.docker_path),
        },
        volumes={
            str(HOST_TMP_PATH): {'bind': str(IN_DOCKER_WORKDIR)+"/tmp/", 'mode': 'ro'},
            str(SHARED_DIR): {'bind': str(IN_DOCKER_SHARED_DIR), 'mode': 'rw'},
        },
        working_dir=str(IN_DOCKER_WORKDIR),
        cpuset_cpus=str(core_to_use),
        mem_limit="1g",
        mem_swappiness=0,
        log_config={'max-size': '10m'},
        detach=True
    )
    try:
        yield container
    except Exception as exc:
        raise exc
    finally: # This will stop the container if there is an exception or not.
        try:
            container.kill(2)
            for _ in range(50):
                time.sleep(.1)
                container.reload()
            while True:
                container.stop()
                logger.info(f"! Testing container still alive {container.name}, keep killing it.")
                time.sleep(1)
        except docker.errors.NotFound: # type: ignore[misc]
            # container is dead
            pass


@contextlib.contextmanager
def start_mutation_container(
    core_to_use: Optional[int],
    timeout: Optional[int],
) -> Generator[Container, None, None]:
    # Start and run the container
    container = Container(
        "mutator_mutator", # the image
        ["sleep", str(timeout) if timeout is not None else 'infinity'], # the arguments, give a max uptime for containers
        init=True,
        ipc_mode="host",
        auto_remove=True,
        user=os.getuid(),
        volumes={
            str(HOST_TMP_PATH): {'bind': "/home/mutator/tmp/", 'mode': 'rw'},
            str(SHARED_DIR): {'bind': str(IN_DOCKER_SHARED_DIR), 'mode': 'rw'},
        },
        mem_limit="10g",
        mem_swappiness=0,
        cpuset_cpus=str(core_to_use) if core_to_use is not None else None,
        log_config={'max-size': '10m'},
        detach=True,
    )
    try:
        yield container
    except Exception as exc:
        raise exc
    finally: # This will stop the container if there is an exception or not.
        try:
            container.kill(2)
            time.sleep(.5)
            container.reload()
            for _ in range(10):
                time.sleep(5)
                container.reload()
            while True:
                container.stop()
                logger.info(f"! Mutation container still alive {container.name}, keep killing it.")
                time.sleep(10)
        except docker.errors.NotFound: # type: ignore[misc]
            # container is dead
            pass


def run_exec_in_container(
        container: Container,
        raise_on_error: bool,
        cmd: List[str],
        exec_args: Optional[List[str]] = None,
        timeout: Optional[int] = None
) -> Dict[str, Union[int, str, bool]]:
    """
    Start a short running command in the given container,
    sigint is ignored for this command.
    If return_code is not 0, raise a ValueError containing the run result.
    """
    container_name = container.name

    timed_out = False
    sub_cmd: List[str] = ["docker", "exec", *(exec_args if exec_args is not None else []), container_name, *cmd]
    proc = subprocess.Popen(sub_cmd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            close_fds=True,
            errors='backslashreplace',  # text mode: stdout is a str
            preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN))
    try:
        stdout, _ = proc.communicate(timeout=MAX_RUN_EXEC_IN_CONTAINER_TIME if timeout is None else timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, _ = proc.communicate()
        timed_out = True

    assert isinstance(proc.returncode, int) # type: ignore[misc]
    if raise_on_error and proc.returncode != 0:
        logger.debug(f"process error (timed out): {str(proc.args)}\n{stdout}")
        raise ValueError(f"exec_in_docker failed (timed out)\nexec_code: {proc.returncode}\n{stdout}")

    return {'returncode': proc.returncode, 'out': stdout, 'timed_out': timed_out}
    ##################
    # alternative version using docker lib, this errors with lots of docker containers
    # https://github.com/docker/docker-py/issues/2278
    # 
    #  if exec_args is not None:
    #      raise ValueError("Exec args not supported for container exec_run.")
    #  proc = container.exec_run(cmd)
    #  if raise_on_error and proc[0] != 0:
    #      logger.info("process error: =======================",
    #              cmd,
    #              proc[1],
    #              sep="\n")
    #      raise ValueError(proc)
    #  return {'returncode': proc[0], 'out': proc[1]}
