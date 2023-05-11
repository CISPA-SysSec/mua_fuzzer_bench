import os
from pathlib import Path
import uuid

import psutil


EXEC_ID = str(uuid.uuid4())

# set the number of concurrent runs
NUM_CPUS = int(os.getenv("MUT_NUM_CPUS", psutil.cpu_count(logical=True)))

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

SHARED_DIR = Path(os.getenv("MUT_SHARED_DIR", "/dev/shm/")).absolute()
SHARED_DIR.mkdir(parents=True, exist_ok=True)

IN_DOCKER_SHARED_DIR = Path("/shared/")

BLOCK_SIZE = 1024*4


# The programs that can be evaluated
PROGRAMS = {
    "dev": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": False,
        "orig_bin": str(Path("tmp/samples/dev/out/test")),
        "orig_bc": str(Path("tmp/samples/dev/out/test.bc")),
        "name": "dev",
        "path": "samples/dev",
        "dict": None,
        "omit_functions": ["LLVMFuzzerTestOneInput"],
    },
    "cares_parse_reply": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": False,
        "orig_bin": str(Path("tmp/samples/c-ares/out/ares-parse-reply")),
        "orig_bc": str(Path("tmp/samples/c-ares/out/ares-parse-reply.bc")),
        "name": "cares",
        "path": "samples/c-ares",
        "dict": None,
        "omit_functions": ["LLVMFuzzerTestOneInput"],
    },
    "cares_name": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": False,
        "orig_bin": str(Path("tmp/samples/c-ares/out/ares-name")),
        "orig_bc": str(Path("tmp/samples/c-ares/out/ares-name.bc")),
        "name": "cares",
        "path": "samples/c-ares",
        "dict": None,
        "omit_functions": ["LLVMFuzzerTestOneInput"],
    },
    "woff2_base": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/woff2/out/convert_woff2ttf_fuzzer/convert_woff2ttf_fuzzer")),
        "orig_bc": str(Path("tmp/samples/woff2/out/convert_woff2ttf_fuzzer/convert_woff2ttf_fuzzer.bc")),
        "name": "woff2",
        "path": "samples/woff2/out/convert_woff2ttf_fuzzer",
        "dict": None,
        "omit_functions": ["LLVMFuzzerTestOneInput"],
    },
    "woff2_new": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/woff2/out/convert_woff2ttf_fuzzer_new_entry/convert_woff2ttf_fuzzer_new_entry")),
        "orig_bc": str(Path("tmp/samples/woff2/out/convert_woff2ttf_fuzzer_new_entry/convert_woff2ttf_fuzzer_new_entry.bc")),
        "name": "woff2",
        "path": "samples/woff2/out/convert_woff2ttf_fuzzer_new_entry",
        "dict": None,
        "omit_functions": ["LLVMFuzzerTestOneInput"],
    },
    "re2": {
        "bc_compile_args": [
            {'val': "-std=c++11", 'action': None},
        ],
        "bin_compile_args": [
            # {'val': "tmp/samples/re2_harness/harness.cc", 'action': 'prefix_workdir'},
            {'val': "-lpthread", 'action': None},
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/re2-code/out/re2_fuzzer")),
        "orig_bc": str(Path("tmp/samples/re2-code/out/re2.bc")),
        "name": "re2",
        "path": "samples/re2-code",
        "dict": "tmp/samples/re2_harness/re2.dict",
        "omit_functions": ["LLVMFuzzerTestOneInput"],
    },
     "bloaty": {
         "bc_compile_args": [
            {'val': "-L", 'action': None},
            {'val': "tmp/samples/bloaty/work/third_party/protobuf/cmake/", 'action': 'prefix_workdir'},
            {'val': "-L", 'action': None},
            {'val': "tmp/samples/bloaty/work/third_party/re2/", 'action': 'prefix_workdir'},
            {'val': "-L", 'action': None},
            {'val': "tmp/samples/bloaty/work/third_party/capstone/", 'action': 'prefix_workdir'},
            {'val': "-lprotobuf", 'action': None},
            {'val': "-lre2", 'action': None},
            {'val': "-lcapstone", 'action': None},
            {'val': "-lpthread", 'action': None},
            {'val': "-lz", 'action': None},
         ],
         "bin_compile_args": [
         ],
         "is_cpp": True,
         "orig_bin": str(Path("tmp/samples/bloaty/work/bloaty-orig")),
         "orig_bc": str(Path("tmp/samples/bloaty/work/bloaty.bc")),
         "name": "bloaty",
         "path": "samples/bloaty/",
         "dict": None,
        "omit_functions": ["LLVMFuzzerTestOneInput"],
     },
     "curl": {
        "bc_compile_args": [
           {'val': "-L", 'action': None},
           {'val': "tmp/samples/curl/out/lib/", 'action': 'prefix_workdir'},
           {'val': "-lpthread", 'action': None},
           {'val': "-lidn2", 'action': None},
           {'val': "-lnghttp2", 'action': None},
           {'val': "-lz", 'action': None},
        ],
        "bin_compile_args": [
        ],
        "is_cpp": False,
        "orig_bin": str(Path("tmp/samples/curl/out/curl_fuzzer")),
        "orig_bc": str(Path("tmp/samples/curl/out/curl.bc")),
        "name": "curl",
        "path": "samples/curl/",
        "dict": None,
        "omit_functions": ["LLVMFuzzerTestOneInput"],
     },
    "guetzli": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/guetzli/guetzli-orig")),
        "orig_bc": str(Path("tmp/samples/guetzli/guetzli.bc")),
        "name": "guetzli",
        "path": "samples/guetzli/",
        "dict": "tmp/samples/guetzli_harness/guetzli.dict",
        "omit_functions": ["LLVMFuzzerTestOneInput"],
    },
    "libevent": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
            {'val': '-lstdc++', 'action': None},
        ],
        "is_cpp": False,
        "orig_bin": str(Path("tmp/samples/libevent/out/parse_query_fuzzer")),
        "orig_bc": str(Path("tmp/samples/libevent/out/parse_query_fuzzer.bc")),
        "name": "libevent",
        "path": "samples/libevent/",
        "dict": None,
        "omit_functions": ["LLVMFuzzerTestOneInput"],
    },
    "mjs": {
        "bc_compile_args": [
            {'val': "-ldl", 'action': None},
        ],
        "bin_compile_args": [
        ],
        "is_cpp": False,
        "orig_bin": str(Path("tmp/samples/mjs/out/mjs_fuzzer")),
        "orig_bc": str(Path("tmp/samples/mjs/out/mjs.bc")),
        "name": "mjs",
        "path": "samples/mjs/",
        "dict": None,
        "omit_functions": ["LLVMFuzzerTestOneInput"],
    },
    "jsoncpp": {
        "bc_compile_args": [
        ],
        "bin_compile_args": [
        ],
        "is_cpp": True,
        "orig_bin": str(Path("tmp/samples/jsoncpp/out/jsoncpp-orig")),
        "orig_bc": str(Path("tmp/samples/jsoncpp/out/jsoncpp.bc")),
        "name": "jsoncpp",
        "path": "samples/jsoncpp/",
        "dict": "tmp/samples/jsoncpp_harness/fuzz.dict",
        "omit_functions": ["LLVMFuzzerTestOneInput"],
    },
    #  "mjs": {
    #      "bc_compile_args": [
    #      ],
    #      "bin_compile_args": [
    #          {'val': "-ldl", 'action': None},
    #      ],
    #      "is_cpp": False,
    #      "orig_bin": str(Path("tmp/samples/mjs/mjs/mjs")),
    #      "orig_bc": str(Path("tmp/samples/mjs/mjs/mjs.bc")),
    #      "name": "mjs",
    #      "path": "samples/mjs/",
    #      "dict": None,
    #      "args": "@@",
    #  },
    #  "freetype": {
    #      "bc_compile_args": [
    #      ],
    #      "bin_compile_args": [
    #      ],
    #      "is_cpp": True,
    #      "orig_bin": str(Path("tmp/samples/freetype/out/ftfuzzer")),
    #      "orig_bc": str(Path("tmp/samples/freetype/out/ftfuzzer.bc")),
    #      "name": "freetype",
    #      "path": "samples/ftfuzzer",
    #      "dict": None,
    #  },
    # "aspell": {
    #     "bc_compile_args": [
    #         {'val': "-lpthread", 'action': None},
    #         {'val': "-ldl", 'action': None},
    #     ],
    #     "bin_compile_args": [
    #     ],
    #     "is_cpp": True,
    #     "orig_bin": str(Path("tmp/samples/aspell/out/aspell_fuzzer")),
    #     "orig_bc": str(Path("tmp/samples/aspell/out/aspell_fuzzer.bc")),
    #     "name": "aspell",
    #     "path": "samples/aspell/",
    #     "dict": None,
    # },
    # "vorbis": {
    #     "bc_compile_args": [
    #     ],
    #     "bin_compile_args": [
    #     ],
    #     "is_cpp": True,
    #     "orig_bin": str(Path("tmp/samples/vorbis/out/decode_fuzzer")),
    #     "orig_bc": str(Path("tmp/samples/vorbis/out/decode_fuzzer.bc")),
    #     "name": "vorbis",
    #     "path": "samples/vorbis/",
    #     "dict": "tmp/samples/vorbis_harness/vorbis.dict",
    #     "args": "@@",
    # },
    #  "harfbuzz": {
    #      "bc_compile_args": [
    #      ],
    #      "bin_compile_args": [
    #      ],
    #      "is_cpp": True,
    #      "orig_bin": str(Path("tmp/samples/harfbuzz/hb-subset-fuzzer")),
    #      "orig_bc": str(Path("tmp/samples/harfbuzz/hb-subset-fuzzer.bc")),
    #      "name": "harfbuzz",
    #      "path": "samples/harfbuzz/",
    #      "dict": None,
    #  },
    #  "file": {
    #      "bc_compile_args": [
    #      ],
    #      "bin_compile_args": [
    #          {'val': "-lz", 'action': None},
    #      ],
    #      "is_cpp": False,
    #      "orig_bin": str(Path("tmp/samples/file/magic_fuzzer")),
    #      "orig_bc": str(Path("tmp/samples/file/magic_fuzzer.bc")),
    #      "name": "file",
    #      "path": "samples/file/",
    #      "dict": None,
    #      "args": "<WORK>/samples/file_harness/magic.mgc @@",
    #  },
    # "libjpeg": {
    #     "bc_compile_args": [
    #     ],
    #     "bin_compile_args": [
    #     ],
    #     "is_cpp": True,
    #     "orig_bin": str(Path("tmp/samples/libjpeg-turbo/out/libjpeg")),
    #     "orig_bc": str(Path("tmp/samples/libjpeg-turbo/out/libjpeg.bc")),
    #     "name": "libjpeg",
    #     "path": "samples/libjpeg-turbo/",
    #     "dict": "tmp/samples/libjpeg-turbo_harness/libjpeg.dict",
    #     "args": "@@",
    # },
    #  "sqlite3": {
    #      "bc_compile_args": [
    #      ],
    #      "bin_compile_args": [
    #          {'val': "-lpthread", 'action': None},
    #          {'val': "-ldl", 'action': None},
    #      ],
    #      "is_cpp": False,
    #      "orig_bin": str(Path("tmp/samples/sqlite3/sqlite3_ossfuzz")),
    #      "orig_bc": str(Path("tmp/samples/sqlite3/sqlite3_ossfuzz.bc")),
    #      "name": "sqlite",
    #      "path": "samples/sqlite3/",
    #      "dict": None,
    #      "args": "@@",
    #  },
    # "libcxx": {
    #     "bc_compile_args": [
    #     ],
    #     "bin_compile_args": [
    #     ],
    #     "is_cpp": True,
    #     "orig_bin": str(Path("tmp/samples/libcxx/out/libjpeg")),
    #     "orig_bc": str(Path("tmp/samples/libcxx/out/libjpeg.bc")),
    #     "name": "libcxx",
    #     "path": "samples/libcxx/",
    #     "dict": "tmp/samples/libcxx/libjpeg.dict",
    # },
    # "openthread": {
    #     "bc_compile_args": [
    #     ],
    #     "bin_compile_args": [
    #     ],
    #     "is_cpp": True,
    #     "orig_bin": str(Path("tmp/samples/libcxx/out/libjpeg")),
    #     "orig_bc": str(Path("tmp/samples/libcxx/out/libjpeg.bc")),
    #     "name": "openthread",
    #     "path": "samples/openthread/",
    #     "dict": None,
    # },
    # "libarchive": {
    #     "bc_compile_args": [
    #         # {'val': "-Itmp/samples/libarchive/libarchive/libarchive", 'action': 'prefix_workdir'},
    #         {'val': "-lcrypto", 'action': None},
    #         {'val': "-lacl", 'action': None},
    #         {'val': "-llzma", 'action': None},
    #         {'val': "-llz4", 'action': None},
    #         {'val': "-lbz2", 'action': None},
    #         {'val': "-lz", 'action': None},
    #         {'val': "-ldl", 'action': None},
    #     ],
    #     "bin_compile_args": [
    #     ],
    #     "is_cpp": True,
    #     "orig_bin": str(Path("tmp/samples/libarchive/out/libarchive_fuzzer")),
    #     "orig_bc": str(Path("tmp/samples/libarchive/out/libarchive.bc")),
    #     "name": "libarchive",
    #     "path": "samples/libarchive/",
    #     "dict": None,
    # },
    # "spdk": {
    #     "bc_compile_args": [
    #         {'val': "-ldl", 'action': None},
    #         {'val': "-lpthread", 'action': None},
    #         {'val': "-lnuma", 'action': None},
    #         {'val': "-luuid", 'action': None},
    #     ],
    #     "bin_compile_args": [
    #     ],
    #     "is_cpp": True,
    #     "orig_bin": str(Path("tmp/samples/spdk/out/parse_json_fuzzer")),
    #     "orig_bc": str(Path("tmp/samples/spdk/out/spdk.bc")),
    #     "name": "spdk",
    #     "path": "samples/spdk/",
    #     "dict": None,
    # },
}