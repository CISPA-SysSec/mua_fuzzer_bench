from .afl import collect_afl
from .libfuzzer import collect_libfuzzer
from .honggfuzz import collect_honggfuzz


SEED_HANDLERS = {
    'honggfuzz': collect_honggfuzz,
    'libfuzzer': collect_libfuzzer,
    'aflpp': collect_afl,
    'afl': collect_afl,
}
