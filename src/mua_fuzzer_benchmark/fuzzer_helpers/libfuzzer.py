
def collect_libfuzzer(path):
    found = path.glob("seeds/*")
    crashes = list(path.glob("artifacts/*"))
    return list(found) + list(crashes)