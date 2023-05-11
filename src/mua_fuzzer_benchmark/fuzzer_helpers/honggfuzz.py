
def collect_honggfuzz(path):
    found = path.glob("output/*")
    crashes = list(path.glob("crashes/*"))
    return list(found) + list(crashes)