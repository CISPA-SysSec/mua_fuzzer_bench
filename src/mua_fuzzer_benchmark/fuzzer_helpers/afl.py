
def collect_afl(path):
    found = [pp for pp in path.glob("**/queue/*") if pp.name != '.state']
    crashes = list([pp for pp in path.glob("**/crashes/*") if pp.name != 'README.txt'])
    return list(found) + list(crashes)