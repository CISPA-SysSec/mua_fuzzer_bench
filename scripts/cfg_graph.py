import tempfile
from subprocess import run
from pathlib import Path
import pydot

def get_dot_file_graph(path):
    graphs = pydot.graph_from_dot_file(path)
    return graphs[0]


def create_cfg_dots(bc_path):
    with tempfile.TemporaryDirectory() as d:
        run(["opt", "-passes=dot-cfg", "-debug-pass-manager", str(bc_path), "--disable-output"], cwd=d)
        print(d)
        input("bla")

def main():
    bc_file = Path('cares_name.bc')
    # create_cfg_dots(bc_file.absolute())
    get_dot_file_graph('/tmp/dot_test/.try_config.dot')



if __name__ == "__main__":
    main()