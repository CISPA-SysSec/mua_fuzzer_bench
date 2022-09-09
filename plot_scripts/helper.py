
from dataclasses import dataclass
from pathlib import Path
import sqlite3
import os
from typing import List, Optional

def db_connect(path: Path):
    return sqlite3.connect(path)


@dataclass
class QueryResult():
    res: list
    indices: dict

    def get(self, name):
        return self.run[self.indices[name]]


def query(db: sqlite3.Connection, stmt: str) -> QueryResult:
    res = db.execute(stmt)
    columns = [dd[0] for dd in res.description]
    indices = {nn: ii for ii, nn in enumerate(columns)}
    res = list(res.fetchall())
    return QueryResult(res, indices)


def fix_path(path: Path | str) -> Path:
    path = Path(path)
    if Path(os.getcwd()).name in ["plot_scripts"]:
        print("In plot_scripts")
        if path.parts[0] in ["data", "seeds", "plot"]:
            path = Path("..")/path
    return path


def to_latex_table(data: List[List[str] | str], /, suffixes: Optional[List[Optional[str]]]=None):
    # for ll in data:
    #     print(ll)

    if suffixes:
        assert len(suffixes) == len(data), f"{len(suffixes)} == {len(data)}"

    assert isinstance(data[0], list)
    columns = len(data[0])
    col_lengths = [0]*columns

    # get max lengths for each column, to make the table more readable in raw form
    for rr in data:
        if isinstance(rr, list):
            assert len(rr) == columns
            for ii, el in enumerate(rr):
                col_lengths[ii] = max(col_lengths[ii], len(el))

    res = ""
    for row_idx, rr in enumerate(data):
        if isinstance(rr, list):
            for ii, el in enumerate(rr):
                res += f"{el:<{col_lengths[ii]}}"
                if ii < columns - 1:
                    res += f" & "
        elif isinstance(rr, str):
            res += rr
        else:
            raise ValueError(f"{rr} unhandled type")
        res +=  r" \\"
        if suffixes:
            suff = suffixes[row_idx]
            if suff:
                res += " " + suff

        res += "\n"

    return res


def out_path(name: str) -> Path:
    return fix_path(Path("plot/fig")/name)