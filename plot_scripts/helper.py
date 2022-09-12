
from dataclasses import dataclass
from pathlib import Path
import sqlite3
import os
from typing import Any, Iterable, List, Optional

def db_connect(path: Path):
    used_path = fix_path(path)
    try:
        return sqlite3.connect(used_path)
    except sqlite3.OperationalError as e:
        print(used_path)
        raise e



@dataclass
class QueryElem():
    rr: List[Any]
    indices: dict

    def get(self, name) -> Any:
        return self.rr[self.indices[name]]


@dataclass
class QueryList():
    res: list
    indices: dict

    def __iter__(self) -> Iterable[QueryElem]:
        for rr in self.res:
            yield QueryElem(rr, self.indices)


def query(db: sqlite3.Connection, stmt: str) -> QueryList:
    res = db.execute(stmt)
    columns = [dd[0] for dd in res.description]
    indices = {nn: ii for ii, nn in enumerate(columns)}
    res = list(res.fetchall())
    return QueryList(res, indices)


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
            print(rr)
            for ii, el in enumerate(rr):
                print(el, col_lengths[ii])
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
    res_path = fix_path(Path("plot/fig")/name)
    res_path.parent.mkdir(parents=True, exist_ok=True)
    return res_path


def data_path(name: str) -> Path:
    res_path = fix_path(Path("plot/tmp_data")/name)
    res_path.parent.mkdir(parents=True, exist_ok=True)
    return res_path