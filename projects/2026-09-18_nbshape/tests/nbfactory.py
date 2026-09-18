"""Notebook builders shared by the nbshape test suite.

Kept out of the test_*.py namespace so unittest discovery does not treat it as
a test module. Every builder returns a plain dict in nbformat v4 shape.
"""

from __future__ import annotations

import json
import os
import tempfile


PY_META = {
    "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
    "language_info": {"name": "python", "version": "3.11.4"},
}


def meta():
    return json.loads(json.dumps(PY_META))


def nb(cells, minor=4, metadata=None, nbformat=4):
    return {
        "cells": list(cells),
        "metadata": meta() if metadata is None else metadata,
        "nbformat": nbformat,
        "nbformat_minor": minor,
    }


def code(source, ec=None, outputs=None, cid=None, as_list=False):
    src = source
    if as_list:
        parts = source.split("\n")
        src = [p + "\n" for p in parts[:-1]] + [parts[-1]]
    cell = {
        "cell_type": "code",
        "execution_count": ec,
        "metadata": {},
        "outputs": list(outputs) if outputs else [],
        "source": src,
    }
    if cid is not None:
        cell["id"] = cid
    return cell


def markdown(source, cid=None, extra=None):
    cell = {"cell_type": "markdown", "metadata": {}, "source": source}
    if cid is not None:
        cell["id"] = cid
    if extra:
        cell.update(extra)
    return cell


def stream(text, name="stdout"):
    return {"name": name, "output_type": "stream", "text": text}


def exec_result(text, ec):
    return {
        "data": {"text/plain": text},
        "execution_count": ec,
        "metadata": {},
        "output_type": "execute_result",
    }


def display(mime, payload, plain="<Figure>"):
    return {
        "data": {mime: payload, "text/plain": plain},
        "metadata": {},
        "output_type": "display_data",
    }


# Secret-shaped strings are never stored verbatim in this repository. They are
# assembled here from sub-16-character parts at import time, so the value a
# detection test needs exists in memory while no committed file carries it.
CRED_VALUE = "".join(("8Xk2vJ9pQ3w", "RnT5yBz7cLm"))
ENTROPY_TOKEN = "".join(("4mQ7xZ2pR9", "tLb6VnK3wY", "8sHj5DgF1c", "PzA0"))
PEM_HEADER = "-----BEGIN PRIV" + "ATE KEY-----"


class TempTree(object):
    """Context manager writing notebooks into a throwaway directory."""

    def __init__(self):
        self.dir = None
        self._tmp = None

    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        return self

    def __exit__(self, *exc):
        self._tmp.cleanup()
        return False

    def write(self, name, obj):
        """Write a notebook dict as JSON. Returns the absolute path."""
        path = os.path.join(self.dir, name)
        parent = os.path.dirname(path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(obj, fh, indent=1, ensure_ascii=False)
        return path

    def write_raw(self, name, text, encoding="utf-8"):
        """Write arbitrary text. Returns the absolute path."""
        path = os.path.join(self.dir, name)
        parent = os.path.dirname(path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        with open(path, "w", encoding=encoding, newline="\n") as fh:
            fh.write(text)
        return path

    def write_bytes(self, name, data):
        path = os.path.join(self.dir, name)
        parent = os.path.dirname(path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        with open(path, "wb") as fh:
            fh.write(data)
        return path
