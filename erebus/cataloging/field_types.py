"""Column type classes for the gateway field rules (spec 015 "Sync behaviour").

Pure. Maps the type names Postgres, MySQL, SQLite, MSSQL, Oracle and the warehouses
report to one class. Only ``text`` can be auto-accepted; arrays, maps and structs are
``complex`` (never one text value); a type not listed here is ``unknown`` and goes to
review instead of being guessed.
"""
from __future__ import annotations

import re

_CLASSES = {
    "text": (
        "text", "tinytext", "mediumtext", "longtext", "varchar", "character varying", "char", "character",
        "nvarchar", "nchar", "ntext", "national character varying", "national character", "clob", "nclob",
        "string", "citext", "varchar2", "nvarchar2", "bpchar", "name", "",
    ),
    "integer": (
        "int", "integer", "smallint", "bigint", "tinyint", "mediumint", "int2", "int4", "int8", "int64",
        "serial", "smallserial", "bigserial", "serial4", "serial8", "byteint",
    ),
    "boolean": ("bool", "boolean", "bit"),
    "datetime": (
        "date", "time", "timetz", "timestamptz", "smalldatetime", "datetimeoffset", "year",
    ),
    "numeric": (
        "numeric", "decimal", "dec", "fixed", "real", "double", "double precision", "money", "smallmoney",
        "number", "bignumeric", "bigdecimal", "float4", "float8", "float64",
    ),
    "uuid": ("uuid", "uniqueidentifier"),
    "json": ("json", "jsonb", "variant", "object"),
    "network": ("inet", "cidr", "macaddr", "macaddr8"),
    "binary": (
        "bytea", "blob", "tinyblob", "mediumblob", "longblob", "binary", "varbinary", "image", "raw",
        "long raw", "bytes", "bfile",
    ),
    "complex": ("array", "map", "struct", "record"),
}
_BY_NAME = {name: cls for cls, names in _CLASSES.items() for name in names}
_PREFIXES = (
    ("timestamp", "datetime"), ("time ", "datetime"), ("datetime", "datetime"), ("interval", "datetime"),
    ("float", "numeric"),
)
_PARAMS = re.compile(r"\([^)]*\)")
_MODIFIERS = frozenset({"unsigned", "signed", "zerofill"})


def type_class(db_type: str) -> str:
    """The class of a reported column type: text, integer, boolean, datetime, numeric,
    uuid, json, network, binary, complex or unknown."""
    raw = db_type.strip().lower()
    if "[]" in raw or "<" in raw or raw.startswith("_"):
        return "complex"  # text[], ARRAY<STRING>, map<string,int>, STRUCT<...>; _text is Postgres' array
    words = [w for w in _PARAMS.sub(" ", raw).split() if w not in _MODIFIERS]
    name = " ".join(words)
    if name in _BY_NAME:
        return _BY_NAME[name]
    for prefix, cls in _PREFIXES:
        if name.startswith(prefix):
            return cls
    return "unknown"
