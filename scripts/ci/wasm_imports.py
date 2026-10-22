#!/usr/bin/env python3
"""specs/042: what a wasm extension needs from the DuckDB-wasm that loads it.

    wasm_imports.py <extension .wasm> <duckdb-wasm engine .wasm>

Every function or global the extension imports from `env` (or through `GOT.func` / `GOT.mem`) must be exported
by the engine or by the extension itself (emscripten imports a side module's own default-visibility symbols too,
and resolves them to its exports): what neither has cannot be resolved when the extension is LOADed - OpenSSL,
sockets, a symbol the engine does not export. The loader's own (`__memory_base`, `__table_base`) are set by it.
"""
import sys

LOADER = {"__memory_base", "__table_base", "__stack_pointer", "__indirect_function_table", "memory"}


def leb(data, i):
    result = shift = 0
    while True:
        byte = data[i]
        i += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            return result, i


def sections(data):
    if data[:4] != b"\0asm":
        raise SystemExit("wasm_imports: not a wasm module")
    i = 8
    while i < len(data):
        section, i = data[i], i + 1
        size, i = leb(data, i)
        yield section, i
        i += size


def name(data, i):
    length, i = leb(data, i)
    return data[i : i + length].decode("utf-8", "replace"), i + length


def limits(data, i):
    flags, i = data[i], i + 1
    _, i = leb(data, i)
    if flags & 1:
        _, i = leb(data, i)
    return i


def imports(data):
    out = []
    for section, i in sections(data):
        if section != 2:
            continue
        count, i = leb(data, i)
        for _ in range(count):
            module, i = name(data, i)
            field, i = name(data, i)
            kind, i = data[i], i + 1
            if kind == 0:  # function: a type index
                _, i = leb(data, i)
            elif kind == 1:  # table: a reference type and limits
                i = limits(data, i + 1)
            elif kind == 2:  # memory
                i = limits(data, i)
            elif kind == 3:  # global: a value type and mutability
                i += 2
            elif kind == 4:  # tag: an attribute and a type index
                _, i = leb(data, i + 1)
            out.append((module, field))
    return out


def exports(data):
    out = set()
    for section, i in sections(data):
        if section != 7:
            continue
        count, i = leb(data, i)
        for _ in range(count):
            field, i = name(data, i)
            _, i = leb(data, i + 1)
            out.add(field)
    return out


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    extension = open(sys.argv[1], "rb").read()
    engine = open(sys.argv[2], "rb").read()
    known = exports(engine) | exports(extension) | LOADER
    wanted = {field for module, field in imports(extension) if module in ("env", "GOT.func", "GOT.mem")}
    missing = sorted(wanted - known)
    if missing:
        print("wasm_imports: the extension needs %d symbol(s) the engine does not export:" % len(missing))
        for field in missing:
            print("  " + field)
        sys.exit(1)
    print("wasm_imports: all %d imports resolve against the engine" % len(wanted))


if __name__ == "__main__":
    main()
