# A session's Python interpreter: one process that outlives the calls of a session,
# so what a cell defines is there for the next cell. It is started by the launcher in
# launch.sh with its stdout and stderr on two FIFOs, and runs one cell per connection
# to its control socket. The relay (relay.js) reads the FIFOs between the
# cell's start and end markers.
#
# A cell runs as a notebook cell does: its statements in one global namespace, top-level
# await allowed, and the value of a final expression printed with repr and kept as _.
import ast
import asyncio
import inspect
import json
import linecache
import os
import socket
import sys
import traceback

# Started with -I, so a file in the work directory (a json.py an earlier call wrote)
# shadowed none of the imports above. A cell's own imports find the work directory
# first, as a script's would.
sys.path.insert(0, "")

directory = sys.argv[1]
namespace = {"__name__": "__main__", "__builtins__": __builtins__}
loop = asyncio.new_event_loop()
cells = 0


def run_cell(code):
    global cells
    cells += 1
    filename = "<cell %d>" % cells
    linecache.cache[filename] = (len(code), None, code.splitlines(True), filename)
    flags = ast.PyCF_ALLOW_TOP_LEVEL_AWAIT
    tree = ast.parse(code, filename, "exec")
    last = None
    if tree.body and isinstance(tree.body[-1], ast.Expr):
        last = ast.Expression(tree.body.pop().value)
    result = eval(compile(tree, filename, "exec", flags=flags), namespace)
    if inspect.isawaitable(result):
        loop.run_until_complete(result)
    if last is not None:
        value = eval(compile(last, filename, "eval", flags=flags), namespace)
        if inspect.isawaitable(value):
            value = loop.run_until_complete(value)
        if value is not None:
            namespace["_"] = value
            print(repr(value))


def print_error(error):
    # Drop this file's frames: the traceback starts at the cell.
    tb = error.__traceback__
    while tb is not None and not tb.tb_frame.f_code.co_filename.startswith("<cell"):
        tb = tb.tb_next
    traceback.print_exception(type(error), error, tb, file=sys.stderr)


def write_all(fd, data):
    while data:
        data = data[os.write(fd, data):]


def marker(kind, nonce):
    return ("\0plimsoll-cell-%s-%s\0" % (kind, nonce)).encode()


def flush():
    for stream in (sys.stdout, sys.stderr, sys.__stdout__, sys.__stderr__):
        try:
            stream.flush()
        except Exception:
            pass


server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(os.path.join(directory, "ctl.sock"))
server.listen(1)
with open(os.path.join(directory, "ready"), "w") as f:
    f.write(str(os.getpid()))

while True:
    conn, _ = server.accept()
    try:
        data = b""
        while b"\n" not in data:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
        request = json.loads(data.split(b"\n", 1)[0])
        write_all(1, marker("start", request["nonce"]))
        write_all(2, marker("start", request["nonce"]))
        status = "ok"
        try:
            run_cell(request["code"])
        except BaseException as error:  # a cell's SystemExit or KeyboardInterrupt ends the cell, not the interpreter
            status = "error"
            flush()
            print_error(error)
        flush()
        for fd in (1, 2):
            try:
                write_all(fd, marker("end", request["nonce"]))
            except OSError:
                pass
        conn.sendall((json.dumps({"status": status}) + "\n").encode())
    except Exception:
        pass
    finally:
        conn.close()
