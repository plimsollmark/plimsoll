# What every guest program of the sdk-grants example reports besides its calls: the
# environment it was given, the environment of every process it can read, and what the
# sandbox does with sockets other than the local address. Each program prints one JSON
# document on stdout; the run's record covers that output, and the page is drawn from it.
import json
import os
import socket
import sys
import time


def now_ms():
    return time.time() * 1000.0


def headers(request):
    """The headers a request carried as the client library sent it, in order."""
    return [[k.decode("latin-1"), v.decode("latin-1")] for k, v in request.headers.raw]


def processes():
    """Every process this one can see, with its command line and environment."""
    out = []
    for name in sorted((d for d in os.listdir("/proc") if d.isdigit()), key=int):
        entry = {"pid": int(name)}
        try:
            with open("/proc/%s/cmdline" % name, "rb") as f:
                entry["cmdline"] = f.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
            with open("/proc/%s/environ" % name, "rb") as f:
                entry["environ"] = [x.decode("utf-8", "replace") for x in f.read().split(b"\0") if x]
        except OSError as e:
            entry["error"] = "%s errno %s" % (type(e).__name__, e.errno)
        out.append(entry)
    return out


def attempt(make):
    try:
        make()
        return "allowed"
    except OSError as e:
        return "%s: errno %d, %s" % (type(e).__name__, e.errno, os.strerror(e.errno)) if e.errno else "%s: %s" % (type(e).__name__, e)


def connect_outside():
    # 192.0.2.1 is TEST-NET-1, an address set aside for documentation: no network routes
    # to it, and a container with only its loopback interface has no route at all.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(3)
        s.connect(("192.0.2.1", 443))
    finally:
        s.close()


def sockets():
    return {
        "ipv4_tcp": attempt(lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()),
        "ipv4_udp": attempt(lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).close()),
        "ipv6_tcp": attempt(lambda: socket.socket(socket.AF_INET6, socket.SOCK_STREAM).close()),
        "outside_address": attempt(connect_outside),
    }


def report(calls, sdks):
    doc = {
        "python": sys.version.split()[0],
        "sdks": sdks,
        "environment": dict(sorted(os.environ.items())),
        "processes": processes(),
        "sockets": sockets(),
        "calls": calls,
    }
    print(json.dumps(doc, sort_keys=True))
