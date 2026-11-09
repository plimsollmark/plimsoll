# The -live run's key scan, from inside the sandbox. The harness sends scan.json: a random salt
# and, for each API key the daemon holds, its length and SHA-256(salt + key). The key itself
# never comes in. This hashes every window of that length in each place a key could sit (each
# process's environment and command line, and the files under the working directory, /tmp and
# the home directory), and reports how much it read and whether any window matched.
#
# It finds a key's exact bytes, not an encoded copy of them.
import hashlib
import json
import os

MAX_BYTES = 8 << 20


def blobs():
    for pid in (d for d in os.listdir("/proc") if d.isdigit()):
        for name in ("environ", "cmdline"):
            try:
                with open("/proc/%s/%s" % (pid, name), "rb") as f:
                    yield "/proc/%s/%s" % (pid, name), f.read()
            except OSError:
                continue
    seen = set()
    home = os.path.expanduser("~")
    for root in [os.getcwd(), "/tmp"] + ([home] if home not in ("", "/") else []):
        for directory, _, names in os.walk(root):
            for name in names:
                path = os.path.realpath(os.path.join(directory, name))
                if path in seen or not os.path.isfile(path) or name == "scan.json":
                    continue
                seen.add(path)
                try:
                    with open(path, "rb") as f:
                        yield path, f.read(MAX_BYTES)
                except OSError:
                    continue


def scan(spec_path="scan.json"):
    with open(spec_path, encoding="utf-8") as f:
        spec = json.load(f)
    salt = bytes.fromhex(spec["salt"])
    keys = [(k["length"], bytes.fromhex(k["sha256"])) for k in spec["keys"]]
    read, windows, places, hits = 0, 0, 0, []
    for place, blob in blobs():
        if read + len(blob) > MAX_BYTES:
            return {"bytes": read, "windows": windows, "places": places, "hits": hits, "stopped_at_limit": True}
        read += len(blob)
        places += 1
        for length, digest in keys:
            for i in range(len(blob) - length + 1):
                windows += 1
                if hashlib.sha256(salt + blob[i:i + length]).digest() == digest:
                    hits.append(place)
    return {"bytes": read, "windows": windows, "places": places, "hits": hits, "stopped_at_limit": False}
