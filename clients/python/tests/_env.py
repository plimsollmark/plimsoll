"""Settings the Go test (client_test.go) passes to the suites that need a daemon.

Run alone, those suites skip. Under ``go test ./clients/python``,
PLIMSOLL_INTEGRATION_REQUIRED=1 turns a missing setting into a failure, so a pass
there means every case ran.
"""

from __future__ import annotations

import os
import unittest

REQUIRED = os.environ.get("PLIMSOLL_INTEGRATION_REQUIRED") == "1"


def setting(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        if REQUIRED:
            raise RuntimeError(f"{name} is not set, and PLIMSOLL_INTEGRATION_REQUIRED=1")
        raise unittest.SkipTest(f"{name} is not set; run through `go test ./clients/python`")
    return value
