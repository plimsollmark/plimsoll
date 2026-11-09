"""Print what uuid_ctf hides from the model, as one JSON object on stdout.

Run by the attempt driver as a child of its own, in the environment ``vf-eval`` gets: it loads
the outside task's code, and the driver holds an API key, so that code never runs in the
driver's process. The relay takes the values into memory and refuses a request that carries
one where only a leak could put it; nothing here is written to a file.

    python expected_values.py --difficulty easy --num-samples 10
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--difficulty", required=True)
    p.add_argument("--num-samples", type=int, required=True)
    args = p.parse_args(argv)
    from uuid_ctf.taskset import UUIDCTFConfig, UUIDCTFTaskset

    answers, sources = [], []
    for task in UUIDCTFTaskset(UUIDCTFConfig(difficulty=args.difficulty, num_samples=args.num_samples)).load():
        answers.append(task.data.result_uuid)
        sources.extend(task.data.source_uuids)
    print(json.dumps({"answers": answers, "sources": sources}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
