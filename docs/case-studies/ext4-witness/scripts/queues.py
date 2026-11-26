#!/usr/bin/env python3
"""queues.py: write the job queue witness.py runs, for one part of the ext4 case study. Standard library only.

  python3 queues.py merge     the whole ext4 KUnit suite at the pull's tip and at the merge
  python3 queues.py config    the same question under two kernel configurations, and on the ext4 dev tip
  python3 queues.py masking   the 337c173f check: fixes reverted alone and in pairs, watching migrate-test.c:1351
  python3 queues.py fixes     each of the pull's 48 Fixes:-tagged code commits reverted at the tip, the whole suite

The queue goes to standard output as JSON. Every commit below is public: the pull and the merge are in Linus's tree
(github.com/torvalds/linux), the dev tip is in the ext4 tree (git.kernel.org, tytso/ext4.git, branch dev).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

TIP = "bae28a1b11f422d0214654800d9425e042295c71"    # the ext4 pull for 7.4-rc5, its last commit
MERGE = "4dce97c6c265544342e716e62fd24bbb232590c5"  # Linus's merge of that pull, 2026-11-24
DEV = "ad592b92d6774cb520d1492bf17685fb5eede99d"    # ext4 dev: the merge, then Ted Ts'o's two KUnit fixes

FIX_337C = "337c173f966c1fbb1aad6dfdf4243323e3b7e304"  # don't free the tmp_inode tree after a partial migration swap
FIX_6BDA = "6bda1a98b7ce2f88a0e206756999f608f8437722"  # the later fix that empties the same tree first
FIX_BFB8 = "bfb8f5ce8815bb99770e355a916348df98181f18"  # drop tmp inode ownership before migration cleanup
WATCH = ["fs/ext4/migrate-test.c:1351"]                # KUNIT_EXPECT_FALSE(test, migrate_was_freed(ctx, ext_idx_pblk))


def merge():
    return {"tip": TIP, "jobs": [{"id": "tip-bae28a1b", "form": "plain", "commit": TIP},
                                 {"id": "merge-4dce97c6", "form": "plain", "commit": MERGE}]}


def config():
    names = ["CONFIG_USER_NS", "CONFIG_NAMESPACES"]
    cases = [("merge-suite-config", MERGE, []), ("dev-suite-config", DEV, []),
             ("tip-user-ns", TIP, ["CONFIG_USER_NS=y"]), ("merge-user-ns", MERGE, ["CONFIG_USER_NS=y"]),
             ("dev-user-ns", DEV, ["CONFIG_USER_NS=y"])]
    return {"tip": TIP, "jobs": [{"id": cid, "form": "plain", "commit": c, "kconfig_add": add,
                                  "report_config": [n for n in names if not any(a.startswith(n + "=") for a in add)]}
                                 for cid, c, add in cases]}


def masking():
    cases = [("revert-337c173f", [FIX_337C]), ("revert-6bda1a98", [FIX_6BDA]), ("revert-bfb8f5ce", [FIX_BFB8]),
             ("revert-337c173f-6bda1a98", [FIX_6BDA, FIX_337C]), ("revert-337c173f-bfb8f5ce", [FIX_337C, FIX_BFB8])]
    jobs = [{"id": cid, "form": "revert", "fix": revert[-1] if cid == "revert-337c173f-6bda1a98" else revert[0],
             "revert": revert, "suite": "ext4_migrate_test", "watch": WATCH} for cid, revert in cases]
    # The tip's whole suite once more at the end, as a control.
    jobs.append({"id": "tip-control", "form": "plain", "commit": TIP})
    return {"tip": TIP, "jobs": jobs}


def fixes():
    with open(os.path.join(HERE, "fixes.json")) as f:
        rows = json.load(f)["fixes"]
    return {"tip": TIP, "jobs": [{"id": "fix-" + r["fix"][:12], "form": "revert", "fix": r["fix"], "suite": None}
                                 for r in rows]}


if __name__ == "__main__":
    kinds = {"merge": merge, "config": config, "masking": masking, "fixes": fixes}
    if len(sys.argv) != 2 or sys.argv[1] not in kinds:
        sys.exit("usage: queues.py " + "|".join(kinds))
    json.dump(kinds[sys.argv[1]](), sys.stdout, indent=1)
    sys.stdout.write("\n")
