"""plimsoll-sum: the smallest verifiers environment that needs a sandbox. A file to read, an
answer to write, a hidden check staged only into the grading sandbox (``stage_verifier``),
and isolated grading, so a validation run opens a solver sandbox and a fresh grader. Nothing
in it names plimsoll: it runs on any runtime that declares task images, and docker_check.py
runs it on the plimsoll runtime through ``vf-validate``, with no model."""

import verifiers.v1 as vf

__all__ = ["PlimsollSumTaskset"]

# The hidden check, written into the grading sandbox only: the answer must be the input's
# sum and nothing else. POSIX sh and awk, so it runs in a BusyBox image.
CHECK = b"""expected=$(awk '{ s += $1 } END { print s }' input.txt)
if [ "$(cat output/answer.txt)" = "$expected" ]; then echo 1; else echo 0; fi
"""


class PlimsollSumTask(vf.Task[vf.TaskData]):
    NEEDS_CONTAINER = True

    async def setup(self, runtime: vf.Runtime) -> None:
        await runtime.write("input.txt", b"1\n2\n3\n")
        # An untouched task scores zero instead of failing on a missing file.
        await runtime.write("output/answer.txt", b"")

    async def stage_verifier(self, runtime: vf.Runtime) -> None:
        await runtime.write(".grader/check.sh", CHECK)

    @vf.reward
    async def correct(self, runtime: vf.Runtime) -> float:
        result = await runtime.run(["sh", ".grader/check.sh"], {})
        if result.exit_code:
            raise RuntimeError(f"the check failed to run: {result.stderr.strip()}")
        return float(result.stdout.strip() == "1")

    async def validate(self, runtime: vf.Runtime) -> bool:
        await runtime.write("output/answer.txt", b"6\n")
        await self.stage_verifier(runtime)
        return await self.correct(runtime) == 1.0


class PlimsollSumTaskset(vf.Taskset[PlimsollSumTask, vf.TasksetConfig]):
    def load(self) -> list[PlimsollSumTask]:
        return [
            PlimsollSumTask(
                vf.TaskData(
                    name="sum-input",
                    prompt="Sum the integers in input.txt. Write only the sum to output/answer.txt.",
                    scoring=vf.ScoringConfig(mode="isolated"),
                    artifacts=[vf.Artifact(source="output")],
                ),
                self.config.task,
            )
        ]
