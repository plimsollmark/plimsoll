"""The verifiers harness id ``plimsoll-bash`` (verifiers imports a harness by its id as a
top-level module): verifiers' own bash harness with its chat loop on the evaluator, each tool
call one call of the runtime. See :mod:`plimsoll_client.verifiers_harness`."""

from plimsoll_client.verifiers_harness import PlimsollBashHarness

__all__ = ["PlimsollBashHarness"]
