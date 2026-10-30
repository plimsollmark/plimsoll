# An example policy over a pull request's receipt, for verify.py --policy.
#
# verify.py evaluates data.plimsoll.receipt.deny, a set of strings, only after it checked
# the operator's signature and that the run tested this pull request's head commit, and
# only over facts from the signed run (input.schema.json beside this file lists them).
# Each string is a refusal shown in the report; an empty set adds none. A policy can only
# refuse: verify.py's own checks still decide, so a policy cannot accept a receipt they
# refuse. Copy this file and change the rules; keep the package name.
package plimsoll.receipt

# The weakest tier this repository accepts, ranked as input.result.isolation_rank:
# 3 is kernel (gVisor, a kernel written for sandboxes), 4 is vm.
minimum_rank := 3

# The tier the run reports is at least the floor it asked for when it was sent.
deny contains msg if {
	input.result.isolation_rank < input.request.minimum_isolation_rank
	msg := sprintf("the run reports the %s tier, below the %s floor it asked for", [input.result.isolation, input.request.minimum_isolation])
}

# ...and at least this repository's floor, whatever the run asked for.
deny contains msg if {
	input.result.isolation_rank < minimum_rank
	msg := sprintf("the run reports the %s tier; this repository requires kernel or stronger", [input.result.isolation])
}

# Every check the verifier made passed (the signature and the head always have, or this
# policy would not be running).
deny contains msg if {
	some name, passed in input.checks
	not passed
	msg := sprintf("the verifier's %s check did not pass", [name])
}

# The runner itself failed: nothing about the tests is known.
deny contains "the runner inside the sandbox failed" if {
	input.result.outcome == "runner_failed"
}

# The run completed: no setup failure, timeout or protocol error.
deny contains msg if {
	input.result.outcome != "completed"
	msg := sprintf("the run did not complete: %s", [input.result.outcome])
}

# Every step ran, exited 0 and did not time out.
deny contains msg if {
	count(input.result.steps) != count(input.request.steps)
	msg := sprintf("%d of %d steps ran", [count(input.result.steps), count(input.request.steps)])
}

deny contains msg if {
	some i, step in input.result.steps
	step.exit_code != 0
	msg := sprintf("step %d exited %d", [i + 1, step.exit_code])
}

deny contains msg if {
	some i, step in input.result.steps
	step.timed_out
	msg := sprintf("step %d timed out", [i + 1])
}
