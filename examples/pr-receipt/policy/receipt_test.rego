# Tests of receipt.rego, run with the pinned OPA: opa test examples/pr-receipt/policy
# (make policy-suite runs them). The input is the shape verify.py writes
# (input.schema.json); policy_test.go checks verify.py writes that shape.
package plimsoll.receipt_test

import data.plimsoll.receipt

honest := {
	"plimsoll_policy_input": 1,
	"receipt_sha256": "00",
	"signer": "trusted_key",
	"checks": {"signature": true, "head": true, "junit": true, "result": true, "tests": true},
	"subject": {"repository": "example/project", "commit": "d572360a8aeaf91a367addf59513e5ed05c1e229", "pull_request": "7", "base": "", "agent_sessions": []},
	"request": {"protocol": 4, "minimum_isolation": "kernel", "minimum_isolation_rank": 3, "timeout_ms": 30000, "steps": ["npm test"], "artifacts": [], "trace_id": "pr-receipt-7"},
	"result": {
		"provider": "docker", "isolation": "kernel", "isolation_rank": 3, "outcome": "completed",
		"environment": "", "software_identity": "", "duration_ms": 784,
		"steps": [{"command": "npm test", "exit_code": 0, "timed_out": false, "duration_ms": 282}],
		"artifacts": [], "artifacts_truncated": false
	},
	"record": {"version": 4, "record_sha256": "00", "request_sha256": "00", "result_sha256": "00", "started_unix_ms": 1, "ended_unix_ms": 2, "session": "", "instance": ""}
}

with_result(changes) := json.patch(honest, [{"op": "replace", "path": sprintf("/result/%s", [k]), "value": v} | some k, v in changes])

test_an_honest_passing_run_is_not_denied if {
	count(receipt.deny) == 0 with input as honest
}

test_a_vm_run_is_not_denied if {
	r := with_result({"isolation": "vm", "isolation_rank": 4})
	count(receipt.deny) == 0 with input as r
}

test_a_container_run_is_denied if {
	r := with_result({"isolation": "container", "isolation_rank": 2})
	"the run reports the container tier; this repository requires kernel or stronger" in receipt.deny with input as r
}

test_a_tier_below_the_requested_floor_is_denied if {
	r := json.patch(honest, [
		{"op": "replace", "path": "/request/minimum_isolation", "value": "vm"},
		{"op": "replace", "path": "/request/minimum_isolation_rank", "value": 4}
	])
	"the run reports the kernel tier, below the vm floor it asked for" in receipt.deny with input as r
}

test_an_unknown_tier_is_denied if {
	r := with_result({"isolation": "", "isolation_rank": -1})
	"the run reports the  tier; this repository requires kernel or stronger" in receipt.deny with input as r
}

test_a_failed_verifier_check_is_denied if {
	r := json.patch(honest, [{"op": "replace", "path": "/checks/junit", "value": false}])
	"the verifier's junit check did not pass" in receipt.deny with input as r
}

test_a_failed_tests_check_is_denied if {
	r := json.patch(honest, [{"op": "replace", "path": "/checks/tests", "value": false}])
	"the verifier's tests check did not pass" in receipt.deny with input as r
}

test_a_runner_failure_is_denied if {
	r := with_result({"outcome": "runner_failed"})
	denied := receipt.deny with input as r
	"the runner inside the sandbox failed" in denied
	"the run did not complete: runner_failed" in denied
}

test_a_failing_step_is_denied if {
	r := with_result({"steps": [{"command": "npm test", "exit_code": 1, "timed_out": false, "duration_ms": 9}]})
	"step 1 exited 1" in receipt.deny with input as r
}

test_a_timed_out_step_is_denied if {
	r := with_result({"steps": [{"command": "npm test", "exit_code": 124, "timed_out": true, "duration_ms": 30000}]})
	"step 1 timed out" in receipt.deny with input as r
}

test_a_missing_step_is_denied if {
	r := with_result({"steps": []})
	"0 of 1 steps ran" in receipt.deny with input as r
}
