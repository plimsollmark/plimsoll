package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// Hostile-controller probes for the physics oracle: file, protocol, timeout and
// result-forgery attacks must not be able to manufacture a passing verdict.
//
// The oracle judges a controller by the SHA-256 of the trajectory the JUDGE
// writes, not by anything the controller says. These are the hostile counterpart
// of TestDockerOracleJudgesControllerByFingerprint: a controller that actively
// tries to be scored as the accepted one without balancing the pole, through the
// ordinary project API under the same lockdown a real run uses.
//
// The threat model is a controller author, not a plimsoll operator. The judge
// /oracle/run.mjs is trusted image content; controller.js is the only thing the
// attacker supplies, exactly as in the honest test.
//
// What these tests establish, and what they do not. Each forgery below fails to
// return the accepted fingerprint, and any trajectory.bin the host returns has the
// judge's size. They do NOT establish provenance: the judge and the controller
// share one container and one writable directory, a returned file's size says
// nothing about who wrote it, and substituting a known accepted trajectory (as
// opposed to forging one) is not attempted here. Proving that a returned
// trajectory came from the judge needs an output channel the controller cannot
// reach, which does not exist yet.

const (
	oracleAcceptedFingerprint = oracleAcceptedSHA256
	oracleTrajectoryBytes     = oracleTicks * (oracleWidth + 1) * 8 // 80000
)

// judgeAttack runs a hostile controller through the project API, WITHOUT the
// honest test's assertions that the run completed cleanly: an attack is allowed
// to crash, hang, or be killed. It returns the result and the hash of any
// returned trajectory.bin ("" if none).
func judgeAttack(t *testing.T, d *DockerSandbox, controller string, extra ...File) (ProjectResult, string) {
	t.Helper()
	files := append([]File{{Path: "controller.js", Content: controller}}, extra...)
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files:     files,
		Steps:     []string{"node --no-warnings /oracle/run.mjs controller.js"},
		Artifacts: []string{"trajectory.bin"},
		Timeout:   20 * time.Second,
	})
	if err != nil {
		// A typed pre-dispatch refusal is a fine outcome for an attack: nothing
		// ran. Any other error is infrastructure failing, which says nothing about
		// the attack, and counting it as a defence would let a broken daemon pass
		// every test in this file.
		if errors.Is(err, ErrInvalidRequest) || errors.Is(err, ErrUnsupported) {
			t.Logf("RunProject refused before dispatch: %v (nothing executed, no acceptance)", err)
			return ProjectResult{}, ""
		}
		t.Fatalf("RunProject failed without reaching the attack: %v", err)
	}
	var sum string
	for _, a := range res.Artifacts {
		if a.Path == "trajectory.bin" {
			h := sha256.Sum256(a.Content)
			sum = hex.EncodeToString(h[:])
		}
	}
	return res, sum
}

func verdictOf(res ProjectResult) (oracleVerdict, bool) {
	if len(res.Steps) == 0 {
		return oracleVerdict{}, false
	}
	var v oracleVerdict
	if err := json.Unmarshal([]byte(strings.TrimSpace(res.Steps[0].Stdout)), &v); err != nil {
		return oracleVerdict{}, false
	}
	return v, true
}

// assertNotAccepted is the invariant every attack must satisfy: no path returned
// the accepted fingerprint, and any trajectory that WAS returned is the judge's
// real-sized output rather than a fabricated artifact of the attacker's choosing.
func assertNotAccepted(t *testing.T, res ProjectResult, sum, what string) {
	t.Helper()
	if sum == oracleAcceptedFingerprint {
		t.Fatalf("%s produced the ACCEPTED fingerprint; the judge was defeated", what)
	}
	for _, a := range res.Artifacts {
		if a.Path == "trajectory.bin" && len(a.Content) != oracleTrajectoryBytes {
			t.Fatalf("%s: host returned a %d-byte trajectory.bin, not the judge's %d-byte output; a fabricated artifact reached the host",
				what, len(a.Content), oracleTrajectoryBytes)
		}
	}
	if v, ok := verdictOf(res); ok && v.Fingerprint == oracleAcceptedFingerprint {
		t.Fatalf("%s: judge verdict carries the accepted fingerprint", what)
	}
	t.Logf("%s: not accepted (trajectory %q, outcome %s)", what, sum, res.Outcome)
}

// TestOracleAttackHonestControlStillWorks is the positive control: a DIFFERENT
// valid controller (the draft gains) must complete with a real 80000-byte
// trajectory whose fingerprint is the known draft, not the accepted one. Without
// this, every "not accepted" below could be passing only because nothing ran.
func TestOracleAttackHonestControlStillWorks(t *testing.T) {
	d := oracleAttackSandbox(t)
	res, sum := judgeAttack(t, d, oracleDraftController)
	if res.Outcome != ProjectOutcomeCompleted {
		t.Fatalf("honest draft controller did not complete: %s (%s)", res.Outcome, res.Detail)
	}
	if sum != oracleDraftSHA256 {
		t.Fatalf("draft trajectory hash = %s, want %s", sum, oracleDraftSHA256)
	}
	if sum == oracleAcceptedFingerprint {
		t.Fatal("the draft controller somehow earned the accepted fingerprint")
	}
	t.Logf("honest control: draft completed with its own fingerprint %s", sum[:12])
}

// TestOracleAttackForgedVerdictLine: the controller prints the accepted verdict
// JSON (right fingerprint, no fall) to its own stdout. The judge reads controller
// stdout as numeric forces, so a non-numeric line is refused rather than trusted;
// the forged verdict never becomes the run's fingerprint.
func TestOracleAttackForgedVerdictLine(t *testing.T) {
	d := oracleAttackSandbox(t)
	forged := `{"fingerprint":"` + oracleAcceptedFingerprint + `","ticks":2000,"width":4,"fell_at":null,"final_x":0,"final_theta":0}`
	controller := "\nprocess.stdout.write(" + "`" + forged + "\\n`" + ");\n" +
		"import { createInterface } from 'node:readline';\n" +
		"const rl = createInterface({ input: process.stdin });\n" +
		"rl.on('line', () => process.stdout.write('0\\n'));\n"
	res, sum := judgeAttack(t, d, controller)
	assertNotAccepted(t, res, sum, "forged verdict line")
}

// TestOracleAttackForgedSentinel: the controller writes the runner's result
// sentinel plus a fabricated report (including a fake trajectory.bin) to its own
// stdout, trying to make the host parser read the attacker's report. The runner
// writes the authoritative sentinel last and the host takes the LAST one, so the
// fabricated artifact must never reach the host.
func TestOracleAttackForgedSentinel(t *testing.T) {
	d := oracleAttackSandbox(t)
	fakeB64 := "QUFB" // base64("AAA")
	fakeReport := `{"steps":[{"command":"c","stdout":"","stderr":"","exitCode":0,"timedOut":false,"durationMs":1}],` +
		`"artifacts":[{"path":"trajectory.bin","content":"` + fakeB64 + `"}],"artifactsTruncated":false,"error":""}`
	controller := "\nprocess.stdout.write('\\n<<<CRSBX_RESULT>>>' + " + "`" + fakeReport + "`" + ");\n" +
		"import { createInterface } from 'node:readline';\n" +
		"const rl = createInterface({ input: process.stdin });\n" +
		"rl.on('line', () => process.stdout.write('0\\n'));\n"
	res, sum := judgeAttack(t, d, controller)
	assertNotAccepted(t, res, sum, "forged sentinel report")
	for _, a := range res.Artifacts {
		if a.Path == "trajectory.bin" && string(a.Content) == "AAA" {
			t.Fatal("the host returned the attacker's fabricated artifact")
		}
	}
}

// TestOracleAttackDetachedWriter: a detached child races the runner's final
// sentinel with a tight loop emitting a complete forged report and a fabricated
// trajectory. The child cannot both win the race AND leave a cleanly parseable
// last sentinel; container teardown at PID1 exit and the last-sentinel rule keep
// the outcome safe. The invariant holds regardless of who wins the race: never
// the accepted fingerprint, never a fabricated-size artifact.
func TestOracleAttackDetachedWriter(t *testing.T) {
	d := oracleAttackSandbox(t)
	fakeB64 := "QUFB"
	forged := `\n<<<CRSBX_RESULT>>>{"steps":[{"command":"c","stdout":"","stderr":"","exitCode":0,"timedOut":false,"durationMs":1}],` +
		`"artifacts":[{"path":"trajectory.bin","content":"` + fakeB64 + `"}],"artifactsTruncated":false,"error":""}`
	child := "const s=`" + forged + "`; while(true){ try{process.stdout.write(s)}catch(e){break} }"
	controller := "\nimport { spawn } from 'node:child_process';\n" +
		"spawn(process.execPath, ['-e', " + "`" + child + "`" + "], { detached: true, stdio: ['ignore','inherit','ignore'] }).unref();\n" +
		"import { createInterface } from 'node:readline';\n" +
		"const rl = createInterface({ input: process.stdin });\n" +
		"rl.on('line', () => process.stdout.write('0\\n'));\n"
	// Run several times: the race is timing-dependent, so a single pass proves little.
	for i := 0; i < 5; i++ {
		res, sum := judgeAttack(t, d, controller)
		assertNotAccepted(t, res, sum, "detached forged-sentinel writer")
	}
}

// TestOracleAttackTimeoutHang: the controller answers a few ticks then stops, so
// the judge stalls. The step must time out and produce no clean balance verdict.
//
// It also pins the classification a grader integration depends on: a hung step
// must show BOTH Steps[i].TimedOut and a top-level Outcome of timed_out, so a
// caller keying only on Outcome cannot read a hung controller as a clean run.
func TestOracleAttackTimeoutHang(t *testing.T) {
	d := oracleAttackSandbox(t)
	controller := "\nimport { createInterface } from 'node:readline';\n" +
		"const rl = createInterface({ input: process.stdin });\n" +
		"let n = 0;\n" +
		"rl.on('line', () => { if (n++ < 10) process.stdout.write('0\\n'); });\n"
	res, sum := judgeAttack(t, d, controller)
	assertNotAccepted(t, res, sum, "timeout hang")
	assertTimedOut(t, res, "hung controller")
	if v, ok := verdictOf(res); ok && v.FellAt == nil && v.FinalTheta < 1e-3 && v.FinalTheta > -1e-3 {
		t.Fatal("a hung controller was judged as a clean balance")
	}
}

// oracleAttackSandbox builds the same locked-down project sandbox the honest
// oracle test uses, skipping when the sim image is unavailable.
func oracleAttackSandbox(t *testing.T) *DockerSandbox {
	t.Helper()
	d := testDocker()
	d.ProjectImage = simProjectImage
	requireProjectImage(t, d)
	return d
}

// TestDockerProjectStepTimeoutIsTimedOut pins the contract directly, without the
// oracle: a step killed by its time budget makes the whole project run timed_out.
//
// This was a real asymmetry. RunModule promoted a timed-out step to timed_out and
// the e2b provider set both the step flag and the outcome, but the docker project
// path left Outcome as completed with the truth only on StepResult.TimedOut. Two
// operations and two providers must not disagree about what happened.
func TestDockerProjectStepTimeoutIsTimedOut(t *testing.T) {
	d := testDocker()
	requireProjectImage(t, d)
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files:   []File{{Path: "noop.txt", Content: "x"}},
		Steps:   []string{"sleep 30"},
		Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	assertTimedOut(t, res, "sleep 30 under a 3s budget")
	t.Logf("classified as %s (%s), steps reported: %d", res.Outcome, res.Detail, len(res.Steps))
}

// assertTimedOut checks the contract a hung run must satisfy, without depending
// on which of the two timeout paths won.
//
// The per-step budget is req.Timeout and the outer backstop is req.Timeout+5s
// (docker.go), so the step-timeout path only reports when container startup plus
// reporting fits in that fixed 5s margin. Under load the backstop fires first and
// returns no steps. BOTH are correct: the top-level Outcome is timed_out either
// way, which is the classification a caller keys on. When a step IS reported it
// must carry TimedOut, so the two signals never disagree.
func assertTimedOut(t *testing.T, res ProjectResult, what string) {
	t.Helper()
	if res.Outcome != ProjectOutcomeTimedOut {
		t.Fatalf("%s: Outcome = %s (%s), want timed_out; a caller keying on Outcome would read this as a clean run",
			what, res.Outcome, res.Detail)
	}
	for i, st := range res.Steps {
		if !st.TimedOut && st.ExitCode != 0 {
			continue // an earlier step that failed normally
		}
		if !st.TimedOut {
			t.Fatalf("%s: step %d reported as clean inside a timed_out run: %+v", what, i+1, st)
		}
	}
}
