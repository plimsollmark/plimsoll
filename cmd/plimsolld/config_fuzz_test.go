package main

// Env-parsing fuzz for the daemon's safety configuration: the limiter envelope,
// the startup isolation floor, and the hardened-mode toggle. Safety settings
// must parse fail-closed — a typo can reject startup but must never silently
// weaken or disable a limit.

import (
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox"
)

func FuzzDaemonConfigEnv(f *testing.F) {
	f.Add("8", "4", "30", "30", "2048", "kernel", "docker", "256", "1")
	f.Add("", "", "", "", "", "", "", "", "")
	f.Add("-1", "9999", "1e3", "0x10", "NaN", "VM", "wasm", " 256 ", "yes")
	f.Add("1025", "0", "-5", "", "1", "none", "e2b", "0", "true")
	f.Add("07", "+3", "30\n", "٣", "9223372036854775808", "Kernel ", "docker", "", "1")
	f.Fuzz(func(t *testing.T, maxc, perKey, rate, burst, total, minIso, provider, perRunMem, hardened string) {
		env := map[string]string{
			"SANDBOX_MAX_CONCURRENT":     maxc,
			"SANDBOX_PER_KEY_CONCURRENT": perKey,
			"SANDBOX_RATE_PER_MIN":       rate,
			"SANDBOX_RATE_BURST":         burst,
			"SANDBOX_TOTAL_MEMORY_MB":    total,
			"SANDBOX_MIN_ISOLATION":      minIso,
			"PLIMSOLL_HARDENED":        hardened,
		}
		getenv := func(k string) string { return env[k] }

		env["SANDBOX_MEMORY_MB"] = perRunMem
		perRunMemMB, err := envIntWith(getenv, "SANDBOX_MEMORY_MB", 256)
		if err != nil {
			perRunMemMB = 256 // unparseable per-run memory would already fail Build
		}
		lc, err := loadLimiterConfig(getenv, provider, perRunMemMB)
		if err == nil {
			// An accepted envelope must satisfy the documented bounds exactly.
			if verr := validateLimiterConfig(lc.MaxConcurrent, lc.PerKey, lc.RatePerMin, lc.Burst); verr != nil {
				t.Fatalf("loadLimiterConfig accepted an envelope validate rejects: %+v: %v", lc, verr)
			}
		}

		want, required, err := minimumIsolationWith(getenv)
		if err == nil && required {
			// A configured floor must be a real boundary tier, never None/Unknown.
			if want < sandbox.IsolationProcess || want > sandbox.IsolationVM {
				t.Fatalf("minimumIsolationWith accepted %q as tier %v", minIso, want)
			}
		}

		if on, err := strictBoolEnv(getenv, "PLIMSOLL_HARDENED"); err == nil && on {
			// Hardened may only turn ON for the canonical spellings (case/space
			// normalized) — never for a typo the parser guessed at.
			if norm := strings.ToLower(strings.TrimSpace(hardened)); norm != "1" && norm != "true" {
				t.Fatalf("hardened enabled by unexpected value %q", hardened)
			}
		}

		// The policy itself must never panic on arbitrary env/fact combinations.
		_ = enforceHardenedPolicy(getenv, hardenedFacts{
			Provider:   provider,
			Isolation:  sandbox.ParseIsolationClass(minIso),
			Addr:       maxc, // arbitrary string; loopbackAddr must cope
			RatePerMin: lc.RatePerMin,
		})
	})
}
