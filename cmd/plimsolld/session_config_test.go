package main

import (
	"testing"
	"time"
)

func TestLoadSessionConfig(t *testing.T) {
	env := func(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }
	c, err := loadSessionConfig(env(nil))
	if err != nil || c.MaxSessions != 0 || c.Lifetime != 30*time.Minute || c.IdleTimeout != 5*time.Minute || c.DiskBytes != 1<<30 {
		t.Fatalf("defaults: %+v, %v", c, err)
	}
	c, err = loadSessionConfig(env(map[string]string{"SANDBOX_MAX_SESSIONS": "3", "SANDBOX_SESSION_LIFETIME": "90s", "SANDBOX_SESSION_IDLE": "0", "SANDBOX_SESSION_DISK_MB": "0"}))
	if err != nil || c.MaxSessions != 3 || c.Lifetime != 90*time.Second || c.IdleTimeout != 0 || c.DiskBytes != 0 {
		t.Fatalf("set: %+v, %v", c, err)
	}
	for _, bad := range []map[string]string{
		{"SANDBOX_MAX_SESSIONS": "-1"},
		{"SANDBOX_MAX_SESSIONS": "two"},
		{"SANDBOX_SESSION_LIFETIME": "30"},
		{"SANDBOX_SESSION_LIFETIME": "13h"},
		{"SANDBOX_SESSION_LIFETIME": "500ms"},
		{"SANDBOX_SESSION_IDLE": "-1s"},
		{"SANDBOX_SESSION_DISK_MB": "-5"},
	} {
		if _, err := loadSessionConfig(env(bad)); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
}
