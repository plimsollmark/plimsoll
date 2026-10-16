// Command devscenario prints the independent trial's development scenario for one adapter
// (package practice): the adapter runs in a locked-down docker sandbox through the docker
// provider's broker, never on the host. Run it from the repository root after
// make docker-images; SANDBOX_DOCKER_RUNTIME=runsc runs it under gVisor. The trial's
// adapters are judged through plimsolld by the example program.
//
//	go run ./examples/adapter/trial/devscenario ADAPTER.js
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/plimsollmark/plimsoll/examples/adapter/trial/practice"
	"github.com/plimsollmark/plimsoll/sandbox"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./examples/adapter/trial/devscenario ADAPTER.js")
		os.Exit(2)
	}
	if err := run(context.Background(), os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "devscenario:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, adapterPath string) error {
	spec, err := os.ReadFile(filepath.Join("examples", "adapter", "vendor", "fleet.openapi.json"))
	if err != nil {
		return fmt.Errorf("run this from the repository root: %w", err)
	}
	harness, err := os.ReadFile(filepath.Join("examples", "adapter", "contract", "harness.js"))
	if err != nil {
		return err
	}
	adapter, err := os.ReadFile(adapterPath)
	if err != nil {
		return err
	}
	seccomp, err := filepath.Abs(filepath.Join("docker", "seccomp.json"))
	if err != nil {
		return err
	}
	// The provider reads only these settings, never the rest of this process's environment.
	env := map[string]string{"SANDBOX_PROVIDER": "docker", "SANDBOX_DOCKER_SECCOMP": seccomp}
	if r := os.Getenv("SANDBOX_DOCKER_RUNTIME"); r != "" {
		env["SANDBOX_DOCKER_RUNTIME"] = r
	}
	p, err := sandbox.Build(func(k string) string { return env[k] })
	if err != nil {
		return err
	}
	if err := p.EnsureReady(ctx); err != nil {
		return fmt.Errorf("docker is not ready (make docker-images?): %w", err)
	}
	res, err := practice.Run(ctx, p.Sandbox, spec, string(harness), string(adapter))
	if err != nil {
		return err
	}
	fmt.Print(res.Text)
	return nil
}
