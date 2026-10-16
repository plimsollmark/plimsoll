// Command plimsoll-mcp is the plimsoll MCP server over stdio, configured from
// PLIMSOLL_* variables (see the README). stdout carries the MCP stream, so
// everything else goes to stderr.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/plimsollmark/plimsoll/clients/mcp/remotehttp"
	"github.com/plimsollmark/plimsoll/clients/mcp/server"
)

// closeGrace bounds closing the sandboxes after the host ends the connection. A host
// may kill the process sooner (Claude Code allows half a second), so each sandbox's
// lifetime, asked of the daemon at its open, is the backstop.
const closeGrace = 5 * time.Second

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Println(server.Name, server.Version)
		return
	}
	if len(os.Args) > 1 {
		if len(os.Args) != 2 {
			fail(2, errors.New("supply one command, with configuration in PLIMSOLL_* variables"))
		}
		if err := remoteCommand(os.Args[1]); err != nil {
			fail(1, err)
		}
		return
	}
	cfg, err := server.FromEnv(os.Getenv)
	if err != nil {
		fail(2, err)
	}
	s, err := server.New(cfg)
	if err != nil {
		fail(2, err)
	}
	// The host ends the server by closing stdin (Run returns) or by a signal. On a
	// signal, calls in progress are cancelled and the sandboxes closed at once, rather
	// than after the MCP session drains: a host that signals kills soon after. SIGHUP
	// too: a terminal closing sends it, and the npm launcher forwards it; unhandled, it
	// would end the process at once, its sandboxes left open until their lifetime.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	served := make(chan error, 1)
	go func() { served <- s.MCP().Run(context.Background(), &mcp.StdioTransport{}) }()
	var runErr error
	select {
	case runErr = <-served:
	case <-signals:
	}
	closing, cancel := context.WithTimeout(context.Background(), closeGrace)
	defer cancel()
	if err := s.Close(closing); err != nil {
		fmt.Fprintf(os.Stderr, "plimsoll-mcp: closing sandboxes: %v\n", err)
	}
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		fail(1, runErr)
	}
}

func remoteCommand(command string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	switch command {
	case "status", "disable", "enable", "enroll", "reset-owner":
		dir := strings.TrimSpace(os.Getenv("PLIMSOLL_MCP_STATE_DIR"))
		operation, stop := context.WithTimeout(ctx, 7*time.Second)
		defer stop()
		result, err := remotehttp.Operator(operation, dir, command)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "serve-http", "enroll-http":
		enrollment := command == "enroll-http"
		var daemon server.Config
		var err error
		if !enrollment {
			daemon, err = server.FromEnv(os.Getenv)
			if err != nil {
				return err
			}
		}
		cfg, err := remotehttp.FromEnv(os.Getenv, daemon, enrollment)
		if err != nil {
			return err
		}
		engine, err := remotehttp.New(cfg)
		if err != nil {
			return err
		}
		defer func() {
			closing, stop := context.WithTimeout(context.Background(), closeGrace)
			defer stop()
			_ = engine.Close(closing)
		}()
		if enrollment {
			code, err := engine.EnrollmentCode()
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Owner enrollment: %s/owner/enroll\nOne-use local enrollment code (expires in five minutes): %s\nOAuth and tools are unavailable in enrollment-only mode.\n", cfg.PublicURL, code)
		}
		fmt.Fprintf(os.Stderr, "plimsoll-mcp: dedicated HTTP listener %s; public routing is configured separately\n", cfg.Listen)
		return engine.Run(ctx)
	default:
		return errors.New("unknown command; use serve-http, enroll-http, enroll, status, disable, enable or reset-owner; no command serves stdio")
	}
}

func fail(code int, err error) {
	fmt.Fprintf(os.Stderr, "plimsoll-mcp: %v\n", err)
	os.Exit(code)
}
