package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	os.Exit(run())
}

// run executes the CLI under a context cancelled by Ctrl-C (os.Interrupt) or
// SIGTERM. On Windows, Go delivers console close, logoff, and shutdown events
// as SIGTERM, so a scan stopped by the host also shuts down cleanly.
// Cancellation stops in-flight requests, flushes and syncs the checkpoint
// journal and content file, and leaves a resumable journal. After the first
// signal default handling is restored, so a second one terminates immediately.
func run() int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	go func() {
		select {
		case <-sigs:
			signal.Reset(os.Interrupt, syscall.SIGTERM)
			fmt.Fprintln(os.Stderr, "Interrupt received: stopping collection and closing the checkpoint journal (send again to force quit).")
			cancel()
		case <-ctx.Done():
		}
	}()

	if err := newRootCommand().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	return 0
}
