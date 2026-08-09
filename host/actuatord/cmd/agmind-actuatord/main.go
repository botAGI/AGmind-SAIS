package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	actuatord "agmind.local/sais/host/actuatord"
)

func run(arguments []string) error {
	flags := flag.NewFlagSet("agmind-actuatord", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String(
		"config",
		actuatord.DefaultConfigPath,
		"strict actuator config",
	)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer cancel()
	daemon, err := actuatord.Bootstrap(ctx, *configPath)
	if err != nil {
		return err
	}
	defer daemon.Close()
	return daemon.Run(ctx)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "agmind-actuatord:", err)
		os.Exit(1)
	}
}
