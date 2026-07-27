package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	observerd "agmind.local/sais/host/observerd"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: agmind-observerd [--config PATH]")
	fmt.Fprintln(
		os.Stderr,
		"       agmind-observerd key rotate [--config PATH]",
	)
}

func configFlag(name string, arguments []string) (string, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := flags.String("config", observerd.DefaultConfigPath, "strict observer config")
	if err := flags.Parse(arguments); err != nil {
		return "", err
	}
	if flags.NArg() != 0 {
		return "", fmt.Errorf("unexpected arguments")
	}
	return *config, nil
}

func run(arguments []string) error {
	if len(arguments) >= 2 && arguments[0] == "key" && arguments[1] == "rotate" {
		config, err := configFlag("key rotate", arguments[2:])
		if err != nil {
			return err
		}
		return observerd.RotateKeys(config)
	}
	if len(arguments) > 0 && (arguments[0] == "help" || arguments[0] == "--help") {
		usage()
		return nil
	}
	config, err := configFlag("agmind-observerd", arguments)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer cancel()
	daemon, err := observerd.Bootstrap(ctx, config)
	if err != nil {
		return err
	}
	defer daemon.Close()
	<-ctx.Done()
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "agmind-observerd:", err)
		os.Exit(1)
	}
}
