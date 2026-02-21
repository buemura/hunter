package main

import (
	"os"

	"github.com/buemura/hunter/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
