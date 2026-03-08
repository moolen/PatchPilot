package main

import (
	"fmt"
	"os"

	"github.com/moolen/patchpilot/cmd"
)

func main() {
	if err := cmd.Execute(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(cmd.ExitCodeFromError(err))
	}
}
