package cmd

import (
	"fmt"
	"os"
)

func logProgress(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[cvefix] "+format+"\n", args...)
}
