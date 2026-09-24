package main

import (
	"guardrail-proxy/safefs"
	"os"
)

func main() {
	// Drop inherited provider credentials before processing any untrusted bytes.
	os.Clearenv()
	if safefs.Serve(os.Stdin, os.Stdout, "/workspace") != nil {
		os.Exit(1)
	}
}
