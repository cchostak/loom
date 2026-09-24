package main

import (
	"net/http"
	"os"
	"syscall"
	"time"

	"guardrail-proxy/safefs"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--health" {
		if !healthy("http://localhost:8080/v1/models") {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--isolated" {
		// Re-exec before reading any untrusted bytes. The new process's initial
		// environment (including /proc/self/environ) contains no provider credential.
		if syscall.Exec(os.Args[0], []string{os.Args[0]}, []string{}) != nil {
			os.Exit(1)
		}
		return
	}
	os.Clearenv()
	if safefs.Serve(os.Stdin, os.Stdout, "/workspace") != nil {
		os.Exit(1)
	}
}

func healthy(url string) bool {
	client := http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}
