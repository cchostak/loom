package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestStdioProcess(t *testing.T) {
	if os.Getenv("LOOM_TEST_PROCESS") == "1" {
		main()
		return
	}
	for _, method := range []string{"initialize", "ping", "tools/list", "unknown", "resources/read", "tools/call"} {
		t.Run(method, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestStdioProcess$")
			cmd.Env = append(os.Environ(), "LOOM_TEST_PROCESS=1", "OPENROUTER_API_KEY=synthetic-not-a-key")
			cmd.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"` + method + `"}` + "\n")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(out, []byte(`"jsonrpc":"2.0"`)) || bytes.Contains(out, []byte("synthetic-not-a-key")) {
				t.Fatal("bad protocol or credential leak")
			}
		})
	}
}

func TestHealthProbe(t *testing.T) {
	for _, status := range []int{200, 204, 301, 401, 403, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer server.Close()
			if healthy(server.URL) != (status == 200) {
				t.Fatal(status)
			}
		})
	}
	if healthy("http://127.0.0.1:1") {
		t.Fatal("outage")
	}
}
