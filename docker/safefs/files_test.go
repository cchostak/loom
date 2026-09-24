package safefs

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestExecutionBoundary(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "safe"), []byte("inert fixture"), 0600)
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, []byte("must not read"), 0600)
	os.Symlink(outside, filepath.Join(root, "escape"))
	os.Symlink("safe", filepath.Join(root, "internal-link"))
	os.Mkdir(filepath.Join(root, "dir"), 0700)
	os.Symlink(filepath.Dir(outside), filepath.Join(root, "linkdir"))
	syscall.Mkfifo(filepath.Join(root, "fifo"), 0600)
	os.WriteFile(filepath.Join(root, "large"), bytes.Repeat([]byte("x"), 65537), 0600)
	os.WriteFile(filepath.Join(root, "binary"), []byte{255}, 0600)
	cases := []struct {
		tool, args string
		allowed    bool
	}{
		{"read_text_file", `{"path":"/workspace/safe"}`, true},
		{"list_directory", `{"path":"/workspace"}`, true},
		{"read_text_file", `{"path":"/workspace/escape"}`, false},
		{"read_text_file", `{"path":"/workspace/internal-link"}`, false},
		{"read_text_file", `{"path":"/workspace/linkdir/outside"}`, false},
		{"read_text_file", `{"path":"/workspace/../outside"}`, false},
		{"read_text_file", `{"path":"/etc/passwd"}`, false},
		{"read_text_file", `{"path":"/workspace/fifo"}`, false},
		{"read_text_file", `{"path":"/workspace/large"}`, false},
		{"read_text_file", `{"path":"/workspace/binary"}`, false},
		{"read_text_file", `{"path":"/workspace/safe","command":"inert"}`, false},
		{"write_file", `{"path":"/workspace/new"}`, false},
		{"execute_command", `{"path":"/workspace/safe"}`, false},
		{"list_directory", `{"path":"/workspace/safe"}`, false},
		{"read_text_file", `null`, false},
	}
	for _, tc := range cases {
		t.Run(tc.tool+tc.args, func(t *testing.T) {
			_, err := Execute(root, tc.tool, json.RawMessage(tc.args))
			if tc.allowed != (err == nil) {
				t.Fatal(err)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(root, "new")); !os.IsNotExist(err) {
		t.Fatal("write occurred")
	}
}

func TestMCPProtocol(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "safe"), []byte("safe"), 0600)
	for _, method := range []string{"initialize", "ping", "tools/list", "tools/call", "resources/read", "unknown"} {
		request := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{"name":"read_text_file","arguments":{"path":"/workspace/safe"}}}`
		var out bytes.Buffer
		if err := Serve(strings.NewReader(request+"\n"), &out, root); err != nil {
			t.Fatal(err)
		}
		var response map[string]any
		if json.Unmarshal(out.Bytes(), &response) != nil {
			t.Fatal(out.String())
		}
		if method == "resources/read" || method == "unknown" {
			if response["error"] == nil {
				t.Fatal("method allowed")
			}
		}
		if method == "tools/call" && !strings.Contains(out.String(), `"tainted":true`) {
			t.Fatal("lost provenance")
		}
	}
}

func FuzzMCPParser(f *testing.F) {
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	f.Add(`null`)
	f.Add(`[]`)
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<20 {
			return
		}
		var out bytes.Buffer
		_ = Serve(strings.NewReader(s), &out, t.TempDir())
	})
}
