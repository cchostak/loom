package main

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServerSafeDefaults(t *testing.T) {
	var audit bytes.Buffer
	s := newServer(&audit)
	if s.ReadHeaderTimeout != 5*time.Second {
		t.Fatal("header deadline")
	}
	if s.ReadTimeout != 10*time.Second {
		t.Fatal("read deadline")
	}
	if s.WriteTimeout != 35*time.Second {
		t.Fatal("write deadline")
	}
	if s.IdleTimeout != 30*time.Second {
		t.Fatal("idle deadline")
	}
	if s.MaxHeaderBytes != 16384 {
		t.Fatal("header bound")
	}
	if s.Addr != ":8080" {
		t.Fatal("listener")
	}
	for _, path := range []string{"/mcp", "/v1/chat/completions", "/admin", "/approvals", "/policy", "/unknown"} {
		w := httptest.NewRecorder()
		s.Handler.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(`{}`)))
		if w.Code != 401 {
			t.Fatal(path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}
