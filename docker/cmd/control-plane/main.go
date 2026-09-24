package main

import (
	"guardrail-proxy/boundary"
	"guardrail-proxy/security"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	f, err := os.OpenFile("/audit/security.jsonl", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal("Audit storage unavailable")
	}
	defer f.Close()
	if _, err := security.LoadPolicy("/config/policy.json"); err != nil {
		log.Fatal("Policy unavailable")
	}
	log.Fatal(newServer(f).ListenAndServe())
}

func newServer(audit io.Writer) *http.Server {
	s := &boundary.Server{Auth: security.Registry{File: "/identity/credentials.json", Audience: "loom-local"}, PolicyFile: "/config/policy.json", Audit: &security.Audit{Writer: audit}, Budgets: &security.Budgets{Limits: security.Limits{RequestsPerMinute: 60, Calls: 500, Concurrent: 4, InputBytes: 65536, OutputTokens: 4096, Workflow: time.Hour}}, Client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, ModelURL: "http://agentgateway:8080", MCPURL: "http://agentgateway:3000", GuardURL: "http://guardrail-proxy:9090"}
	return &http.Server{Addr: ":8080", Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
}
