package main

import (
	"context"
	"guardrail-proxy/boundary"
	"guardrail-proxy/enterprise"
	"guardrail-proxy/security"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--health" {
		c, e := net.DialTimeout("tcp", "127.0.0.1:8080", time.Second)
		if e != nil {
			os.Exit(1)
		}
		c.Close()
		return
	}
	workload, err := security.WorkloadFromEnvironment()
	if err != nil {
		log.Fatal("Workload identity unavailable")
	}

	f, err := os.OpenFile("/audit/security.jsonl", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal("Audit storage unavailable")
	}
	defer f.Close()
	if _, err := security.LoadPolicy("/config/policy.json"); err != nil {
		log.Fatal("Policy unavailable")
	}
	log.Fatal(security.ServeWorkload(newServerWithWorkload(f, workload), workload))
}

func newServer(audit io.Writer) *http.Server { return newServerWithWorkload(audit, nil) }

func newServerWithWorkload(audit io.Writer, workload *security.Workload) *http.Server {
	s := &boundary.Server{Auth: security.Registry{File: "/identity/credentials.json", Audience: "loom-local"}, PolicyFile: "/config/policy.json", Audit: &security.Audit{Writer: audit}, Budgets: &security.Budgets{Limits: security.Limits{RequestsPerMinute: 60, Calls: 500, Concurrent: 4, InputBytes: 65536, OutputTokens: 4096, Workflow: time.Hour}}, Client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, ModelURL: "http://agentgateway:8080", MCPURL: "http://agentgateway:3000", GuardURL: "http://guardrail-proxy:9090"}
	if endpoint := os.Getenv("LOOM_OTLP_LOGS_ENDPOINT"); endpoint != "" {
		token := ""
		if path := os.Getenv("LOOM_OTLP_TOKEN_FILE"); path != "" {
			b, err := os.ReadFile(path)
			if err != nil {
				log.Fatal("Telemetry credential unavailable")
			}
			token = string(b)
		}
		events := security.NewOTLPEvents(context.Background(), endpoint, token, nil)
		s.Budgets.Events = events
		s.ModelCircuit.Events = events
		s.ModelCircuit.Resource = "model"
		s.ToolCircuit.Events = events
		s.ToolCircuit.Resource = "mcp"
	}
	if path := os.Getenv("LOOM_MCP_SIGNING_KEY"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			log.Fatal("MCP signing key unavailable")
		}
		s.MCPSigner, err = security.LoadMCPSigner(b)
		if err != nil {
			log.Fatal("Invalid MCP signing key")
		}
	}
	if workload != nil {
		s.Auth = security.WorkloadAuth{Auth: s.Auth, Bindings: workload.Config.IdentityBindings}
		s.Client.Transport = workload
	}
	var handler http.Handler = s
	if path := os.Getenv("LOOM_ENTERPRISE_CONFIG"); path != "" {
		var err error
		handler, err = enterprise.ConfigureWithWorkload(s, path, workload)
		if err != nil {
			log.Fatal("Enterprise configuration unavailable")
		}
	}
	return &http.Server{Addr: ":8080", Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
}
