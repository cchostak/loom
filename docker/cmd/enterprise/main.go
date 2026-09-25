package main

import (
	"crypto/tls"
	"crypto/x509"
	rl "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"guardrail-proxy/enterprise"
	"guardrail-proxy/security"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

func required(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatal("Missing configuration: " + name)
	}
	return v
}
func key(name string) string {
	b, e := os.ReadFile(required(name))
	if e != nil || len(b) < 32 {
		log.Fatal("Missing secret: " + name)
	}
	return string(b)
}
func main() {
	workload, err := security.WorkloadFromEnvironment()
	if err != nil {
		log.Fatal("Workload identity unavailable")
	}
	mode := required("LOOM_SERVICE_MODE")
	if mode == "ingress" {
		ingress()
		return
	}
	if mode == "fixture" {
		fixture()
		return
	}
	store, err := enterprise.Open(required("LOOM_DB"), []byte(key("LOOM_SIGNING_KEY_FILE")))
	if err != nil {
		log.Fatal("State storage unavailable")
	}
	defer store.DB.Close()
	audit := enterprise.Remote{}
	if mode != "audit" && mode != "normalizer" {
		audit = enterprise.Remote{URL: required("LOOM_AUDIT_URL"), Token: key("LOOM_AUDIT_TOKEN_FILE")}
		store.Audit = func(v any) error { return audit.Call("/events", v, nil) }
	}
	var handler http.Handler
	if mode == "normalizer" {
		handler = enterprise.Normalizer{Store: store, IngestToken: key("LOOM_SERVICE_TOKEN_FILE"), ReadToken: key("LOOM_READ_TOKEN_FILE")}
	} else if mode == "connector" {
		proxy, err := url.Parse(required("LOOM_PROXY"))
		if err != nil {
			log.Fatal("Invalid proxy")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			log.Fatal("System roots unavailable")
		}
		if path := os.Getenv("LOOM_CA_FILE"); path != "" {
			b, err := os.ReadFile(path)
			if err != nil || !roots.AppendCertsFromPEM(b) {
				log.Fatal("Invalid provider CA")
			}
		}
		client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}}
		handler = enterprise.Connector{Store: store, State: enterprise.Remote{URL: required("LOOM_STATE_URL"), Token: key("LOOM_STATE_TOKEN_FILE")}, Audit: audit, Client: client, URL: required("LOOM_PROVIDER_URL"), ProviderKey: key("LOOM_PROVIDER_KEY_FILE")}
	} else {
		handler = enterprise.Service{Store: store, Token: key("LOOM_SERVICE_TOKEN_FILE"), Mode: mode}
		if mode == "state" {
			if value := os.Getenv("LOOM_RATE_LIMIT"); value != "" {
				n, err := strconv.Atoi(value)
				if err != nil || n < 1 {
					log.Fatal("Invalid rate limit")
				}
				store.Rate = n
			}
			listener, err := net.Listen("tcp", ":8081")
			if err != nil {
				log.Fatal("Quota listener unavailable")
			}
			options := []grpc.ServerOption{grpc.MaxRecvMsgSize(65536)}
			if workload != nil {
				options = append(options, grpc.Creds(credentials.NewTLS(workload.ServerTLS())))
			}
			rpc := grpc.NewServer(options...)
			rl.RegisterRateLimitServiceServer(rpc, &enterprise.RateLimit{Store: store})
			go func() {
				if rpc.Serve(listener) != nil {
					log.Fatal("Quota server unavailable")
				}
			}()
		}
	}
	server := &http.Server{Addr: ":8080", Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 35 * time.Second, MaxHeaderBytes: 32768}
	log.Fatal(security.ServeWorkload(server, workload))
}
