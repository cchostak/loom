// Workload proxy protects applications that do not implement SPIFFE themselves.
// Plaintext endpoints are loopback-only within the same workload network namespace.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"guardrail-proxy/security"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"time"
)

type listener struct {
	Address string `json:"address"`
	Target  string `json:"target"`
	Peer    string `json:"peer,omitempty"`
}
type configuration struct {
	Workload  string     `json:"workload"`
	Listeners []listener `json:"listeners"`
}

func main() {
	b, err := os.ReadFile(os.Getenv("LOOM_PROXY_CONFIG"))
	if err != nil {
		log.Fatal("Proxy configuration unavailable")
	}
	var config configuration
	if json.Unmarshal(b, &config) != nil {
		log.Fatal("Invalid proxy configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	identity, err := security.OpenWorkload(ctx, config.Workload)
	if err != nil {
		log.Fatal("Workload identity unavailable")
	}
	defer identity.Source.Close()
	for _, endpoint := range config.Listeners {
		var l net.Listener
		if endpoint.Peer == "" {
			host, _, err := net.SplitHostPort(endpoint.Target)
			if err != nil || host != "127.0.0.1" {
				log.Fatal("Inbound proxy target must be loopback")
			}
			l, err = tls.Listen("tcp", endpoint.Address, identity.ServerTLS())
		} else {
			host, _, err := net.SplitHostPort(endpoint.Address)
			if err != nil || host != "127.0.0.1" {
				log.Fatal("Outbound proxy listener must be loopback")
			}
			l, err = net.Listen("tcp", endpoint.Address)
		}
		if err != nil {
			log.Fatal("Workload proxy listener unavailable")
		}
		go serve(l, endpoint, identity)
	}
	if len(os.Args) > 1 {
		// The container entrypoint supplies the fixed application command. No agent
		// tool invokes this launcher and it grants no extra filesystem/network access.
		command := exec.Command(os.Args[1], os.Args[2:]...)
		command.Stdin = os.Stdin
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if err := command.Run(); err != nil {
			os.Exit(1)
		}
		return
	}
	select {}
}
func serve(l net.Listener, endpoint listener, identity *security.Workload) {
	for {
		incoming, err := l.Accept()
		if err != nil {
			return
		}
		go func(incoming net.Conn) {
			var err error
			defer incoming.Close()
			var outgoing net.Conn
			if secured, ok := incoming.(*tls.Conn); ok {
				if secured.Handshake() != nil {
					return
				}
				state := secured.ConnectionState()
				if len(state.PeerCertificates) == 0 {
					return
				}
				_ = incoming.SetDeadline(state.PeerCertificates[0].NotAfter)
			}
			if endpoint.Peer == "" {
				outgoing, err = net.DialTimeout("tcp", endpoint.Target, 3*time.Second)
			} else {
				outgoing, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", endpoint.Target, identity.ClientTLS(endpoint.Peer))
			}
			if err != nil {
				return
			}
			defer outgoing.Close()
			if secured, ok := outgoing.(*tls.Conn); ok {
				state := secured.ConnectionState()
				if len(state.PeerCertificates) > 0 {
					_ = outgoing.SetDeadline(state.PeerCertificates[0].NotAfter)
				}
			}
			done := make(chan struct{}, 1)
			go func() { _, _ = io.Copy(outgoing, incoming); done <- struct{}{} }()
			go func() { _, _ = io.Copy(incoming, outgoing); done <- struct{}{} }()
			<-done
		}(incoming)
	}
}
