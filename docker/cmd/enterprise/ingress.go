package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// ingress publishes fixed local lab endpoints without giving workloads an
// external Docker network. It cannot select arbitrary upstreams from a request.
func ingress() {
	routes := map[string]string{":8080": "http://control-plane:8080", ":8081": "http://control-plane-b:8080", ":8555": "http://issuer:8080", ":8686": "http://jaeger:16686"}
	for address, target := range routes {
		u, _ := url.Parse(target)
		proxy := httputil.NewSingleHostReverseProxy(u)
		proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) { http.Error(w, "Lab service unavailable", 503) }
		server := &http.Server{Addr: address, Handler: proxy, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 40 * time.Second, MaxHeaderBytes: 32768}
		go func() {
			if server.ListenAndServe() != nil {
				log.Fatal("Lab ingress stopped")
			}
		}()
	}
	select {}
}
