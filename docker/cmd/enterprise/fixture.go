package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

func fixture() {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer "+key("LOOM_PROVIDER_KEY_FILE") {
			http.Error(w, "denied", 403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "fixture", "object": "chat.completion", "created": 0, "model": body["model"], "choices": []any{map[string]any{"index": 0, "message": map[string]string{"role": "assistant", "content": "Enterprise lab response"}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}})
	})
	server := &http.Server{Addr: ":8443", Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 35 * time.Second}
	log.Fatal(server.ListenAndServeTLS(required("LOOM_TLS_CERT"), required("LOOM_TLS_KEY")))
}
