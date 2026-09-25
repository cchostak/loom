package enterprise

import (
	"bytes"
	"encoding/json"
	"errors"
	"guardrail-proxy/security"
	"io"
	"net/http"
	"time"
)

type Remote struct {
	URL, Token string
	Client     *http.Client
}

func (r Remote) Call(route string, q any, result any) error {
	b, err := json.Marshal(q)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, r.URL+route, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.Token)
	req.Header.Set("Content-Type", "application/json")
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	res, err := client.Do(req)
	if err != nil {
		return errors.New("enterprise service unavailable")
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	if err != nil || len(data) > 65536 || res.StatusCode != 200 {
		return errors.New("enterprise operation denied")
	}
	if result != nil {
		return json.Unmarshal(data, result)
	}
	return nil
}

// Acquire reserves lifetime operations/output capacity durably before dispatch.
// Reservations are never refunded by a failed or missing provider response.
func (r Remote) Acquire(key string, size, tokens int, _ time.Time) (func(), error) {
	var lease struct {
		ID string `json:"id"`
	}
	err := r.Call("/budget/acquire", Request{Key: key, Size: size, Tokens: tokens}, &lease)
	if err != nil || lease.ID == "" {
		return nil, errors.New("shared budget unavailable")
	}
	return func() { _ = r.Call("/budget/release", Request{ID: lease.ID}, nil) }, nil
}

type ActiveAuth struct {
	Auth  security.Authenticator
	State Remote
}

func (a ActiveAuth) Authenticate(req *http.Request) (security.IdentityContext, error) {
	id, err := a.Auth.Authenticate(req)
	if err != nil {
		return id, err
	}
	if err = a.State.Call("/active", Request{Identity: id}, nil); err != nil {
		return security.IdentityContext{}, err
	}
	return id, nil
}

type AuditWriter struct{ Remote Remote }

func (w AuditWriter) Write(b []byte) (int, error) {
	var event security.SecurityEvent
	if security.Decode(b, &event) != nil {
		return 0, errors.New("invalid audit record")
	}
	if err := w.Remote.Call("/events", event, nil); err != nil {
		return 0, err
	}
	return len(b), nil
}
