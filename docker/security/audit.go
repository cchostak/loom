package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

// SecurityEvent intentionally has no free-form headers, arguments or content.
// Resource digest supports matching evidence without exposing sensitive paths.
type SecurityEvent struct {
	Timestamp    time.Time      `json:"timestamp"`
	TraceID      string         `json:"trace_id"`
	Decision     PolicyDecision `json:"decision"`
	Principal    string         `json:"principal"`
	Workload     string         `json:"workload"`
	Tenant       string         `json:"tenant"`
	Session      string         `json:"session"`
	ActionDigest string         `json:"action_digest"`
	Stage        string         `json:"stage"`
	Status       int            `json:"status"`
}

type Audit struct {
	mu     sync.Mutex
	Writer io.Writer
}

// Record serializes only trusted identity and policy fields. Failed intent
// writes are fatal to dispatch; a later result-write error cannot undo a read.
func (a *Audit) Record(action ActionRequest, d PolicyDecision, trace, stage string, status int) error {
	b, _ := json.Marshal(action)
	digest := sha256.Sum256(b)
	e := SecurityEvent{time.Now().UTC(), trace, d, action.Identity.Principal, action.Identity.Workload, action.Identity.Tenant, action.Identity.Session, hex.EncodeToString(digest[:]), stage, status}
	a.mu.Lock()
	defer a.mu.Unlock()
	if file, ok := a.Writer.(*os.File); ok {
		info, err := file.Stat()
		if err != nil || info.Size() >= 100<<20 {
			return errors.New("audit capacity")
		}
	}
	if err := json.NewEncoder(a.Writer).Encode(e); err != nil {
		return err
	}
	if syncer, ok := a.Writer.(interface{ Sync() error }); ok {
		return syncer.Sync()
	}
	return nil
}
