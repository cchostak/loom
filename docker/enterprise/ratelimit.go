package enterprise

import (
	"context"
	"database/sql"
	rl "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

type RateLimit struct {
	rl.UnimplementedRateLimitServiceServer
	Store *Store
}

// ShouldRateLimit implements Agentgateway's actual Envoy remote rate-limit API.
// A missing/malformed descriptor denies; only Loom-signed descriptors have identity.
func (r *RateLimit) ShouldRateLimit(_ context.Context, q *rl.RateLimitRequest) (*rl.RateLimitResponse, error) {
	deny := &rl.RateLimitResponse{OverallCode: rl.RateLimitResponse_OVER_LIMIT}
	if q.Domain != "loom-enterprise" || len(q.Descriptors) != 1 || len(q.Descriptors[0].Entries) != 1 || q.HitsAddend > 1 {
		return deny, nil
	}
	entry := q.Descriptors[0].Entries[0]
	if entry.Key != "dispatch" {
		return deny, nil
	}
	p, err := Verify(r.Store.Key, entry.Value)
	if err != nil {
		return deny, nil
	}
	_, err = r.Store.transaction(func(tx *sql.Tx) (any, error) {
		if active(tx, p.Identity) != nil {
			return nil, denied
		}
		now := time.Now().Unix()
		window := now / 60
		if _, err := tx.Exec(`DELETE FROM nonces WHERE expires<=?`, now); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`INSERT INTO nonces VALUES (?,?)`, "rl:"+p.ID, p.ExpiresAt.Unix()); err != nil {
			return nil, denied
		}
		key := p.Identity.Tenant + "/" + p.Identity.Principal + "/" + p.Identity.Workload
		var previous int64
		var count int
		err := tx.QueryRow(`SELECT window,count FROM rates WHERE key=?`, key).Scan(&previous, &count)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		if previous != window {
			count = 0
		}
		if count >= r.Store.Rate {
			return nil, denied
		}
		_, err = tx.Exec(`INSERT INTO rates VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET window=excluded.window,count=excluded.count`, key, window, count+1)
		return nil, err
	})
	if err == denied {
		return deny, nil
	}
	if err != nil {
		return nil, status.Error(codes.Unavailable, "quota storage unavailable")
	}
	return &rl.RateLimitResponse{OverallCode: rl.RateLimitResponse_OK}, nil
}
