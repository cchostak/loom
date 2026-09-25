package enterprise

import (
	"database/sql"
	"guardrail-proxy/security"
	"time"
)

// action deliberately implements only an inert receipt. The receipt and one-use
// consumption commit together; no external action is claimed to be exactly once.
func (s *Store) action(tx *sql.Tx, route string, q Request) (any, error) {
	if s.Audit == nil {
		return nil, denied
	}
	now := time.Now().Unix()
	if route == "/actions/propose" {
		if !has(q.Identity, "action:propose") || len(q.Content) == 0 || len(q.Content) > 4096 {
			return nil, denied
		}
		id := security.NewID()
		if err := s.Audit(map[string]string{"event": "action_proposed", "id": id, "tenant": q.Identity.Tenant, "actor": q.Identity.Principal}); err != nil {
			return nil, err
		}
		_, err := tx.Exec(`INSERT INTO actions(id,tenant,requester,session,body,version,expires,approver) VALUES (?,?,?,?,?,1,?,'')`, id, q.Identity.Tenant, q.Identity.Principal, q.Identity.Session, q.Content, now+300)
		return map[string]any{"id": id, "kind": "inert-receipt", "expires": now + 300}, err
	}
	var tenant, requester, session, body, approver string
	var version, used, revoked int
	var expires int64
	if tx.QueryRow(`SELECT tenant,requester,session,body,version,expires,approver,used,revoked FROM actions WHERE id=?`, q.ID).Scan(&tenant, &requester, &session, &body, &version, &expires, &approver, &used, &revoked) != nil {
		return nil, denied
	}
	if tenant != q.Identity.Tenant || expires <= now || used != 0 || revoked != 0 || q.Content != "" || version != 1 {
		return nil, denied
	}
	// Reauthorize the original requester as well as the current caller.
	original := security.IdentityContext{Tenant: tenant, Principal: requester, Session: session}
	if active(tx, original) != nil {
		return nil, denied
	}
	if route == "/actions/approve" || route == "/actions/revoke" {
		if !has(q.Identity, "operator:approve") || q.Identity.Principal == requester {
			return nil, denied
		}
		if s.Audit(map[string]string{"event": route, "id": q.ID, "tenant": tenant, "actor": q.Identity.Principal}) != nil {
			return nil, denied
		}
		if route == "/actions/revoke" {
			_, err := tx.Exec(`UPDATE actions SET revoked=1 WHERE id=?`, q.ID)
			return map[string]bool{"revoked": true}, err
		}
		if approver != "" {
			return nil, denied
		}
		_, err := tx.Exec(`UPDATE actions SET approver=? WHERE id=?`, q.Identity.Principal, q.ID)
		return map[string]bool{"approved": true}, err
	}
	if !has(q.Identity, "action:propose") || q.Identity.Principal != requester || q.Identity.Session != session || approver == "" {
		return nil, denied
	}
	if active(tx, security.IdentityContext{Tenant: tenant, Principal: approver}) != nil {
		return nil, denied
	}
	if s.Audit(map[string]string{"event": "inert_execution_intent", "id": q.ID, "tenant": tenant, "actor": requester}) != nil {
		return nil, denied
	}
	receipt := security.NewID()
	if _, err := tx.Exec(`INSERT INTO receipts VALUES (?,?,?)`, receipt, q.ID, tenant); err != nil {
		return nil, err
	}
	_, err := tx.Exec(`UPDATE actions SET used=1 WHERE id=?`, q.ID)
	return map[string]string{"receipt": receipt, "kind": "inert-receipt", "action": q.ID}, err
}
