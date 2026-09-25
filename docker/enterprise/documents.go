package enterprise

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"guardrail-proxy/security"
)

type Document struct {
	ID      string               `json:"id"`
	Content string               `json:"content"`
	Readers []string             `json:"-"`
	Roots   []string             `json:"-"`
	Version int                  `json:"version"`
	Data    security.DataContext `json:"data"`
}

func readDoc(tx *sql.Tx, id, tenant, principal string) (Document, error) {
	d := Document{ID: id}
	var readers, roots string
	if tx.QueryRow(`SELECT content,readers,roots,version FROM documents WHERE id=? AND tenant=?`, id, tenant).Scan(&d.Content, &readers, &roots, &d.Version) != nil {
		return d, denied
	}
	if json.Unmarshal([]byte(readers), &d.Readers) != nil || json.Unmarshal([]byte(roots), &d.Roots) != nil {
		return d, denied
	}
	allowed := false
	for _, v := range d.Readers {
		if v == principal {
			allowed = true
		}
	}
	if !allowed {
		return d, denied
	}
	return d, nil
}
func authorizedDoc(tx *sql.Tx, id string, actor security.IdentityContext) (Document, error) {
	d, err := readDoc(tx, id, actor.Tenant, actor.Principal)
	if err != nil {
		return d, err
	}
	for _, root := range d.Roots {
		if _, err = readDoc(tx, root, actor.Tenant, actor.Principal); err != nil {
			return d, err
		}
	}
	return d, nil
}
func (s *Store) document(tx *sql.Tx, route string, q Request) (any, error) {
	if !has(q.Identity, "document:read") {
		return nil, denied
	}
	if route == "/documents/revoke" {
		if !has(q.Identity, "operator:approve") {
			return nil, denied
		}
		var raw string
		if tx.QueryRow(`SELECT readers FROM documents WHERE id=? AND tenant=?`, q.ID, q.Identity.Tenant).Scan(&raw) != nil {
			return nil, denied
		}
		var readers []string
		if json.Unmarshal([]byte(raw), &readers) != nil {
			return nil, denied
		}
		next := []string{}
		for _, v := range readers {
			if v != q.Reader {
				next = append(next, v)
			}
		}
		if s.Audit == nil || s.Audit(map[string]string{"event": "source_acl_revoked", "id": q.ID, "tenant": q.Identity.Tenant}) != nil {
			return nil, denied
		}
		_, err := tx.Exec(`UPDATE documents SET readers=?,version=version+1 WHERE id=? AND tenant=?`, jsonText(next), q.ID, q.Identity.Tenant)
		return map[string]bool{"revoked": true}, err
	}
	if route == "/documents/read" {
		d, err := authorizedDoc(tx, q.ID, q.Identity)
		if err != nil {
			return nil, err
		}
		d.Data = security.DataContext{Source: d.ID, Producer: "loom-retrieval", Trust: "untrusted", Sensitivity: "sensitive", Origin: "repository", Tainted: true, Parents: d.Roots}
		// Attests server-issued lineage and content, never truthfulness or export rights.
		mac := hmac.New(sha256.New, s.Key)
		mac.Write([]byte(jsonText(map[string]any{"tenant": q.Identity.Tenant, "document": d})))
		d.Data.Integrity = hex.EncodeToString(mac.Sum(nil))
		if s.Audit == nil || s.Audit(map[string]string{"event": "document_read", "id": q.ID, "tenant": q.Identity.Tenant, "actor": q.Identity.Principal}) != nil {
			return nil, denied
		}
		return d, nil
	}
	if !has(q.Identity, "document:write") || len(q.Content) == 0 || len(q.Content) > 16000 || len(q.Readers) > 16 || len(q.Parents) > 8 {
		return nil, denied
	}
	if (route == "/documents/create" && len(q.Parents) != 0) || (route == "/documents/derive" && len(q.Parents) == 0) {
		return nil, denied
	}
	roots := []string{}
	seen := map[string]bool{}
	for _, parent := range q.Parents {
		d, err := authorizedDoc(tx, parent, q.Identity)
		if err != nil {
			return nil, err
		}
		for _, root := range append(d.Roots, d.ID) {
			if !seen[root] {
				roots = append(roots, root)
				seen[root] = true
			}
		}
	}
	if len(roots) > 32 {
		return nil, denied
	}
	readers := append([]string{q.Identity.Principal}, q.Readers...)
	id := security.NewID()
	if s.Audit == nil || s.Audit(map[string]string{"event": "document_created", "id": id, "tenant": q.Identity.Tenant, "actor": q.Identity.Principal}) != nil {
		return nil, denied
	}
	_, err := tx.Exec(`INSERT INTO documents(id,tenant,content,readers,roots) VALUES (?,?,?,?,?)`, id, q.Identity.Tenant, q.Content, jsonText(readers), jsonText(roots))
	return map[string]string{"id": id}, err
}
