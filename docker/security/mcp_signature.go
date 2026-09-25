package security

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func LoadMCPSigner(b []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(b)
	if block == nil || len(rest) != 0 {
		return nil, errors.New("invalid MCP signing key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	result, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("MCP key must be Ed25519")
	}
	return result, nil
}
func signatureDigest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

// SealMCP binds inspected bytes to the exact request, session, status and trace.
// A signature authenticates transport integrity, never the truth of tool content.
func SealMCP(key ed25519.PrivateKey, request, result []byte, session, trace string, status int, now time.Time) http.Header {
	issued := strconv.FormatInt(now.Unix(), 10)
	message := strings.Join([]string{"loom-mcp-v1", signatureDigest(request), signatureDigest(result), signatureDigest([]byte(session)), trace, strconv.Itoa(status), issued}, "\n")
	h := http.Header{}
	h.Set("X-Loom-MCP-Issued", issued)
	h.Set("X-Loom-MCP-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(message))))
	return h
}
