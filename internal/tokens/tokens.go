// Package tokens handles JWT access-token signing, key rotation and the
// JWKS endpoint. Two algorithms are supported:
//
//   - Ed25519 (default): compact, fast, no key-size negotiation.
//   - RSA RS256: for interop with verifiers that only speak RSA.
//
// Keys live in-process (optionally loaded from PEM files). When
// RotateAfter > 0 a background goroutine periodically generates a fresh
// key, retires the previous one to the verified-until set served by JWKS,
// and keeps at most MaxHistory keys for verification. With a single key the
// JWKS still returns the active key so external verifiers can rotate.
package tokens

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Algorithm identifiers.
const (
	AlgEdDSA = "EdDSA"
	AlgRS256 = "RS256"
)

// MaxHistory is how many retired keys stay published for verification.
const MaxHistory = 4

// Key is a signing key with its public JWKS entry.
type Key struct {
	ID        string
	Alg       string
	CreatedAt time.Time
	signer    crypto.Signer
	public    crypto.PublicKey
}

// JWK renders the public key as a JSON Web Key (RFC 7517).
func (k *Key) JWK() map[string]any {
	switch pub := k.public.(type) {
	case ed25519.PublicKey:
		return map[string]any{
			"kty": "OKP",
			"crv": "Ed25519",
			"kid": k.ID,
			"alg": AlgEdDSA,
			"use": "sig",
			"x":   base64.RawURLEncoding.EncodeToString(pub),
		}
	case *rsa.PublicKey:
		return map[string]any{
			"kty": "RSA",
			"kid": k.ID,
			"alg": AlgRS256,
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(bigEndian(pub.E)),
		}
	default:
		return map[string]any{"kty": "unknown", "kid": k.ID}
	}
}

func bigEndian(v int) []byte {
	var b [8]byte
	n := v
	for i := 7; i >= 0; i-- {
		b[i] = byte(n)
		n >>= 8
	}
	// trim leading zeros
	i := 0
	for i < 7 && b[i] == 0 {
		i++
	}
	return b[i:]
}

// Signer manages the active signing key plus retired keys for verification.
type Signer struct {
	mu      sync.RWMutex
	active  *Key
	history []*Key
	alg     string
	now     func() time.Time
	rotate  time.Duration
	done    chan struct{}
	keyPath string
}

// Claims carries the inside of an access token.
type Claims struct {
	UserID      string   `json:"uid"`
	Email       string   `json:"email"`
	Name        string   `json:"name"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"perms"`
	SessionID   string   `json:"sid"`
	Type        string   `json:"typ"` // "access" | "id_token"
	Nonce       string   `json:"nonce,omitempty"`
	jwt.RegisteredClaims
}

// Options configures a Signer.
type Options struct {
	// Alg selects "ed25519" or "rsa".
	Alg string
	// KeyPath loads an existing PEM (PKCS#8/EC/RSA) — ignored when empty.
	KeyPath string
	// RotateAfter rotates the signing key periodically; 0 disables.
	RotateAfter time.Duration
	// Issuer is baked into tokens.
	Issuer string
}

// NewSigner creates a signer, optionally loading a key from disk.
func NewSigner(o Options) (*Signer, error) {
	s := &Signer{
		alg:     o.Alg,
		now:     time.Now,
		rotate:  o.RotateAfter,
		done:    make(chan struct{}),
		keyPath: o.KeyPath,
	}
	if o.Alg != "ed25519" && o.Alg != "rsa" {
		return nil, fmt.Errorf("tokens: unsupported algorithm %q", o.Alg)
	}
	initial, err := s.loadInitialKey()
	if err != nil {
		return nil, err
	}
	s.active = initial
	if o.RotateAfter > 0 {
		go s.rotateLoop(o.RotateAfter)
	}
	_ = o.Issuer
	return s, nil
}

func (s *Signer) loadInitialKey() (*Key, error) {
	if s.keyPath == "" {
		return s.genKey()
	}
	b, err := os.ReadFile(s.keyPath)
	if err != nil {
		return nil, fmt.Errorf("tokens: read key %s: %w", s.keyPath, err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("tokens: no PEM block in %s", s.keyPath)
	}
	tryParse := func() (crypto.Signer, crypto.PublicKey, bool) {
		if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if signer, ok := k.(crypto.Signer); ok {
				return signer, signer.Public(), true
			}
		}
		if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return k, k.Public(), true
		}
		if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return k, k.Public(), true
		}
		return nil, nil, false
	}
	signer, pub, ok := tryParse()
	if !ok {
		return nil, fmt.Errorf("tokens: unsupported PEM in %s", s.keyPath)
	}
	switch signer.(type) {
	case ed25519.PrivateKey:
		if s.alg != "ed25519" {
			return nil, fmt.Errorf("tokens: loaded Ed25519 key but algorithm is %s", s.alg)
		}
	case *rsa.PrivateKey:
		if s.alg != "rsa" {
			return nil, fmt.Errorf("tokens: loaded RSA key but algorithm is %s", s.alg)
		}
	case *ecdsa.PrivateKey:
		// ECDSA P-256 is acceptable for RS256-style JWT (ES256); we only
		// support it when algorithm maps — reject for clarity.
		return nil, fmt.Errorf("tokens: ECDSA keys not supported; use Ed25519 or RSA")
	}
	return &Key{
		ID:        uuid.NewString()[:12],
		Alg:       jwtAlg(s.alg),
		CreatedAt: s.now(),
		signer:    signer,
		public:    pub,
	}, nil
}

func (s *Signer) genKey() (*Key, error) {
	switch s.alg {
	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("tokens: generate ed25519: %w", err)
		}
		return &Key{ID: uuid.NewString()[:12], Alg: AlgEdDSA, CreatedAt: s.now(), signer: priv, public: pub}, nil
	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("tokens: generate rsa: %w", err)
		}
		return &Key{ID: uuid.NewString()[:12], Alg: AlgRS256, CreatedAt: s.now(), signer: key, public: &key.PublicKey}, nil
	}
	return nil, fmt.Errorf("tokens: unknown alg %s", s.alg)
}

func jwtAlg(alg string) string {
	if alg == "rsa" {
		return AlgRS256
	}
	return AlgEdDSA
}

func (s *Signer) rotateLoop(period time.Duration) {
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.Rotate()
		case <-s.done:
			return
		}
	}
}

// Rotate generates a fresh key and retires the current one. Called
// automatically when RotateAfter > 0; tests call it directly.
func (s *Signer) Rotate() {
	k, err := s.genKey()
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.history = append([]*Key{s.active}, s.history...)
	if len(s.history) > MaxHistory {
		s.history = s.history[:MaxHistory]
	}
	s.active = k
}

// Close stops background rotation.
func (s *Signer) Close() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

// ActiveKeyID returns the current kid (tests/instrumentation).
func (s *Signer) ActiveKeyID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.ID
}

// ActiveAlg returns the JWT algorithm of the active key ("EdDSA"/"RS256").
func (s *Signer) ActiveAlg() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.Alg
}

// Sign issues a token with the given claims and issuer/ttl.
func (s *Signer) Sign(claims Claims, ttl time.Duration, issuer string) (string, error) {
	now := s.now()
	if claims.ID == "" {
		claims.ID = uuid.NewString()
	}
	claims.RegisteredClaims.Issuer = issuer
	claims.RegisteredClaims.IssuedAt = jwt.NewNumericDate(now)
	claims.RegisteredClaims.NotBefore = jwt.NewNumericDate(now)
	claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(now.Add(ttl))

	s.mu.RLock()
	key := s.active
	s.mu.RUnlock()

	var token *jwt.Token
	switch key.signer.(type) {
	case ed25519.PrivateKey:
		token = jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	case *rsa.PrivateKey:
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	default:
		return "", fmt.Errorf("tokens: unsupported signer type")
	}
	token.Header["kid"] = key.ID
	return token.SignedString(key.signer)
}

// Verify parses and validates a token against active + retired keys.
// It enforces expiry and a token type claim when typ != "".
func (s *Signer) Verify(tokenStr, typ string) (*Claims, error) {
	s.mu.RLock()
	keys := append([]*Key{s.active}, s.history...)
	s.mu.RUnlock()

	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		// find the key by kid
		kid, _ := t.Header["kid"].(string)
		for _, k := range keys {
			if kid == "" || k.ID == kid {
				return k.public, nil
			}
		}
		return nil, fmt.Errorf("tokens: unknown kid %q", kid)
	}, jwt.WithValidMethods([]string{AlgEdDSA, AlgRS256}))
	if err != nil || !parsed.Valid {
		if err == nil {
			return nil, errors.New("tokens: invalid token")
		}
		return nil, err
	}
	if typ != "" && claims.Type != typ {
		return nil, fmt.Errorf("tokens: wrong token type %q (wanted %q)", claims.Type, typ)
	}
	return claims, nil
}

// JWKS returns the public key set as JSON (RFC 7517).
func (s *Signer) JWKS() []byte {
	s.mu.RLock()
	keyList := append([]*Key{s.active}, s.history...)
	s.mu.RUnlock()
	out := map[string]any{"keys": make([]any, 0, len(keyList))}
	list := out["keys"].([]any)
	for _, k := range keyList {
		list = append(list, k.JWK())
	}
	out["keys"] = list
	b, _ := json.Marshal(out)
	return b
}
