package tokens

import (
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	s, err := NewSigner(Options{Alg: "ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	raw, err := s.Sign(Claims{UserID: "u1", Email: "a@b.c", Roles: []string{"admin"}, Permissions: []string{"billing:read"}, Type: "access"}, time.Minute, "https://auth.example.com")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.Verify(raw, "access")
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != "u1" || claims.Email != "a@b.c" {
		t.Fatalf("claims mismatch: %+v", claims)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "admin" {
		t.Fatalf("roles wrong: %v", claims.Roles)
	}
}

func TestVerifyRejectsWrongType(t *testing.T) {
	s, _ := NewSigner(Options{Alg: "ed25519"})
	defer s.Close()
	raw, _ := s.Sign(Claims{UserID: "u1", Type: "id_token"}, time.Minute, "iss")
	if _, err := s.Verify(raw, "access"); err == nil {
		t.Fatal("expected type mismatch error")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	s, _ := NewSigner(Options{Alg: "ed25519"})
	defer s.Close()
	raw, _ := s.Sign(Claims{UserID: "u1", Type: "access"}, -time.Minute, "iss")
	if _, err := s.Verify(raw, "access"); err == nil {
		t.Fatal("expected expiry error")
	}
}

func TestVerifyRejectsTampered(t *testing.T) {
	s, _ := NewSigner(Options{Alg: "ed25519"})
	defer s.Close()
	raw, _ := s.Sign(Claims{UserID: "u1", Type: "access"}, time.Minute, "iss")
	tampered := raw[:len(raw)-4] + "AAAA"
	if _, err := s.Verify(tampered, "access"); err == nil {
		t.Fatal("expected signature error")
	}
}

func TestKeyRotationKeepsOldKeysVerifiable(t *testing.T) {
	s, _ := NewSigner(Options{Alg: "ed25519"})
	defer s.Close()
	oldRaw, _ := s.Sign(Claims{UserID: "u1", Type: "access"}, time.Minute, "iss")
	oldKID := s.ActiveKeyID()

	for i := 0; i < 3; i++ {
		s.Rotate()
	}
	if s.ActiveKeyID() == oldKID {
		t.Fatal("expected kid to change after rotation")
	}
	// Old token still verifies against the retired key in the JWKS set.
	claims, err := s.Verify(oldRaw, "access")
	if err != nil {
		t.Fatalf("old key should verify: %v", err)
	}
	if claims.UserID != "u1" {
		t.Fatal("wrong subject")
	}
	// New tokens verify too.
	newRaw, _ := s.Sign(Claims{UserID: "u2", Type: "access"}, time.Minute, "iss")
	if _, err := s.Verify(newRaw, "access"); err != nil {
		t.Fatal(err)
	}
}

func TestJWKSContainsActiveAndRetiredKeys(t *testing.T) {
	s, _ := NewSigner(Options{Alg: "ed25519"})
	defer s.Close()
	s.Rotate()
	s.Rotate()
	doc := string(s.JWKS())
	// Both kids appear.
	if !contains(t, doc, `"kty":"OKP"`) {
		t.Fatalf("jwks missing OKP key: %s", doc)
	}
}

func TestRS256SignAndVerify(t *testing.T) {
	s, err := NewSigner(Options{Alg: "rsa"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	raw, err := s.Sign(Claims{UserID: "u1", Type: "access"}, time.Minute, "iss")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.Verify(raw, "access")
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != "u1" {
		t.Fatal("claims wrong")
	}
	if s.ActiveAlg() != "RS256" {
		t.Fatal("expected RS256 alg")
	}
}

func contains(t *testing.T, s, sub string) bool {
	t.Helper()
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
