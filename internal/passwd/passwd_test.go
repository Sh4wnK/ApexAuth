package passwd

import "testing"

func TestHashVerify(t *testing.T) {
	h, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if len(h) < 60 || h[:10] != "$argon2id$" {
		t.Fatalf("unexpected hash format: %q", h)
	}
	if !Verify("correct horse battery staple", h) {
		t.Fatal("valid password rejected")
	}
	if Verify("wrong", h) {
		t.Fatal("wrong password accepted")
	}
}

func TestVerifyMalformed(t *testing.T) {
	// Malformed hashes must verify false, never panic.
	for _, bad := range []string{"", "plaintext", "$6$abc$def", "$argon2id$v=19$not-params$x$y", "$argon2id$v=19$m=x,t=1,p=4$!!$!!"} {
		if Verify("pw", bad) {
			t.Fatalf("malformed hash %q verified", bad)
		}
	}
}

func TestHashUnique(t *testing.T) {
	a, _ := Hash("same")
	b, _ := Hash("same")
	if a == b {
		t.Fatal("salts must differ")
	}
}
