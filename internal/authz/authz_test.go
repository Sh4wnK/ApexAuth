package authz

import "testing"

func TestHasPermission(t *testing.T) {
	perms := []string{"billing:read", "users:write", "roles:*"}
	cases := []struct {
		req  string
		want bool
	}{
		{"billing:read", true},
		{"billing:write", false},
		{"users:write", true},
		{"roles:read", true},
		{"roles:delete", true},
		{"audit:read", false},
		{"*:read", false}, // no wildcard resource in the list
		{"billing", false},
	}
	for _, c := range cases {
		if got := HasPermission(perms, c.req); got != c.want {
			t.Errorf("HasPermission(%q) = %v, want %v", c.req, got, c.want)
		}
	}
}

func TestMatchWildcards(t *testing.T) {
	cases := []struct {
		pattern, req string
		want         bool
	}{
		{"billing:*", "billing:read", true},
		{"billing:*", "billing:write", true},
		{"billing:*", "users:read", false},
		{"*:read", "billing:read", true},
		{"*:read", "users:read", true},
		{"*:read", "users:write", false},
		{"*", "anything:at:all", true},
		{"users:read", "users:read", true},
		{"users:read", "users:write", false},
		{"users:read", "users:read:extra", false},
		{"nested:type:thing", "nested:type", false},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.req); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.req, got, c.want)
		}
	}
}

func TestWildcardEverywhere(t *testing.T) {
	perms := []string{"*"}
	for _, req := range []string{"a:b", "billing:write", "x:y:z", "single"} {
		if !HasPermission(perms, req) {
			t.Errorf("wildcard should match %q", req)
		}
	}
}

func TestImpersonationPerms(t *testing.T) {
	if !HasPermission([]string{"users:impersonate"}, "users:impersonate") {
		t.Fatal("exact match failed")
	}
	if HasPermission([]string{"users:impersonate"}, "users:write") {
		t.Fatal("should not match unrelated permission")
	}
}
