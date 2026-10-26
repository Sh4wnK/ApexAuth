// Package authz implements role-based access control checks with wildcard
// support. Permissions are strings of the form "<resource>:<action>", e.g.
// "billing:read" or "users:write". A trailing "*" wildcard matches any
// segment:
//
//	"billing:*" matches "billing:read", "billing:write", "billing:delete"
//	"*:read"   matches "billing:read", "users:read", ...
//	"*"        matches everything
//
// Matching is exact otherwise; a user is allowed a permission when any of
// their effective permissions (union over assigned roles) matches.
package authz

import "strings"

// HasPermission reports whether perms contains an entry that matches req.
func HasPermission(perms []string, req string) bool {
	for _, p := range perms {
		if Match(p, req) {
			return true
		}
	}
	return false
}

// Match reports whether an exact or wildcard permission pattern matches a
// requested permission.
func Match(pattern, req string) bool {
	if pattern == "*" || pattern == req {
		return true
	}
	pi := strings.IndexByte(pattern, ':')
	ri := strings.IndexByte(req, ':')
	// Both must have the colon structure to compare segment-wise.
	if pi < 0 || ri < 0 {
		return false
	}
	pres, pact := pattern[:pi], pattern[pi+1:]
	rres, ract := req[:ri], req[ri+1:]
	if resMatch(pres, rres) && (pact == "*" || pact == ract) {
		return true
	}
	// Also allow wildcard resource ("*:action") — resMatch handles "*".
	return false
}

func resMatch(p, r string) bool {
	return p == "*" || p == r
}
