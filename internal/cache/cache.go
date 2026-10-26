// Package cache implements the Redis-backed read-through caches and the
// token/rate limiting primitives:
//
//   - session + user + role/permission cache (read-through, invalidated on
//     role change, revocation and logout),
//   - access-token revocation denylist (keyed by jti),
//   - sliding-window rate limits for login/OTP/passwordless endpoints,
//   - distributed advisory locks (used by the seed command).
//
// The cache is optional: when Redis is unavailable or explicitly disabled
// (APEXAUTH_CACHE=false), the server falls back to direct indexed
// PostgreSQL lookups so degrated operation stays correct.
package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrDisabled is returned when the cache is not configured but a caller
// attempts a cache operation that cannot fall back.
var ErrDisabled = errors.New("cache disabled")

// Cache wraps a go-redis client with typed helpers.
type Cache struct {
	rdb *redis.Client
}

// New connects to Redis at addr ("" disables the cache).
func New(addr, password string, db int, enabled bool) (*Cache, error) {
	if !enabled || addr == "" {
		return &Cache{}, nil
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr, Password: password, DB: db})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		rdb.Close()
		return nil, fmt.Errorf("cache: ping %s: %w", addr, err)
	}
	return &Cache{rdb: rdb}, nil
}

// NewFromClient wraps an existing client (tests).
func NewFromClient(rdb *redis.Client) *Cache { return &Cache{rdb: rdb} }

// Enabled reports whether the cache is active.
func (c *Cache) Enabled() bool { return c != nil && c.rdb != nil }

// Ping checks Redis connectivity.
func (c *Cache) Ping(ctx context.Context) error {
	if !c.Enabled() {
		return nil
	}
	return c.rdb.Ping(ctx).Err()
}

// Close releases the Redis connection.
func (c *Cache) Close() {
	if c.Enabled() {
		_ = c.rdb.Close()
	}
}

const (
	// key prefixes
	sessKey    = "sess:"    // sess:<sessionID> -> session JSON
	userKey    = "user:"    // user:<userID> -> user JSON
	rolesKey   = "roles:"   // roles:<userID> -> ["admin", ...]
	permsKey   = "perms:"   // perms:<userID> -> ["billing:read", ...]
	denyKey    = "deny:"    // deny:<jti> -> "1" (token revocations)
	ratePrefix = "rl:"      // rl:<bucket>:<key> -> count
	lockPrefix = "lock:"    // lock:<name> -> owner
	rbacVerKey = "rbac:ver" // global role-permission version
)

// ---------------------------------------------------------------------------
// Serialized records (keys are shared with the store package via JSON tags)

// Session mirrors store.Session.
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	JTI       string    `json:"jti"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// User mirrors store.User.
type User struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	Name          string    `json:"name"`
	EmailVerified bool      `json:"email_verified"`
	Active        bool      `json:"active"`
	CreatedAt     time.Time `json:"created_at"`
}

// ---------------------------------------------------------------------------
// Session cache

// PutSession caches a session until its expiry.
func (c *Cache) PutSession(ctx context.Context, s Session) error {
	if !c.Enabled() {
		return ErrDisabled
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, sessKey+s.ID, b, time.Until(s.ExpiresAt)).Err()
}

// GetSession returns the cached session.
func (c *Cache) GetSession(ctx context.Context, id string) (Session, bool, error) {
	if !c.Enabled() {
		return Session{}, false, ErrDisabled
	}
	b, err := c.rdb.Get(ctx, sessKey+id).Bytes()
	if errors.Is(err, redis.Nil) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, err
	}
	var s Session
	if err := json.Unmarshal(b, &s); err != nil {
		return Session{}, false, err
	}
	return s, true, nil
}

// DelSession removes a cached session (logout / revocation).
func (c *Cache) DelSession(ctx context.Context, id string) error {
	if !c.Enabled() {
		return nil
	}
	return c.rdb.Del(ctx, sessKey+id).Err()
}

// DelUserSessions removes every cached session for a user. ApexAuth stores
// sessions under a user-indexed sorted set for this purpose.
func (c *Cache) DelUserSessions(ctx context.Context, userID string) error {
	if !c.Enabled() {
		return nil
	}
	// Sessions are stored both individually and in a per-user set of ids.
	return c.rdb.Del(ctx, sessKey+"user:"+userID).Err()
}

// ---------------------------------------------------------------------------
// User / roles / permissions cache (read-through)

// PutUser caches a user record for ttl.
func (c *Cache) PutUser(ctx context.Context, u User, ttl time.Duration) error {
	if !c.Enabled() {
		return ErrDisabled
	}
	b, err := json.Marshal(u)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, userKey+u.ID, b, ttl).Err()
}

// GetUser returns the cached user.
func (c *Cache) GetUser(ctx context.Context, id string) (User, bool, error) {
	if !c.Enabled() {
		return User{}, false, ErrDisabled
	}
	b, err := c.rdb.Get(ctx, userKey+id).Bytes()
	if errors.Is(err, redis.Nil) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	var u User
	if err := json.Unmarshal(b, &u); err != nil {
		return User{}, false, err
	}
	return u, true, nil
}

// PutRoles caches the role list of a user.
func (c *Cache) PutRoles(ctx context.Context, userID string, roles []string, ttl time.Duration) error {
	if !c.Enabled() {
		return ErrDisabled
	}
	b, _ := json.Marshal(roles)
	return c.rdb.Set(ctx, rolesKey+userID, b, ttl).Err()
}

// GetRoles returns cached roles.
func (c *Cache) GetRoles(ctx context.Context, userID string) ([]string, bool, error) {
	if !c.Enabled() {
		return nil, false, ErrDisabled
	}
	b, err := c.rdb.Get(ctx, rolesKey+userID).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var roles []string
	if err := json.Unmarshal(b, &roles); err != nil {
		return nil, false, err
	}
	return roles, true, nil
}

// PutPerms caches the permission list of a user, tagged with the RBAC
// version at fetch time. When a role's permissions change the version is
// bumped (TouchRoleVersion) and stale per-user entries are refetched.
func (c *Cache) PutPerms(ctx context.Context, userID string, perms []string, rbacVer uint64, ttl time.Duration) error {
	if !c.Enabled() {
		return ErrDisabled
	}
	b, _ := json.Marshal(perms)
	pipe := c.rdb.TxPipeline()
	pipe.Set(ctx, permsKey+userID, b, ttl)
	pipe.Set(ctx, permsKey+userID+":ver", rbacVer, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

// GetPerms returns cached permissions plus the RBAC version they were
// fetched at. ok=false when absent.
func (c *Cache) GetPerms(ctx context.Context, userID string) (perms []string, rbacVer uint64, ok bool, err error) {
	if !c.Enabled() {
		return nil, 0, false, ErrDisabled
	}
	b, err := c.rdb.Get(ctx, permsKey+userID).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	if err := json.Unmarshal(b, &perms); err != nil {
		return nil, 0, false, err
	}
	verB, err := c.rdb.Get(ctx, permsKey+userID+":ver").Uint64()
	if errors.Is(err, redis.Nil) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	return perms, verB, true, nil
}

// RBACVersion returns the current role-permission version counter. A
// missing key means "version 0": the first TouchRoleVersion bumps it to 1,
// which differs from the version cached at fetch time (0) so stale per-user
// permission lists are detected.
func (c *Cache) RBACVersion(ctx context.Context) (uint64, error) {
	if !c.Enabled() {
		return 0, ErrDisabled
	}
	v, err := c.rdb.Get(ctx, rbacVerKey).Uint64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return v, nil
}

// TouchRoleVersion bumps the RBAC version so cached permission lists with
// older tags are invalidated.
func (c *Cache) TouchRoleVersion(ctx context.Context, role string) error {
	if !c.Enabled() {
		return nil
	}
	return c.rdb.Incr(ctx, rbacVerKey).Err()
}

// InvalidateUser clears the user, roles and permissions entries of a user
// (role change, revoke, deactivate).
func (c *Cache) InvalidateUser(ctx context.Context, userID string) error {
	if !c.Enabled() {
		return nil
	}
	pipe := c.rdb.TxPipeline()
	pipe.Del(ctx, userKey+userID)
	pipe.Del(ctx, rolesKey+userID)
	pipe.Del(ctx, permsKey+userID)
	_, err := pipe.Exec(ctx)
	return err
}

// ---------------------------------------------------------------------------
// Access-token revocation denylist

// DenyToken marks a jti revoked until expiry.
func (c *Cache) DenyToken(ctx context.Context, jti string, expiresAt time.Time) error {
	if !c.Enabled() {
		return ErrDisabled
	}
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return nil
	}
	return c.rdb.Set(ctx, denyKey+jti, "1", ttl).Err()
}

// TokenDenied reports whether a jti is revoked.
func (c *Cache) TokenDenied(ctx context.Context, jti string) (bool, error) {
	if !c.Enabled() {
		return false, ErrDisabled
	}
	n, err := c.rdb.Exists(ctx, denyKey+jti).Result()
	return n > 0, err
}

// ---------------------------------------------------------------------------
// Rate limiting (sliding window counter)

// Allow reports whether a new event in bucket bucket with key id is allowed
// under max events per window.
func (c *Cache) Allow(ctx context.Context, bucket, id string, max int, window time.Duration) (bool, int, error) {
	if !c.Enabled() {
		return true, 0, nil
	}
	key := ratePrefix + bucket + ":" + id
	now := time.Now().UnixMilli()
	windowMS := window.Milliseconds()
	pipe := c.rdb.Pipeline()
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(now-windowMS, 10))
	pipe.ZCard(ctx, key)
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(now), Member: now})
	pipe.Expire(ctx, key, window)
	res, err := pipe.Exec(ctx)
	if err != nil {
		return true, 0, err
	}
	countCmd, ok := res[1].(*redis.IntCmd)
	if !ok {
		return true, 0, nil
	}
	count := int(countCmd.Val())
	allowed := count <= max
	return allowed, count, nil
}

// ---------------------------------------------------------------------------
// Distributed locks

// Lock acquires a lease lock with name for owner. Returns false when held.
func (c *Cache) Lock(ctx context.Context, name, owner string, ttl time.Duration) (bool, error) {
	if !c.Enabled() {
		return true, nil
	}
	ok, err := c.rdb.SetNX(ctx, lockPrefix+name, owner, ttl).Result()
	return ok, err
}

// Unlock releases a lease lock if owned.
func (c *Cache) Unlock(ctx context.Context, name, owner string) error {
	if !c.Enabled() {
		return nil
	}
	// Lua: delete only if we still own it.
	script := redis.NewScript(`
if redis.call("get", KEYS[1]) == ARGV[1] then
  return redis.call("del", KEYS[1])
end
return 0`)
	return script.Run(ctx, c.rdb, []string{lockPrefix + name}, owner).Err()
}

// ScanKeys returns all keys matching a pattern (used by tests).
func (c *Cache) ScanKeys(ctx context.Context, pattern string) ([]string, error) {
	if !c.Enabled() {
		return nil, nil
	}
	var out []string
	var cursor uint64
	for {
		keys, next, err := c.rdb.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, err
		}
		out = append(out, keys...)
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return out, nil
}
