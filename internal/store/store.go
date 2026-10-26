// Package store implements the PostgreSQL data layer: users, credentials,
// roles/permissions, sessions, refresh-token families, OAuth clients and
// codes, passwordless tokens, consents and the audit log.
//
// Secrets are stored hashed (SHA-256) and passwords as PHC-encoded argon2id
// strings; the store never sees plaintext material.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a lookup key does not exist.
var ErrNotFound = errors.New("not found")

// ErrReuseDetected is returned by RotateRefreshToken when an already-used
// (rotated-out) token is presented again. Callers must revoke the family.
var ErrReuseDetected = errors.New("refresh token reuse detected")

// ErrConflict is returned when a unique constraint would be violated.
var ErrConflict = errors.New("conflict")

// ErrInactive is returned when a user account is disabled.
var ErrInactive = errors.New("user account inactive")

// Store is the PostgreSQL-backed data layer. All methods are safe for
// concurrent use.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// New connects to PostgreSQL at dsn and returns a ready store.
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{pool: pool, now: time.Now}, nil
}

// FromPool wraps an existing pool (used by tests).
func FromPool(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool, now: time.Now}
}

// SetNow overrides the clock (tests).
func (s *Store) SetNow(f func() time.Time) { s.now = f }

// Close releases the underlying pool.
func (s *Store) Close() { s.pool.Close() }

// Ping checks database connectivity.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// Pool exposes the underlying pool (tests use it to set up fixtures).
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// ---------------------------------------------------------------------------
// Users & credentials

// User is the persisted user record. Roles and Permissions are lazily
// populated by ListRoles/ListPermissions.
type User struct {
	ID            string
	Email         string
	Name          string
	EmailVerified bool
	Active        bool
	CreatedAt     time.Time
}

// CreateUser inserts a new user. Returns ErrConflict when the email exists.
func (s *Store) CreateUser(ctx context.Context, email, name string, emailVerified bool) (User, error) {
	id := uuid.NewString()
	_, err := s.pool.Exec(ctx, `INSERT INTO users (id, email, name, email_verified) VALUES ($1, $2, $3, $4)`,
		id, email, name, emailVerified)
	if err != nil {
		if isUniqueViolation(err) {
			return User{}, ErrConflict
		}
		return User{}, fmt.Errorf("store: create user: %w", err)
	}
	return s.GetUserByID(ctx, id)
}

// GetUserByID returns a user by id.
func (s *Store) GetUserByID(ctx context.Context, id string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, name, email_verified, active, created_at FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.Email, &u.Name, &u.EmailVerified, &u.Active, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("store: get user: %w", err)
	}
	return u, nil
}

// GetUserByEmail returns a user by email (case-insensitive).
func (s *Store) GetUserByEmail(ctx context.Context, email string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, name, email_verified, active, created_at FROM users WHERE lower(email) = lower($1)`, email).
		Scan(&u.ID, &u.Email, &u.Name, &u.EmailVerified, &u.Active, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("store: get user by email: %w", err)
	}
	return u, nil
}

// ListUsers pages users ordered by creation time (admin API). The total
// count is returned for pagination metadata.
func (s *Store) ListUsers(ctx context.Context, limit, offset int) ([]User, int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, email, name, email_verified, active, created_at
		FROM users ORDER BY created_at DESC, id LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("store: list users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.EmailVerified, &u.Active, &u.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: count users: %w", err)
	}
	return out, total, nil
}

// UpdateUser persists a user's mutable fields.
func (s *Store) UpdateUser(ctx context.Context, u User) error {
	if _, err := s.pool.Exec(ctx, `
		UPDATE users SET name = $2, email_verified = $3, active = $4, updated_at = now() WHERE id = $1`,
		u.ID, u.Name, u.EmailVerified, u.Active); err != nil {
		return fmt.Errorf("store: update user: %w", err)
	}
	return nil
}

// SetPassword stores the PHC-encoded argon2id hash for a user.
func (s *Store) SetPassword(ctx context.Context, userID, phc string) error {
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO credentials (user_id, password) VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE SET password = EXCLUDED.password`, userID, phc); err != nil {
		return fmt.Errorf("store: set password: %w", err)
	}
	return nil
}

// PasswordHash returns the stored PHC hash for a user id.
func (s *Store) PasswordHash(ctx context.Context, userID string) (string, error) {
	var phc string
	err := s.pool.QueryRow(ctx, `SELECT password FROM credentials WHERE user_id = $1`, userID).Scan(&phc)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: password hash: %w", err)
	}
	return phc, nil
}

// ---------------------------------------------------------------------------
// Roles & permissions

// Role is a named set of permissions.
type Role struct {
	ID          string
	Name        string
	Description string
	// Permissions is populated by AllRoles and RolePermissions.
	Permissions []string
}

// Permission is a (resource, action) pair.
type Permission struct {
	ID          string
	Resource    string
	Action      string
	Description string
}

// PermissionString renders "resource:action".
func (p Permission) String() string { return p.Resource + ":" + p.Action }

// EnsureRole creates a role if missing and returns it.
func (s *Store) EnsureRole(ctx context.Context, name, description string) (Role, error) {
	var r Role
	err := s.pool.QueryRow(ctx, `
		INSERT INTO roles (id, name, description) VALUES ($1, $2, $3)
		ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
		RETURNING id, name, description`, uuid.NewString(), name, description).
		Scan(&r.ID, &r.Name, &r.Description)
	if err != nil {
		return Role{}, fmt.Errorf("store: ensure role: %w", err)
	}
	return r, nil
}

// EnsurePermission creates a (resource, action) permission if missing.
func (s *Store) EnsurePermission(ctx context.Context, resource, action, description string) (Permission, error) {
	var p Permission
	err := s.pool.QueryRow(ctx, `
		INSERT INTO permissions (id, resource, action, description) VALUES ($1, $2, $3, $4)
		ON CONFLICT (resource, action) DO UPDATE SET description = EXCLUDED.description
		RETURNING id, resource, action, description`, uuid.NewString(), resource, action, description).
		Scan(&p.ID, &p.Resource, &p.Action, &p.Description)
	if err != nil {
		return Permission{}, fmt.Errorf("store: ensure permission: %w", err)
	}
	return p, nil
}

// GrantRolePermission binds a permission string (resource:action) to a role.
// The permission is created if missing.
func (s *Store) GrantRolePermission(ctx context.Context, roleName, permission string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: grant: begin: %w", err)
	}
	defer tx.Rollback(ctx)
	var permID string
	err = tx.QueryRow(ctx, `SELECT id FROM permissions WHERE resource || ':' || action = $1`, permission).Scan(&permID)
	if errors.Is(err, pgx.ErrNoRows) {
		res, act := splitPermission(permission)
		perm, perr := s.EnsurePermission(ctx, res, act, "")
		if perr != nil {
			return perr
		}
		permID = perm.ID
	} else if err != nil {
		return fmt.Errorf("store: grant: lookup permission: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_id)
		SELECT id, $2 FROM roles WHERE name = $1
		ON CONFLICT DO NOTHING`, roleName, permID); err != nil {
		return fmt.Errorf("store: grant: %w", err)
	}
	return tx.Commit(ctx)
}

// AssignRole binds a role to a user by name.
func (s *Store) AssignRole(ctx context.Context, userID, roleName string) error {
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_id)
		SELECT $1, id FROM roles WHERE name = $2
		ON CONFLICT DO NOTHING`, userID, roleName); err != nil {
		return fmt.Errorf("store: assign role: %w", err)
	}
	return nil
}

// RevokeRole removes a role from a user by name.
func (s *Store) RevokeRole(ctx context.Context, userID, roleName string) error {
	if _, err := s.pool.Exec(ctx, `
		DELETE FROM user_roles WHERE user_id = $1 AND role_id = (SELECT id FROM roles WHERE name = $2)`,
		userID, roleName); err != nil {
		return fmt.Errorf("store: revoke role: %w", err)
	}
	return nil
}

// ListRoles returns the role names of a user.
func (s *Store) ListRoles(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1 ORDER BY r.name`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list roles: %w", err)
	}
	defer rows.Close()
	var roles []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		roles = append(roles, n)
	}
	return roles, rows.Err()
}

// ListPermissions returns the permission strings of a user, deduplicated
// across roles.
func (s *Store) ListPermissions(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT p.resource || ':' || p.action
		FROM user_roles ur
		JOIN role_permissions rp ON rp.role_id = ur.role_id
		JOIN permissions p ON p.id = rp.permission_id
		WHERE ur.user_id = $1
		ORDER BY 1`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list permissions: %w", err)
	}
	defer rows.Close()
	var perms []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

// AllRoles returns every role with its permission strings (admin APIs and
// cache warm-up).
func (s *Store) AllRoles(ctx context.Context) ([]Role, error) {
	roles, err := s.allRoles(ctx)
	if err != nil {
		return nil, err
	}
	perms, err := s.pool.Query(ctx, `
		SELECT rp.role_id, p.resource || ':' || p.action
		FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id ORDER BY 2`)
	if err != nil {
		return nil, fmt.Errorf("store: role permissions: %w", err)
	}
	defer perms.Close()
	byID := map[string]int{}
	for i := range roles {
		byID[roles[i].ID] = i
	}
	for perms.Next() {
		var roleID, perm string
		if err := perms.Scan(&roleID, &perm); err != nil {
			return nil, err
		}
		if i, ok := byID[roleID]; ok {
			roles[i].Permissions = append(roles[i].Permissions, perm)
		}
	}
	return roles, perms.Err()
}

func (s *Store) allRoles(ctx context.Context) ([]Role, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, description FROM roles ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: all roles: %w", err)
	}
	defer rows.Close()
	var roles []Role
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.ID, &r.Name, &r.Description); err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

// RoleByName returns a role by name.
func (s *Store) RoleByName(ctx context.Context, name string) (Role, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, description FROM roles WHERE name = $1`, name)
	if err != nil {
		return Role{}, fmt.Errorf("store: role by name: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		_ = rows.Err()
		return Role{}, ErrNotFound
	}
	var r Role
	if err := rows.Scan(&r.ID, &r.Name, &r.Description); err != nil {
		return Role{}, err
	}
	return r, rows.Err()
}

// ListAllPermissions returns every permission in the system.
func (s *Store) ListAllPermissions(ctx context.Context) ([]Permission, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, resource, action, description FROM permissions ORDER BY resource, action`)
	if err != nil {
		return nil, fmt.Errorf("store: list all permissions: %w", err)
	}
	defer rows.Close()
	var out []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Resource, &p.Action, &p.Description); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RevokeRolePermission unbinds a permission string from a role.
func (s *Store) RevokeRolePermission(ctx context.Context, roleName, permission string) error {
	res, act := splitPermission(permission)
	if _, err := s.pool.Exec(ctx, `
		DELETE FROM role_permissions rp USING roles r, permissions p
		WHERE rp.role_id = r.id AND rp.permission_id = p.id
		  AND r.name = $1 AND p.resource = $2 AND p.action = $3`, roleName, res, act); err != nil {
		return fmt.Errorf("store: revoke role permission: %w", err)
	}
	return nil
}

// RolePermissions returns the permission strings granted to a role.
func (s *Store) RolePermissions(ctx context.Context, roleID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT p.resource || ':' || p.action FROM role_permissions rp
		JOIN permissions p ON p.id = rp.permission_id WHERE rp.role_id = $1 ORDER BY 1`, roleID)
	if err != nil {
		return nil, fmt.Errorf("store: role permissions: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// helpers

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

func splitPermission(s string) (resource, action string) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:]
		}
	}
	return s, "*"
}
