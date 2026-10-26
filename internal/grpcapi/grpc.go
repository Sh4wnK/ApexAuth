// Package grpcapi exposes ApexAuth over gRPC: the AuthService (token
// validation, permission checks, user lookup) and AdminService (RBAC
// management), protected by a bearer-token auth interceptor, plus gRPC
// health and reflection services.
package grpcapi

import (
	"context"
	"errors"
	"strings"

	"github.com/Sh4wnK/ApexAuth/gen/apexauth/v1"
	"github.com/Sh4wnK/ApexAuth/internal/cache"
	"github.com/Sh4wnK/ApexAuth/internal/service"
	"github.com/Sh4wnK/ApexAuth/internal/store"
	"github.com/Sh4wnK/ApexAuth/internal/tokens"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// authKey is the authorization metadata key.
const authKey = "authorization"

// Server implements the gRPC services.
type Server struct {
	apexauthv1.UnimplementedAuthServiceServer
	apexauthv1.UnimplementedAdminServiceServer
	tokens *service.Tokens
	store  *store.Store
	cache  *cache.Cache
}

// New builds the gRPC service implementation.
func New(tokens *service.Tokens, st *store.Store, ca *cache.Cache) *Server {
	return &Server{tokens: tokens, store: st, cache: ca}
}

// cacheProvider returns the cache when enabled (admin role mutations
// invalidate cached permission lists).
func (s *Server) cacheProvider() (*cache.Cache, bool) {
	if s.cache != nil && s.cache.Enabled() {
		return s.cache, true
	}
	return nil, false
}

// bearerFromContext extracts the bearer token from gRPC metadata.
func bearerFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get(authKey)
	if len(vals) == 0 {
		return ""
	}
	v := vals[0]
	if len(v) > 7 && strings.EqualFold(v[:7], "Bearer ") {
		return strings.TrimSpace(v[7:])
	}
	return v
}

// publicMethod reports whether a method needs a token. The health service
// and reflection are always open.
func publicMethod(method string) bool {
	if strings.Contains(method, "grpc.health") || strings.Contains(method, "grpc.reflection") {
		return true
	}
	return false
}

// Interceptor authenticates every non-public call: it parses the Bearer
// token and stores the claims in the context.
func Interceptor(tokens *service.Tokens) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if publicMethod(info.FullMethod) {
			return handler(ctx, req)
		}
		raw := bearerFromContext(ctx)
		if raw == "" {
			return nil, status.Error(codes.Unauthenticated, "missing bearer token")
		}
		claims, err := tokens.VerifyAccess(ctx, raw)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token: "+err.Error())
		}
		ctx = context.WithValue(ctx, claimsKey{}, claims)
		return handler(ctx, req)
	}
}

type claimsKey struct{}

func claimsFrom(ctx context.Context) (*tokens.Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(*tokens.Claims)
	return c, ok
}

// ---------------------------------------------------------------------------
// AuthService

// ValidateToken reports whether a token is valid and returns its principal.
func (s *Server) ValidateToken(ctx context.Context, req *apexauthv1.ValidateTokenRequest) (*apexauthv1.ValidateTokenResponse, error) {
	if req.GetToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "token required")
	}
	claims, err := s.tokens.VerifyAccess(ctx, req.GetToken())
	if err != nil {
		return &apexauthv1.ValidateTokenResponse{Valid: false, Error: err.Error()}, nil
	}
	resp := &apexauthv1.ValidateTokenResponse{
		Valid:       true,
		UserId:      claims.UserID,
		Email:       claims.Email,
		Jti:         claims.ID,
		ExpiresAt:   claims.ExpiresAt.Unix(),
		Roles:       claims.Roles,
		Permissions: claims.Permissions,
	}
	return resp, nil
}

// CheckPermission evaluates the caller's permission (or, for admins, any
// user's) against a required permission string.
func (s *Server) CheckPermission(ctx context.Context, req *apexauthv1.CheckPermissionRequest) (*apexauthv1.CheckPermissionResponse, error) {
	caller, ok := claimsFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no principal")
	}
	subject := caller.UserID
	if req.GetUserId() != "" && req.GetUserId() != caller.UserID {
		// Only users with impersonation rights may check other users.
		allowed, err := s.tokens.CheckPermission(ctx, caller.UserID, "users:impersonate")
		if err != nil || !allowed {
			return nil, status.Error(codes.PermissionDenied, "cannot check other users")
		}
		subject = req.GetUserId()
	}
	if req.GetPermission() == "" {
		return nil, status.Error(codes.InvalidArgument, "permission required")
	}
	ok2, err := s.tokens.CheckPermission(ctx, subject, req.GetPermission())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &apexauthv1.CheckPermissionResponse{Allowed: ok2}, nil
}

// GetUser returns a user by id or email (the caller may only fetch their
// own record unless they hold users:read).
func (s *Server) GetUser(ctx context.Context, req *apexauthv1.GetUserRequest) (*apexauthv1.User, error) {
	caller, ok := claimsFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no principal")
	}
	var u store.User
	var err error
	switch {
	case req.GetUserId() != "":
		if req.GetUserId() != caller.UserID {
			if allow, aerr := s.tokens.CheckPermission(ctx, caller.UserID, "users:read"); aerr != nil || !allow {
				return nil, status.Error(codes.PermissionDenied, "cannot view other users")
			}
		}
		u, err = s.store.GetUserByID(ctx, req.GetUserId())
	case req.GetEmail() != "":
		if req.GetEmail() != caller.Email {
			if allow, aerr := s.tokens.CheckPermission(ctx, caller.UserID, "users:read"); aerr != nil || !allow {
				return nil, status.Error(codes.PermissionDenied, "cannot view other users")
			}
		}
		u, err = s.store.GetUserByEmail(ctx, req.GetEmail())
	default:
		return nil, status.Error(codes.InvalidArgument, "user_id or email required")
	}
	if errors.Is(err, store.ErrNotFound) {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	roles, perms, err := s.tokens.PermissionsOf(ctx, u.ID)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &apexauthv1.User{
		Id:            u.ID,
		Email:         u.Email,
		Name:          u.Name,
		EmailVerified: u.EmailVerified,
		Active:        u.Active,
		Roles:         roles,
		Permissions:   perms,
		CreatedAt:     u.CreatedAt.Unix(),
	}, nil
}

// ListUserRoles returns the caller's roles (or another user's, for admins).
func (s *Server) ListUserRoles(ctx context.Context, req *apexauthv1.ListUserRolesRequest) (*apexauthv1.ListUserRolesResponse, error) {
	caller, ok := claimsFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no principal")
	}
	subject := caller.UserID
	if req.GetUserId() != "" && req.GetUserId() != caller.UserID {
		if allow, err := s.tokens.CheckPermission(ctx, caller.UserID, "roles:read"); err != nil || !allow {
			return nil, status.Error(codes.PermissionDenied, "cannot list other users' roles")
		}
		subject = req.GetUserId()
	}
	names, err := s.store.ListRoles(ctx, subject)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	out := &apexauthv1.ListUserRolesResponse{}
	for _, n := range names {
		out.Roles = append(out.Roles, &apexauthv1.Role{Name: n})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// AdminService (requires admin permission)

func (s *Server) requirePerm(ctx context.Context, perm string) (string, error) {
	caller, ok := claimsFrom(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no principal")
	}
	allowed, err := s.tokens.CheckPermission(ctx, caller.UserID, perm)
	if err != nil || !allowed {
		return "", status.Error(codes.PermissionDenied, "missing permission "+perm)
	}
	return caller.UserID, nil
}

func (s *Server) CreateRole(ctx context.Context, req *apexauthv1.CreateRoleRequest) (*apexauthv1.Role, error) {
	if _, err := s.requirePerm(ctx, "roles:write"); err != nil {
		return nil, err
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	role, err := s.store.EnsureRole(ctx, req.GetName(), req.GetDescription())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	for _, p := range req.GetPermissions() {
		_ = s.store.GrantRolePermission(ctx, role.Name, p)
	}
	return &apexauthv1.Role{Id: role.ID, Name: role.Name, Description: role.Description, Permissions: req.GetPermissions()}, nil
}

func (s *Server) ListRoles(ctx context.Context, req *apexauthv1.ListRolesRequest) (*apexauthv1.ListRolesResponse, error) {
	if _, err := s.requirePerm(ctx, "roles:read"); err != nil {
		return nil, err
	}
	roles, err := s.store.AllRoles(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	out := &apexauthv1.ListRolesResponse{}
	for _, r := range roles {
		out.Roles = append(out.Roles, &apexauthv1.Role{Id: r.ID, Name: r.Name, Description: r.Description, Permissions: r.Permissions})
	}
	return out, nil
}

func (s *Server) AssignRole(ctx context.Context, req *apexauthv1.AssignRoleRequest) (*apexauthv1.AssignRoleResponse, error) {
	if _, err := s.requirePerm(ctx, "roles:write"); err != nil {
		return nil, err
	}
	if req.GetUserId() == "" || req.GetRoleName() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id and role_name required")
	}
	if err := s.store.AssignRole(ctx, req.GetUserId(), req.GetRoleName()); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if ca, ok := s.cacheProvider(); ok {
		_ = ca.InvalidateUser(ctx, req.GetUserId())
	}
	return &apexauthv1.AssignRoleResponse{Assigned: true}, nil
}

func (s *Server) RevokeRole(ctx context.Context, req *apexauthv1.RevokeRoleRequest) (*apexauthv1.RevokeRoleResponse, error) {
	if _, err := s.requirePerm(ctx, "roles:write"); err != nil {
		return nil, err
	}
	if err := s.store.RevokeRole(ctx, req.GetUserId(), req.GetRoleName()); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if ca, ok := s.cacheProvider(); ok {
		_ = ca.InvalidateUser(ctx, req.GetUserId())
	}
	return &apexauthv1.RevokeRoleResponse{Revoked: true}, nil
}

func (s *Server) CreatePermission(ctx context.Context, req *apexauthv1.CreatePermissionRequest) (*apexauthv1.Permission, error) {
	if _, err := s.requirePerm(ctx, "roles:write"); err != nil {
		return nil, err
	}
	if req.GetResource() == "" || req.GetAction() == "" {
		return nil, status.Error(codes.InvalidArgument, "resource and action required")
	}
	p, err := s.store.EnsurePermission(ctx, req.GetResource(), req.GetAction(), req.GetDescription())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &apexauthv1.Permission{Id: p.ID, Resource: p.Resource, Action: p.Action, Description: p.Description}, nil
}

func (s *Server) ListPermissions(ctx context.Context, req *apexauthv1.ListPermissionsRequest) (*apexauthv1.ListPermissionsResponse, error) {
	if _, err := s.requirePerm(ctx, "roles:read"); err != nil {
		return nil, err
	}
	permissions, err := s.store.ListAllPermissions(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	out := &apexauthv1.ListPermissionsResponse{}
	for _, p := range permissions {
		out.Permissions = append(out.Permissions, &apexauthv1.Permission{Id: p.ID, Resource: p.Resource, Action: p.Action, Description: p.Description})
	}
	return out, nil
}
