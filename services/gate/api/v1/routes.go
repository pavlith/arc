// Package v1 names Gate-owned system routes; business routes come exclusively
// from the signed and approved Fabric route snapshot.
package v1

const (
    Login = "/api/v1/arc/auth/login"
    Refresh = "/api/v1/arc/auth/refresh"
    Logout = "/api/v1/arc/auth/logout"
    Session = "/api/v1/arc/auth/session"
    Health = "/healthz"
    Ready = "/readyz"
)
