// Package v1 provides Core's stable public Go DTO surface. The server code and
// migrations remain owned by services/core, never by the reusable pkgs module.
package v1

import (
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/fabric"
	"github.com/pavlith/arc/services/core/modules/identity"
)

type LoginRequest = identity.LoginRequest
type LoginResult = identity.LoginResult
type SessionRequest = identity.SessionRequest
type UserExchange = identity.UserExchange
type TokenResult = identity.TokenResult
type CheckRequest = access.CheckRequest
type Decision = access.Decision
type Resource = access.Resource
type EventSubscription = fabric.EventSubscription
type RouteSnapshot = fabric.RouteSnapshot
type SignedSnapshot = fabric.SignedSnapshot
type RouteBundle = fabric.RouteBundle

const (
	RoutesSubject        = fabric.RoutesSubject
	RoutesChangedSubject = fabric.RoutesChangedSubject
	RegisterSubject      = fabric.RegisterSubject
	ReadySubject         = fabric.ReadySubject
	EventPermitSubject   = fabric.EventPermitSubject
	CheckSubject         = fabric.CheckSubject
)
