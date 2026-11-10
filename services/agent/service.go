// Package agent owns the independently deployed Linux infrastructure executor.
package agent

import "github.com/pavlith/arc/services/agent/modules/reconcile"

var ErrInvalid = reconcile.ErrInvalid
var ErrUnavailable = reconcile.ErrUnavailable

type Config = reconcile.Config
type Service = reconcile.Service

func New(cfg Config) (*Service, error) {
	return reconcile.New(cfg)
}
