package fabric

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
	"gorm.io/gorm"
)

// approveGORM writes the contract, deployment, resource types, policy audit and
// route revision in ONE Core-owner transaction. A no-op write on route_state
// acquires SQLite's single-writer lock before checking for existing approvals.
func (c *Core) approveGORM(ctx context.Context, signed SignedInstallation) (string, error) {
	if err := c.readyGORM(); err != nil {
		return "", err
	}
	installation, compiled, err := c.verify(signed)
	if err != nil {
		return "", err
	}
	changed := false
	err = database.RetryBusy(ctx, func() error {
		changed = false
		return c.GormDB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec("UPDATE fabric_route_state SET revision=revision WHERE singleton=1").Error; err != nil {
				return security.ErrUnavailable
			}
			var definition, deployment string
			err := tx.Raw(
				`SELECT service_definition,deployment FROM identity_service_accounts
				WHERE id=? AND disabled_at IS NULL`, installation.Account,
			).Row().Scan(&definition, &deployment)
			if err != nil || definition != compiled.Manifest.Service.Name || deployment != installation.Deployment {
				return security.ErrDenied
			}
			if err := tx.Exec(
				"INSERT INTO fabric_definitions(name,publisher) VALUES(?,?) ON CONFLICT(name) DO NOTHING",
				definition, installation.Publisher,
			).Error; err != nil {
				return security.ErrUnavailable
			}
			var publisher string
			err = tx.Raw("SELECT publisher FROM fabric_definitions WHERE name=?", definition).
				Row().Scan(&publisher)
			if err != nil || publisher != installation.Publisher {
				return security.ErrDenied
			}
			var old []byte
			var revoked sql.NullTime
			err = tx.Raw("SELECT installation,revoked_at FROM fabric_contracts WHERE digest=?", compiled.Digest).
				Row().Scan(&old, &revoked)
			if err == nil {
				oldCanonical, oldErr := security.CanonicalJSON(old)
				newCanonical, newErr := security.CanonicalJSON(signed.Payload)
				if oldErr != nil || newErr != nil || !bytes.Equal(oldCanonical, newCanonical) || revoked.Valid {
					return identity.ErrConflict
				}
				return nil
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return security.ErrUnavailable
			}
			var existing string
			err = tx.Raw(
				`SELECT digest FROM fabric_contracts
				WHERE service_name=? AND api_major=? AND revoked_at IS NULL`,
				definition, compiled.Manifest.Service.APIMajor,
			).Row().Scan(&existing)
			if err == nil {
				return identity.ErrConflict
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return security.ErrUnavailable
			}
			var previous SignedInstallation
			err = tx.Raw(
				`SELECT installation,signature FROM fabric_contracts
				WHERE service_name=? AND api_major=? ORDER BY approved_at DESC LIMIT 1`,
				definition, compiled.Manifest.Service.APIMajor,
			).Row().Scan(&previous.Payload, &previous.Signature)
			if err == nil {
				prior, _, checkErr := c.verify(previous)
				if checkErr != nil || !contract.Compatible(prior.Artifact, installation.Artifact) {
					return contract.ErrInvalid
				}
			} else if !errors.Is(err, sql.ErrNoRows) {
				return security.ErrUnavailable
			}
			approvals := append([]access.Approved(nil), c.Bootstrap...)
			rows, err := tx.Raw(
				"SELECT installation,signature FROM fabric_contracts WHERE revoked_at IS NULL",
			).Rows()
			if err != nil {
				return security.ErrUnavailable
			}
			for rows.Next() {
				var oldSigned SignedInstallation
				if rows.Scan(&oldSigned.Payload, &oldSigned.Signature) != nil {
					rows.Close()
					return security.ErrUnavailable
				}
				prior, _, err := c.verify(oldSigned)
				if err != nil {
					rows.Close()
					return err
				}
				approvals = append(approvals, prior.Policy)
			}
			readErr := rows.Err()
			rows.Close()
			if readErr != nil {
				return security.ErrUnavailable
			}
			approvals = append(approvals, installation.Policy)
			if _, err := access.NewContracts(c.ApprovalKey, approvals); err != nil {
				return security.ErrDenied
			}
			artifact, err := json.Marshal(installation.Artifact)
			if err != nil {
				return contract.ErrInvalid
			}
			subjects, err := json.Marshal(installation.Subjects)
			if err != nil {
				return contract.ErrInvalid
			}
			if err := tx.Exec(
				`INSERT INTO fabric_contracts(digest,service_name,api_major,artifact,installation,signature)
				VALUES(?,?,?,?,?,?)`,
				compiled.Digest, definition, compiled.Manifest.Service.APIMajor,
				string(artifact), string(signed.Payload), signed.Signature,
			).Error; err != nil {
				return security.ErrUnavailable
			}
			if err := tx.Exec(
				"INSERT INTO fabric_deployments(service_account_id,digest,subjects) VALUES(?,?,?)",
				installation.Account, compiled.Digest, string(subjects),
			).Error; err != nil {
				return security.ErrUnavailable
			}
			var policyRevision int64
			err = tx.Raw(
				"UPDATE access_policy_state SET revision=revision+1 WHERE singleton=1 RETURNING revision",
			).Row().Scan(&policyRevision)
			if err != nil {
				return security.ErrUnavailable
			}
			for _, resource := range compiled.Manifest.Resources {
				var provider, encodedActions, share, create, del string
				var inheritance bool
				err = tx.Raw(
					`SELECT provider_service,actions,share_action,create_action,delete_action,allow_inheritance
					FROM access_resource_types WHERE type=?`, resource.Type,
				).Row().Scan(&provider, &encodedActions, &share, &create, &del, &inheritance)
				if err == nil {
					var actions []string
					if json.Unmarshal([]byte(encodedActions), &actions) != nil ||
						provider != installation.Account || !reflect.DeepEqual(actions, resource.Actions) ||
						share != resource.ShareAction || create != resource.CreateAction ||
						del != resource.DeleteAction || inheritance != resource.AllowInheritance {
						return security.ErrDenied
					}
					if err := tx.Exec(
						"UPDATE access_resource_types SET contract_digest=? WHERE type=?",
						compiled.Digest, resource.Type,
					).Error; err != nil {
						return security.ErrUnavailable
					}
					continue
				}
				if !errors.Is(err, sql.ErrNoRows) {
					return security.ErrUnavailable
				}
				actions, marshalErr := json.Marshal(resource.Actions)
				if marshalErr != nil {
					return contract.ErrInvalid
				}
				if err := tx.Exec(
					`INSERT INTO access_resource_types
					(type,provider_service,contract_digest,actions,share_action,create_action,delete_action,allow_inheritance)
					VALUES(?,?,?,?,?,?,?,?)`,
					resource.Type, installation.Account, compiled.Digest, string(actions),
					resource.ShareAction, resource.CreateAction, resource.DeleteAction, resource.AllowInheritance,
				).Error; err != nil {
					return security.ErrUnavailable
				}
			}
			change, _ := json.Marshal(map[string]string{"digest": compiled.Digest})
			if err := tx.Exec(
				`INSERT INTO access_policy_audit
				(actor,caller,operation,policy_revision,change_kind,change)
				VALUES(?,?,'fabric.approve',?,'contract_approved',?)`,
				"operator:"+installation.Publisher, installation.Account, policyRevision, string(change),
			).Error; err != nil {
				return security.ErrUnavailable
			}
			if err := tx.Exec(
				"UPDATE fabric_route_state SET revision=revision+1 WHERE singleton=1",
			).Error; err != nil {
				return security.ErrUnavailable
			}
			changed = true
			return nil
		})
	})
	if err != nil {
		return "", err
	}
	if changed && c.RoutesChanged != nil {
		c.RoutesChanged()
	}
	return compiled.Digest, nil
}

// revokeGORM only accepts a signed operator command; all ACL and route changes
// are committed atomically with revocation.
func (c *Core) revokeGORM(ctx context.Context, raw, sig []byte) error {
	if err := c.readyGORM(); err != nil {
		return err
	}
	canonical, err := security.CanonicalJSON(raw)
	if err != nil || !ed25519.Verify(c.ApprovalKey, canonical, sig) {
		return security.ErrUnauthenticated
	}
	var request Revocation
	if contract.Strict(raw, &request) != nil || !request.Revoke {
		return contract.ErrInvalid
	}
	changed := false
	err = database.RetryBusy(ctx, func() error {
		changed = false
		return c.GormDB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec("UPDATE fabric_route_state SET revision=revision WHERE singleton=1").Error; err != nil {
				return security.ErrUnavailable
			}
			var approved SignedInstallation
			err := tx.Raw(
				`SELECT installation,signature FROM fabric_contracts
				WHERE digest=? AND revoked_at IS NULL`, request.Digest,
			).Row().Scan(&approved.Payload, &approved.Signature)
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			if err != nil {
				return security.ErrUnavailable
			}
			installation, manifest, err := c.verify(approved)
			if err != nil || manifest.Digest != request.Digest {
				return security.ErrDenied
			}
			res := tx.Exec(
				"UPDATE fabric_contracts SET revoked_at=? WHERE digest=? AND revoked_at IS NULL",
				time.Now().UTC(), request.Digest,
			)
			if res.Error != nil || res.RowsAffected != 1 {
				return security.ErrUnavailable
			}
			var policyRevision int64
			if err := tx.Raw(
				"UPDATE access_policy_state SET revision=revision+1 WHERE singleton=1 RETURNING revision",
			).Row().Scan(&policyRevision); err != nil {
				return security.ErrUnavailable
			}
			change, _ := json.Marshal(map[string]string{"digest": request.Digest})
			if err := tx.Exec(
				`INSERT INTO access_policy_audit
				(actor,caller,operation,policy_revision,change_kind,change)
				VALUES('operator',?,'fabric.revoke',?,'contract_revoked',?)`,
				installation.Account, policyRevision, string(change),
			).Error; err != nil {
				return security.ErrUnavailable
			}
			if err := tx.Exec(
				"UPDATE fabric_route_state SET revision=revision+1 WHERE singleton=1",
			).Error; err != nil {
				return security.ErrUnavailable
			}
			changed = true
			return nil
		})
	})
	if err != nil {
		return err
	}
	if changed && c.RoutesChanged != nil {
		c.RoutesChanged()
	}
	return nil
}
