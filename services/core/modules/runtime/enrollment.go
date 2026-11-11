package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"time"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/models"
	"gorm.io/gorm"
)

// EnrollmentRequest pins the host-generated public key before the operator
// gives a ticket to the host over a trusted, independent channel.
type EnrollmentRequest struct {
	Node      NodeRegistration
	Kid       string
	PublicKey ed25519.PublicKey
	TTL       time.Duration
}

// EnrollmentOffer is displayed to the infrastructure administrator ONCE.
// Never persist, log, or broadcast its plaintext token.
type EnrollmentOffer struct {
	ID        string    `json:"id"`
	NodeID    string    `json:"node_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

var enrollmentKid = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$`)

const enrollmentHashDomain = "arc.runtime.enrollment.token.v1\n"

func enrollmentCapabilities(caps []agent.Kind) (string, error) {
	if len(caps) == 0 || len(caps) > 3 {
		return "", ErrInvalid
	}
	copyCaps := append([]agent.Kind(nil), caps...)
	sort.Slice(copyCaps, func(i, j int) bool { return copyCaps[i] < copyCaps[j] })
	for i, kind := range copyCaps {
		if kind != agent.Docker && kind != agent.LXD && kind != agent.Systemd {
			return "", ErrInvalid
		}
		if i > 0 && copyCaps[i-1] == kind {
			return "", ErrInvalid
		}
	}
	return canonical(copyCaps)
}

// IssueEnrollment authorizes one node/credential binding, for 1–30 minutes.
// It does not enable an RPC bootstrap listener or provision broker NKeys.
func (c *Control) IssueEnrollment(ctx context.Context, req EnrollmentRequest) (EnrollmentOffer, error) {
	var out EnrollmentOffer
	if ctx == nil || c == nil || c.db == nil || !agent.ValidID(req.Node.ID) || agent.Bootstrap(req.Node.ID) ||
		req.Node.ServiceAccountID == "" || len(req.Node.ServiceAccountID) > 128 ||
		!enrollmentKid.MatchString(req.Kid) || len(req.PublicKey) != ed25519.PublicKeySize ||
		req.TTL < time.Minute || req.TTL > 30*time.Minute {
		return out, ErrInvalid
	}
	caps, err := enrollmentCapabilities(req.Node.Capabilities)
	if err != nil {
		return out, err
	}
	var random [48]byte
	if _, err := rand.Read(random[:]); err != nil {
		return out, security.ErrUnavailable
	}
	defer clear(random[:])
	id := "enroll-" + hex.EncodeToString(random[:16])
	token := base64.RawURLEncoding.EncodeToString(random[16:])
	now := c.now().UTC()
	offer := models.RuntimeEnrollmentOffer{
		ID: id, NodeID: req.Node.ID, ServiceAccountID: req.Node.ServiceAccountID,
		Kid: req.Kid, PublicKey: append([]byte(nil), req.PublicKey...),
		Capabilities: caps, TokenHash: digest(enrollmentHashDomain + token),
		CreatedAt: now, ExpiresAt: now.Add(req.TTL),
	}
	err = c.managed(ctx, func(tx *gorm.DB, actor string) error {
		var count int64
		if err := tx.Table("identity_service_accounts").
			Where("id=? AND service_definition='arc-agent' AND disabled_at IS NULL", offer.ServiceAccountID).
			Count(&count).Error; err != nil {
			return err
		}
		if count != 1 {
			return security.ErrDenied
		}
		if err := tx.Table("runtime_nodes").
			Where("id=? OR service_account_id=?", offer.NodeID, offer.ServiceAccountID).
			Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			return ErrConflict
		}
		if err := tx.Table("identity_service_credentials").
			Where("service_account_id=? OR kid=?", offer.ServiceAccountID, offer.Kid).
			Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			return ErrConflict
		}
		if err := tx.Table("runtime_enrollment_offers").
			Where("redeemed_at IS NULL AND revoked_at IS NULL AND expires_at>? AND (node_id=? OR service_account_id=? OR kid=?)",
				now, offer.NodeID, offer.ServiceAccountID, offer.Kid).
			Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			return ErrConflict
		}
		offer.ApprovedBy = actor
		if err := tx.Create(&offer).Error; err != nil {
			return err
		}
		return audit(tx, actor, "node.enroll.issue", offer.NodeID, offer.ID, now)
	})
	if err != nil {
		return out, err
	}
	return EnrollmentOffer{ID: id, NodeID: offer.NodeID, Token: token, ExpiresAt: offer.ExpiresAt}, nil
}

// ClaimEnrollment consumes one authorized ticket and the pinned Ed25519 proof
// in a single transaction. This method is NOT an exposed network endpoint;
// a future bootstrap transport must pin the Core trust root and TLS channel.
// Core cannot generate or return an Agent private key or NATS credentials.
func (c *Control) ClaimEnrollment(ctx context.Context, claim agent.EnrollmentClaim) error {
	if ctx == nil || !agent.ValidID(claim.OfferID) || len(claim.Token) != 43 ||
		len(claim.Signature) != 86 || c == nil || c.db == nil {
		return ErrInvalid
	}
	return mapped(database.RetryBusy(ctx, func() error {
		return c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			// Capture time after obtaining the write transaction: a busy retry
			// must never redeem a ticket that expired while waiting.
			now := c.now().UTC()
			var offer models.RuntimeEnrollmentOffer
			if err := tx.Where("id=?", claim.OfferID).Take(&offer).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return security.ErrDenied
				}
				return err
			}
			checkHash := digest(enrollmentHashDomain + claim.Token)
			if offer.RedeemedAt != nil || offer.RevokedAt != nil ||
				!now.Before(offer.ExpiresAt) ||
				subtle.ConstantTimeCompare([]byte(checkHash), []byte(offer.TokenHash)) != 1 ||
				!agent.VerifyEnrollmentClaim(claim, ed25519.PublicKey(offer.PublicKey)) {
				return security.ErrDenied
			}
			var count int64
			if err := tx.Table("identity_service_accounts").
				Where("id=? AND service_definition='arc-agent' AND disabled_at IS NULL", offer.ServiceAccountID).
				Count(&count).Error; err != nil {
				return err
			}
			if count != 1 {
				return security.ErrDenied
			}
			if err := tx.Table("runtime_nodes").
				Where("id=? OR service_account_id=?", offer.NodeID, offer.ServiceAccountID).
				Count(&count).Error; err != nil {
				return err
			}
			if count != 0 {
				return security.ErrDenied
			}
			if err := tx.Table("identity_service_credentials").
				Where("service_account_id=? OR kid=?", offer.ServiceAccountID, offer.Kid).
				Count(&count).Error; err != nil {
				return err
			}
			if count != 0 {
				return security.ErrDenied
			}
			var capabilities []agent.Kind
			if json.Unmarshal([]byte(offer.Capabilities), &capabilities) != nil {
				return security.ErrUnavailable
			}
			caps, err := enrollmentCapabilities(capabilities)
			if err != nil || caps != offer.Capabilities {
				return security.ErrUnavailable
			}
			if err := tx.Exec(`INSERT INTO identity_service_credentials
				(kid,service_account_id,public_key,secret_reference,not_before,expires_at)
				VALUES(?,?,?,?,?,?)`, offer.Kid, offer.ServiceAccountID, offer.PublicKey,
				"operator:enrollment:"+offer.ID, now, now.Add(30*24*time.Hour)).Error; err != nil {
				return err
			}
			if err := tx.Create(&models.RuntimeNode{
				ID: offer.NodeID, ServiceAccountID: offer.ServiceAccountID,
				Capabilities: caps, Active: true, CreatedAt: now,
			}).Error; err != nil {
				return err
			}
			if err := tx.Model(&offer).Update("redeemed_at", now).Error; err != nil {
				return err
			}
			return audit(tx, "enrollment:"+offer.ServiceAccountID, "node.enroll.claim", offer.NodeID, offer.ID, now)
		})
	}))
}

// RevokeEnrollment invalidates a pending offer permanently. A successfully
// claimed node must instead be disabled and its credentials revoked separately.
func (c *Control) RevokeEnrollment(ctx context.Context, offerID string) error {
	if !agent.ValidID(offerID) {
		return ErrInvalid
	}
	return c.managed(ctx, func(tx *gorm.DB, actor string) error {
		var row models.RuntimeEnrollmentOffer
		if err := tx.Where("id=?", offerID).Take(&row).Error; err != nil {
			return err
		}
		if row.RedeemedAt != nil {
			return ErrConflict
		}
		if row.RevokedAt != nil {
			return nil
		}
		now := c.now().UTC()
		if err := tx.Model(&row).Update("revoked_at", now).Error; err != nil {
			return err
		}
		return audit(tx, actor, "node.enroll.revoke", row.NodeID, offerID, now)
	})
}
