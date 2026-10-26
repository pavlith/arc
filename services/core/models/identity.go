// Package models contains Core SQLite persistence records, not public API DTOs.
package models

import "time"

// IdentitySigningKey contains only metadata and the public Ed25519 key.
// Private signing material is never stored in SQLite.
type IdentitySigningKey struct {
	Kid       string     `gorm:"column:kid;primaryKey"`
	PublicKey []byte     `gorm:"column:public_key;not null"`
	NotBefore time.Time  `gorm:"column:not_before;not null"`
	ExpiresAt time.Time  `gorm:"column:expires_at;not null"`
	RevokedAt *time.Time `gorm:"column:revoked_at"`
}

func (IdentitySigningKey) TableName() string { return "identity_signing_key_metadata" }

type IdentityServiceAccount struct {
	ID                string     `gorm:"column:id;primaryKey"`
	ServiceDefinition string     `gorm:"column:service_definition;not null"`
	Deployment        string     `gorm:"column:deployment;not null"`
	DisabledAt        *time.Time `gorm:"column:disabled_at"`
}

func (IdentityServiceAccount) TableName() string { return "identity_service_accounts" }

type IdentityServiceCredential struct {
	Kid              string     `gorm:"column:kid;primaryKey"`
	ServiceAccountID string     `gorm:"column:service_account_id;not null"`
	PublicKey        []byte     `gorm:"column:public_key;not null"`
	SecretReference  string     `gorm:"column:secret_reference;not null"`
	NotBefore        time.Time  `gorm:"column:not_before;not null"`
	ExpiresAt        time.Time  `gorm:"column:expires_at;not null"`
	RevokedAt        *time.Time `gorm:"column:revoked_at"`
}

func (IdentityServiceCredential) TableName() string { return "identity_service_credentials" }
