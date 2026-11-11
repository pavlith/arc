package models

import "time"

type RuntimeNode struct {
	ID               string `gorm:"primaryKey"`
	ServiceAccountID string
	Capabilities     string
	Active           bool
	LastSeenAt       *time.Time
	HostInventory    *string
	CreatedAt        time.Time
}

func (RuntimeNode) TableName() string { return "runtime_nodes" }

type RuntimeTemplate struct {
	NodeID    string `gorm:"primaryKey"`
	ID        string `gorm:"primaryKey"`
	Revision  int64  `gorm:"primaryKey"`
	Spec      string
	Revoked   bool
	CreatedAt time.Time
}

func (RuntimeTemplate) TableName() string { return "runtime_templates" }

type RuntimeResource struct {
	ID               string `gorm:"primaryKey"`
	NodeID           string
	TemplateID       string
	TemplateRevision int64
	Kind             string
	Revision         int64
	State            string
	Replicas         int
	Spec             string
	OperationID      string
	UpdatedAt        time.Time
}

func (RuntimeResource) TableName() string { return "runtime_resources" }

type RuntimeOperation struct {
	ID                string `gorm:"primaryKey"`
	ResourceID        string
	RequestedRevision int64
	Actor             string
	IdempotencyKey    string
	RequestHash       string
	Status            string
	ErrorCode         string
	Result            string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

func (RuntimeOperation) TableName() string { return "runtime_operations" }

type RuntimeNodeProfile struct {
	NodeID     string `gorm:"primaryKey"`
	ID         string `gorm:"primaryKey"`
	Revision   int64  `gorm:"primaryKey"`
	Spec       string
	Digest     string
	Revoked    bool
	ApprovedBy string
	CreatedAt  time.Time
}

func (RuntimeNodeProfile) TableName() string { return "runtime_node_profiles" }

type RuntimeEnrollmentOffer struct {
	ID               string `gorm:"primaryKey"`
	NodeID           string
	ServiceAccountID string
	Kid              string
	PublicKey        []byte
	Capabilities     string
	TokenHash        string
	ApprovedBy       string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	RedeemedAt       *time.Time
	RevokedAt        *time.Time
}

func (RuntimeEnrollmentOffer) TableName() string { return "runtime_enrollment_offers" }
