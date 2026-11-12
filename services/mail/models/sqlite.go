// Package models contains Mail-owned connection records.
package models

type Account struct {
	RootID            string `gorm:"column:acl_root_id;primaryKey"`
	WorkspaceID       string
	OwnerID           string
	Lifecycle         string
	Name              string
	Host              string
	Port              int
	Login             string
	Email             string
	State             string
	Revision          int64
	Generation        int64
	CredentialVersion int64
	KeyID             string
	Ciphertext        []byte
}

func (Account) TableName() string { return "accounts" }
