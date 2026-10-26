package fabric

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/sdk/testcontract"
	coremigrations "github.com/pavlith/arc/services/core/migrations"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
)

func TestSQLiteFabricSignedCatalogAndRouteSnapshots(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "core.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	if err := database.Migrate(ctx, db, coremigrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	operator := key(101)
	signer := key(102)
	account := "10000000-0000-4000-8000-000000000010"
	id := &identity.Core{GormDB: db}
	f := &Core{
		GormDB: db, Identity: id,
		ApprovalKey: operator.Public().(ed25519.PublicKey),
		SnapshotKey: signer,
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(db.Exec(
		"INSERT INTO identity_service_accounts(id,service_definition,deployment) VALUES(?,?,?)",
		account, "books", "books-v1",
	).Error)
	a := testcontract.Artifact(1)
	compiled, err := contract.Compile(a)
	must(err)
	res := compiled.Manifest.Resources[0]
	policy := access.Approval{
		ContractDigests: map[string]string{res.Type: compiled.Digest},
		Types: []access.TypeSpec{{
			Type: res.Type, Provider: account, Actions: res.Actions,
			ShareAction: res.ShareAction, CreateAction: res.CreateAction,
			DeleteAction: res.DeleteAction, AllowInheritance: res.AllowInheritance,
		}},
	}
	subjects := make([]string, 0, len(compiled.Manifest.Operations))
	for _, op := range compiled.Manifest.Operations {
		subjects = append(subjects, op.Subject)
	}
	installation := Installation{
		Publisher: "test-publisher", Account: account, Deployment: "books-v1",
		Artifact: a, Subjects: subjects, Policy: approved(t, operator, policy),
	}
	raw, signature := sign(t, operator, installation)
	artifactJSON, err := json.Marshal(a)
	must(err)
	subjectsJSON, err := json.Marshal(subjects)
	must(err)
	must(db.Exec(
		"INSERT INTO fabric_definitions(name,publisher) VALUES('books','test-publisher')",
	).Error)
	must(db.Exec(
		`INSERT INTO fabric_contracts(digest,service_name,api_major,artifact,installation,signature)
		VALUES(?,?,?,?,?,?)`,
		compiled.Digest, "books", 1, string(artifactJSON), string(raw), signature,
	).Error)
	must(db.Exec(
		"INSERT INTO fabric_deployments(service_account_id,digest,subjects) VALUES(?,?,?)",
		account, compiled.Digest, string(subjectsJSON),
	).Error)
	catalog, err := f.LoadAccess(ctx)
	must(err)
	_, err = catalog.Type(res.Type, account, compiled.Digest)
	must(err)
	active, err := f.active(ctx, account, compiled.Digest)
	must(err)
	if active.Digest != compiled.Digest {
		t.Fatalf("active digest mismatch: %s", active.Digest)
	}
	signed, err := f.Routes(ctx)
	must(err)
	snapshot, err := VerifySnapshot(signer.Public().(ed25519.PublicKey), signed, 0)
	must(err)
	if snapshot.Revision != 0 || len(snapshot.Routes) == 0 ||
		len(snapshot.Artifacts[compiled.Digest].Manifest) == 0 {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	must(db.Exec("UPDATE identity_service_accounts SET disabled_at=CURRENT_TIMESTAMP WHERE id=?", account).Error)
	if _, err := f.active(ctx, account, compiled.Digest); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("disabled account was treated as active: %v", err)
	}
	must(db.Exec("UPDATE fabric_contracts SET revoked_at=CURRENT_TIMESTAMP WHERE digest=?", compiled.Digest).Error)
	must(db.Exec("UPDATE fabric_route_state SET revision=revision+1 WHERE singleton=1").Error)
	newSigned, err := f.Routes(ctx)
	must(err)
	newSnapshot, err := VerifySnapshot(signer.Public().(ed25519.PublicKey), newSigned, 1)
	must(err)
	if len(newSnapshot.Routes) != 0 || newSnapshot.Revision != 1 {
		t.Fatalf("revocation leaked into route snapshot: %+v", newSnapshot)
	}
	if _, err := f.LoadAccess(ctx); !errors.Is(err, security.ErrUnavailable) {
		t.Fatalf("empty unsigned catalog accepted: %v", err)
	}
	f.Identity = &identity.Core{}
	if _, err := f.Routes(ctx); !errors.Is(err, security.ErrUnavailable) {
		t.Fatalf("different database owner accepted: %v", err)
	}
}
