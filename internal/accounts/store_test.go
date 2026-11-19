package accounts

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/JasonJarvan/GrokSwitch/internal/grokauth"
)

func TestStoreUpsertResolveAndPermissions(t *testing.T) {
	root := t.TempDir()
	paths := Paths{
		GrokHome:     filepath.Join(root, ".grok"),
		StoreRoot:    filepath.Join(root, ".grok", "accounts"),
		RegistryPath: filepath.Join(root, ".grok", "accounts", "registry.json"),
		ActiveAuth:   filepath.Join(root, ".grok", "auth.json"),
		ManagerLock:  filepath.Join(root, ".grok", "accounts", ".grok-switch.lock"),
	}
	store := New(paths)
	reg := &Registry{SchemaVersion: SchemaVersion, Accounts: []Account{}}
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)

	one := mustParse(t, authJSON("user-one", "one@example.com", "token-one"))
	account, created, err := store.Upsert(reg, one, "work", now)
	if err != nil {
		t.Fatal(err)
	}
	if !created || account.Alias != "work" {
		t.Fatalf("unexpected upsert result: created=%v account=%+v", created, account)
	}
	if err := store.Save(reg); err != nil {
		t.Fatal(err)
	}

	two := mustParse(t, authJSON("user-two", "two@example.com", "token-two"))
	accountTwo, created, err := store.Upsert(reg, two, "", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !created || accountTwo.Alias != "two" {
		t.Fatalf("unexpected generated alias: %+v", accountTwo)
	}
	if resolution := Resolve(reg, "01"); resolution.Index != 0 {
		t.Fatalf("row selector failed: %+v", resolution)
	}
	if resolution := Resolve(reg, "1garbage"); resolution.Index >= 0 {
		t.Fatalf("garbage row selector unexpectedly matched: %+v", resolution)
	}
	if resolution := Resolve(reg, "two@example.com"); resolution.Index != 1 {
		t.Fatalf("email selector failed: %+v", resolution)
	}
	if resolution := Resolve(reg, accountTwo.ID[4:12]); resolution.Index != 1 {
		t.Fatalf("id prefix selector failed: %+v", resolution)
	}

	if _, _, err := store.Upsert(reg, two, "work", now); err == nil {
		t.Fatal("expected duplicate alias rejection")
	}
	if runtime.GOOS != "windows" {
		registryInfo, err := os.Stat(paths.RegistryPath)
		if err != nil {
			t.Fatal(err)
		}
		if got := registryInfo.Mode().Perm(); got != 0o600 {
			t.Fatalf("registry mode = %o, want 600", got)
		}
		snapshot, _ := store.SnapshotPath(account.ID)
		snapshotInfo, err := os.Stat(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if got := snapshotInfo.Mode().Perm(); got != 0o600 {
			t.Fatalf("snapshot mode = %o, want 600", got)
		}
	}
}

func mustParse(t *testing.T, data []byte) *grokauth.File {
	t.Helper()
	parsed, err := grokauth.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func authJSON(userID, email, token string) []byte {
	return []byte(`{"https://auth.x.ai::client":{"key":"` + token + `","auth_mode":"oidc","create_time":"2026-08-01T00:00:00Z","user_id":"` + userID + `","email":"` + email + `","expires_at":"2030-01-01T00:00:00Z"}}`)
}
