package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAtomicWriteCreatesPrivateFileAndReplacesContents(t *testing.T) {
	target := filepath.Join(t.TempDir(), "nested", "auth.json")
	if err := AtomicWrite(target, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(target, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "second" {
		t.Fatalf("contents = %q, want second", data)
	}
	if runtime.GOOS != "windows" {
		assertMode(t, filepath.Dir(target), 0o700)
		assertMode(t, target, 0o600)
	}
}

func TestReadPrivateFileRejectsSymlinkAndTightensMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not consistently available on Windows")
	}
	root := t.TempDir()
	target := filepath.Join(root, "auth.json")
	if err := os.WriteFile(target, []byte("credential"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked-auth.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateFile(link); err == nil || !strings.Contains(err.Error(), "symlinked") {
		t.Fatalf("symlink read error = %v", err)
	}
	data, err := ReadPrivateFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "credential" {
		t.Fatalf("contents = %q", data)
	}
	assertMode(t, target, 0o600)
}

func TestAtomicWriteRefusesToReplaceDirectory(t *testing.T) {
	target := filepath.Join(t.TempDir(), "auth.json")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(target, []byte("credential"), 0o600); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("error = %v, want directory refusal", err)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}
