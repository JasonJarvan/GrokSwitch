package filelock

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestAcquireIsExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json.lock")
	first, err := Acquire(path, time.Second, true)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release()

	_, err = Acquire(path, 25*time.Millisecond, true)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("second lock error = %v, want ErrBusy", err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	second, err := Acquire(path, time.Second, true)
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Release()
}
