package fsutil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// EnsurePrivateDir creates a credential directory and tightens its Unix mode.
func EnsurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create private directory %s: %w", path, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("secure directory %s: %w", path, err)
		}
	}
	return nil
}

// AtomicWrite publishes data using a same-directory temporary file and rename.
// Credential files are always owner-readable/writable only on Unix.
func AtomicWrite(path string, data []byte, mode os.FileMode) (retErr error) {
	parent := filepath.Dir(path)
	if err := EnsurePrivateDir(parent); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.IsDir() {
		return fmt.Errorf("refusing to replace directory %s", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect destination %s: %w", path, err)
	}

	tmp, err := os.CreateTemp(parent, ".grok-switch-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if retErr != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if runtime.GOOS != "windows" {
		if err := tmp.Chmod(mode); err != nil {
			return fmt.Errorf("secure temporary file: %w", err)
		}
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("publish %s: %w", path, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("secure published file %s: %w", path, err)
		}
	}
	if dir, err := os.Open(parent); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// ReadPrivateFile reads a regular file without following a final symlink.
func ReadPrivateFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to read symlinked credential file %s", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("credential path is not a regular file: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	const max = 8 << 20
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, err
	}
	if len(data) > max {
		return nil, fmt.Errorf("credential file is unexpectedly large: %s", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("secure credential file %s: %w", path, err)
		}
	}
	return data, nil
}
