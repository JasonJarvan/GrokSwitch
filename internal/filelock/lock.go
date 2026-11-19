package filelock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/JasonJarvan/GrokSwitch/internal/fsutil"
)

var ErrBusy = errors.New("credential file is busy")

// Lock is an advisory OS lock compatible with Grok Build's auth.json.lock.
type Lock struct {
	file *os.File
}

// Acquire takes an exclusive lock, polling until timeout. When holderInfo is
// true it writes the PID:UNIX_TIMESTAMP format expected by Grok Build.
func Acquire(path string, timeout time.Duration, holderInfo bool) (*Lock, error) {
	if err := fsutil.EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", path, err)
	}

	deadline := time.Now().Add(timeout)
	for {
		acquired, lockErr := platformTryLock(file)
		if lockErr != nil {
			_ = file.Close()
			return nil, fmt.Errorf("lock %s: %w", path, lockErr)
		}
		if acquired {
			break
		}
		if timeout <= 0 || time.Now().After(deadline) {
			_ = file.Close()
			return nil, fmt.Errorf("%w: %s", ErrBusy, path)
		}
		time.Sleep(50 * time.Millisecond)
	}

	lock := &Lock{file: file}
	if holderInfo {
		if err := writeHolderInfo(file); err != nil {
			_ = lock.Release()
			return nil, fmt.Errorf("write lock holder info: %w", err)
		}
	}
	// Grok can unlink a stale lock and recreate it on a new inode. Verify that
	// the descriptor we locked is still the file visible at lockPath; otherwise
	// retry on the new inode instead of claiming a lock nobody else can see.
	fdInfo, fdErr := file.Stat()
	pathInfo, pathErr := os.Stat(path)
	if fdErr != nil || pathErr != nil || !os.SameFile(fdInfo, pathInfo) {
		_ = lock.Release()
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("%w: lock file changed while acquiring %s", ErrBusy, path)
		}
		return Acquire(path, remaining, holderInfo)
	}
	return lock, nil
}

func writeHolderInfo(file *os.File) error {
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Seek(0, 0); err != nil {
		return err
	}
	value := strconv.Itoa(os.Getpid()) + ":" + strconv.FormatInt(time.Now().Unix(), 10)
	if _, err := file.WriteString(value); err != nil {
		return err
	}
	return file.Sync()
}

func (l *Lock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := platformUnlock(l.file)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
