package util

import (
	"os"
	"syscall"
)

type LockedFile struct{ f *os.File }

func Acquire(path string) (*LockedFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil { return nil, err }
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil { _ = f.Close(); return nil, err }
	return &LockedFile{f:f}, nil
}
func (l *LockedFile) Release() error {
	if l == nil || l.f == nil { return nil }
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	return l.f.Close()
}
