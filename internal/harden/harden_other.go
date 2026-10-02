//go:build unix && !linux

package harden

import "syscall"

// Process disables core dumps.
func Process() error {
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
}
