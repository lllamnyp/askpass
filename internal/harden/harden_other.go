//go:build unix && !linux

// Package harden reduces the ways a password held in process memory can leak.
package harden

import "syscall"

// Process disables core dumps.
func Process() error {
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
}
