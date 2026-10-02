// Package harden reduces the ways a password held in process memory can leak.
package harden

import "syscall"

// Process disables core dumps and marks the process non-dumpable, which also
// stops other processes of the same user from ptracing it or reading its
// memory through /proc.
func Process() error {
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
		return err
	}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0); errno != 0 {
		return errno
	}
	return nil
}
