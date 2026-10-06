# Roadmap

## Verified requests: keep the client key away from the sudo-ing user

### Problem

On a genuine `sudo -A` run, the password is safe from the agent. askpass
writes it into a pipe that sudo reads, and sudo runs as root.

The weakness is that nothing forces the agent through sudo. sudo runs
askpass as the invoking user, so `client.key` has to be readable by that
user, and so by every agent running as them. An agent can therefore:

1. Run `askpass` directly and read the password from its own stdout.
2. Set `SUDO_ASKPASS` to a wrapper that calls the real askpass and keeps a
   copy of its output.
3. Write its own client that uses the key and claims anything it likes:
   host, command, "parent is sudo with EUID 0".

The dialog's WARNING line catches cases 1 and 2. Case 3 can't be told apart
from a real request. The only facts the laptop verifies are the certificate
name and the source address, and both are genuine because the key is.

A smaller gap exists even on the genuine path. askpass is a descendant of
the agent, so under the default `kernel.yama.ptrace_scope=1` the agent can
attach to it in the moment between `execve` and the call that marks the
process non-dumpable, and read its memory.

### Goal

- An agent running as the VPS user can obtain the password only by running
  sudo for real, and then only sudo receives it.
- Every field the dialog shows is either verified on the VPS by root or
  clearly marked as unverified.

### Design

Add a small root-owned daemon on the VPS, **askpassd**, which becomes the
only holder of the client key.

```
 agent ─▶ sudo -A cmd                      (root, setuid)
            └─ askpass "[sudo] password:"  (runs as the user)
                  │  unix socket, passes its stdout fd
                  ▼
               askpassd                    (root)
                  │  checks the peer, then mTLS as today
                  ▼
               askpass-server on the laptop ─▶ dialog
```

1. **The key moves under root.** `/etc/askpass/client.key`, mode 0600,
   owned by root. The user can no longer open an mTLS connection to the
   laptop at all, which closes case 3.
2. **askpass becomes a thin relay.** It connects to askpassd's socket, for
   example `/run/askpass/sock`, which the user can open. It passes the
   prompt and its own stdout file descriptor (via `SCM_RIGHTS`), then waits
   for an exit status. It never sees the password.
3. **askpassd verifies the caller with kernel-sourced facts.**
   - `SO_PEERCRED` gives the peer's PID, UID and GID.
   - The peer's `/proc/<pid>/exe` must be the installed, root-owned askpass
     binary.
   - The peer's parent must have `/proc/<ppid>/exe` equal to `/usr/bin/sudo`
     and effective UID 0. Root can read `exe` for setuid processes; the user
     can't fake it.
   - The command line comes from `/proc/<sudo pid>/cmdline`. The user is the
     real UID of sudo and of askpass.
4. **askpassd checks the received descriptor.** It must be a pipe whose
   other end is open in the verified sudo process; compare pipe inodes
   through `/proc/<sudo pid>/fd`. This stops a wrapper or a ptrace-attached
   agent from substituting its own pipe.
5. **The password goes straight to sudo.** askpassd writes the password
   into the verified pipe itself, then tells askpass to exit 0. The password
   never exists in a process the user owns, which closes the ptrace gap.
6. **The protocol carries verified facts.** The request gains a
   `verified_by: askpassd` marker, and the dialog shows host, user and
   command as verified. Requests without it, such as from a legacy client,
   keep the WARNING treatment, or are refused under a server option like
   `-require-verified`.

Cases 1 and 2 then fail on the VPS before any dialog appears: askpassd
rejects a peer whose parent isn't sudo, or whose executable isn't the real
askpass.

### What it does not fix

- **Root on the VPS can still do anything.** That includes reading the key,
  replacing askpassd, or reading sudo's memory. The laptop now trusts root
  on the VPS rather than the agent's user.
- **A genuine sudo invocation is still genuine.** If an agent runs
  `sudo -A sh -c 'curl … | sh'`, the dialog shows exactly that, verified.
  Judging it is still the human's job.
- **sudo's credential cache** (`timestamp_timeout`) is unchanged.

### Delivery

- A new `cmd/askpassd`.
- A thin client mode in `askpass`, with the current direct-mTLS mode kept
  for setups without the daemon.
- A protocol version bump.
- A systemd system unit with a `RuntimeDirectory` socket.
- Install docs. The install needs root on the VPS, so the operator does it.
- Tests: the peer-verification logic against a fake `/proc` tree, and the
  fd-passing round trip over a socketpair. A full sudo test needs a
  disposable VM or container.

## Smaller items

- **Validate on real hardware.** The current release has not been run with
  a real zenity dialog or real sudo. Check:
  - sudo's effective UID is 0 while askpass runs, so genuine requests don't
    show the WARNING line.
  - The zenity dialog appears in front on GNOME Wayland.
  - The systemd user unit sees `WAYLAND_DISPLAY`.
- **Revocation.** A serial-number denylist on the server, so one client
  certificate can be revoked without rebuilding the CA.
- **Dialog details.** Show a Command longer than 1000 characters in the
  review window too, as Run from already is, rather than cutting it.
