# askpass

Relays `sudo` password prompts from a remote host to a desktop dialog over mTLS.

Agents running on a server sometimes need `sudo`. askpass gives them a way
that needs neither passwordless sudo nor a stored password: every time sudo
needs the password, a dialog pops up on your desktop saying which host, user
and command want it. You type the password or press **Deny**.

```
 VPS                                              laptop (GNOME)
 ───                                              ──────────────
 sudo -A apt install jq
   └─ askpass "[sudo] password for agent: "
        │      ── mTLS (TLS 1.3, CA-pinned both ways) ──▶  askpass-server
        │      request: host, user, prompt, command            └─ zenity dialog
        │                                                         [Send] [Deny]
        │      ◀── password, or denied / timeout ──
        └─ prints password to sudo, exits 0 (or exits 1)
```

There are two static binaries:

- **`askpass`** runs on the server you sudo on (the *client*). sudo runs it
  as its `SUDO_ASKPASS` helper. It connects to the laptop, sends a description
  of the request and prints the password it gets back. If the request is
  denied, times out or the laptop can't be reached, it exits 1 and sudo fails.
- **`askpass-server`** runs on your laptop. It listens on the private-network
  address (default `10.99.0.2:7676`) and shows a zenity dialog for every
  request. It also holds the PKI: it creates the CA and issues the server and
  client certificates.

## Build

Requires Go 1.26 or newer.

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/ ./cmd/...
# bin/askpass  bin/askpass-server
```

Cross-compile with `GOOS=linux GOARCH=arm64` (and so on) as needed. The
binaries have no runtime dependencies. The server needs only `zenity`, which
ships with GNOME.

## Laptop setup

These steps assume the laptop's private-network address is `10.99.0.2`.
Substitute your own where it differs.

1. Install the binary and check zenity is there:

   ```sh
   install -m 0755 bin/askpass-server ~/.local/bin/
   command -v zenity
   ```

2. Create the CA and the server certificate. Everything goes into
   `~/.config/askpass-server/` (override with `-dir` or `ASKPASS_SERVER_DIR`).
   Existing files are never overwritten.

   ```sh
   askpass-server init-ca
   askpass-server issue-server -ip 10.99.0.2
   ```

   `issue-server` takes a comma-separated `-ip` list and an optional `-dns`
   list. The client checks the server certificate against the address it
   dials, or against `server_name` if the client config sets one.

3. Try it in the foreground:

   ```sh
   askpass-server serve                      # listens on 10.99.0.2:7676
   askpass-server serve -listen 10.99.0.2:9000 -timeout 2m
   ```

4. Run it as a systemd user service tied to the graphical session:

   ```sh
   install -Dm 0644 contrib/systemd/askpass-server.service \
       ~/.config/systemd/user/askpass-server.service
   systemctl --user daemon-reload
   systemctl --user enable --now askpass-server.service
   journalctl --user -u askpass-server -f
   ```

   Edit `ExecStart` in the unit to change the address, port or timeout. The
   unit restarts the server until the private-network address is up.
   If requests fail with "dialog failed", check that the user manager has
   the session's display variables: `systemctl --user show-environment | grep
   DISPLAY` should list `WAYLAND_DISPLAY` (and `DISPLAY` for Xwayland). If they
   are missing, run `systemctl --user import-environment WAYLAND_DISPLAY
   DISPLAY` and restart the service.

The server can just as well run some other way, for example in a container,
as long as it can reach the desktop session's Wayland or X11 socket so zenity
can open a window.

## VPS setup

1. Install the client binary, e.g. to `/usr/local/bin/askpass` (that needs
   root, so do it yourself) or `~/.local/bin/askpass`.

2. Get it a certificate. Pick one of these two ways.

   **a) Key generated on the VPS (recommended: the private key never leaves
   the VPS).**

   ```sh
   # On the VPS:
   askpass --csr "$(hostname)"           # writes ~/.config/askpass/client.{key,csr}
   # Copy client.csr to the laptop, then on the laptop:
   askpass-server sign-csr -csr client.csr -out client.crt
   # Copy client.crt and ~/.config/askpass-server/ca.crt back to the VPS's
   # ~/.config/askpass/, then on the VPS:
   echo 'server = 10.99.0.2:7676' > ~/.config/askpass/config
   ```

   **b) Bundle generated on the laptop.**

   ```sh
   # On the laptop:
   askpass-server issue-client -name my-vps -server 10.99.0.2:7676
   # writes ./askpass-my-vps/{client.key,client.crt,ca.crt,config}
   scp -r askpass-my-vps my-vps:.config/askpass   # target must not exist yet
   rm -r askpass-my-vps     # don't leave the client key lying around
   ```

   Either way, the VPS ends up with:

   ```
   ~/.config/askpass/        (0700)
   ├── config                server = 10.99.0.2:7676
   ├── ca.crt                the askpass CA certificate
   ├── client.crt
   └── client.key            (0600)
   ```

   Check permissions with `chmod 700 ~/.config/askpass && chmod 600
   ~/.config/askpass/client.key`.

3. Use it:

   ```sh
   export SUDO_ASKPASS=/usr/local/bin/askpass
   sudo -A apt update
   ```

   sudo only calls the askpass helper when given `-A`. For agents that run
   plain `sudo`, either tell them to use `sudo -A` or put a wrapper earlier
   in their `PATH`:

   ```sh
   #!/bin/sh
   # ~/bin/sudo, ahead of /usr/bin in PATH
   exec /usr/bin/sudo -A "$@"
   ```

### Client configuration

The client reads `$ASKPASS_CONFIG_DIR/config`, else
`$XDG_CONFIG_HOME/askpass/config`, else `~/.config/askpass/config`. The file
holds `key = value` lines; `#` starts a comment.

| key           | default                 | meaning                                                   |
|---------------|-------------------------|-----------------------------------------------------------|
| `server`      | (required)              | `host:port` of askpass-server; the port defaults to 7676  |
| `server_name` | host part of `server`   | name or IP the server certificate must be valid for       |
| `ca`          | `ca.crt`                | CA certificate; relative paths resolve against the config dir |
| `cert`        | `client.crt`            | client certificate                                        |
| `key`         | `client.key`            | client private key                                        |
| `timeout`     | `90s`                   | give up on the whole exchange after this long             |

Keep the client `timeout` longer than the server's `-timeout` (default 60s)
so that a slow answer is reported as a server-side timeout.

## What the dialog shows

```
sudo password requested

Host:      my-vps (certificate "my-vps" from 10.99.0.1:51234)
User:      agent (uid 1000)
Command:   sudo -A apt install jq
Run from:  bash -c 'sudo -A apt install jq'
Directory: /home/agent/project
Prompt:    [sudo] password for agent:
Expires:   14:03:27
                                        [Deny] [Send]
```

- **Host** is what the client reports. The certificate name and source
  address next to it are the only fields the server verified itself.
- **Command** is the command line of askpass's parent process, normally sudo,
  so it is the command being elevated.
- **Run from** is the command line of whatever ran sudo.
- A red **WARNING** line appears when askpass's parent isn't a root-owned
  `sudo` process, meaning something ran askpass directly to read the password.
  Deny those unless you did it yourself.
- Client-supplied text is shown on single lines, with control and
  bidirectional-override characters escaped and Pango markup neutralised, so
  a request can't fake extra lines in the dialog.

Only one dialog is open at a time. Other requests wait their turn, and the
wait counts against their timeout. If the client gives up (sudo was
interrupted, or the client timed out), its dialog closes.

## Security model

**Authentication.** The laptop holds a private CA used only for askpass.
Connections are TLS 1.3 only.

- The server requires a client certificate that chains to that CA and carries
  the clientAuth usage. Unauthenticated connections never reach the dialog.
- The client trusts only that CA, never the system roots. It requires the
  server certificate to carry the serverAuth usage and be valid for the
  address it dialled. A client certificate can't stand in for a server
  certificate, and the other way round.

**The password.**

- It is typed into zenity and read from zenity's stdout pipe into one
  fixed-size buffer.
- It is sent in a single length-prefixed binary frame, not JSON, so it never
  goes through string conversions.
- The client writes it to sudo through its stdout pipe.
- Each buffer that holds it is zeroed as soon as it has been used.
- It is never logged and never written to disk. The server logs who asked for
  what and the outcome.
- Both binaries disable core dumps and mark themselves non-dumpable. That also
  stops other processes of the same user from ptracing them or reading their
  memory through `/proc`.

**No caching.** The server keeps nothing between requests. Each request is
one dialog and one answer.

**Timeouts.**

| stage                                 | limit                              |
|---------------------------------------|------------------------------------|
| TLS handshake and reading the request | 10s                                |
| waiting for an answer (incl. queueing)| server `-timeout`, default 60s; the dialog is then closed |
| whole exchange, on the client         | client `timeout`, default 90s      |

### Known limitations

- **Approving a request hands the password to the VPS user account.** sudo
  runs askpass as the invoking user, so `client.key` has to be readable by
  that user. Anything running as that user, such as the agents themselves,
  can connect with that key. It can run `askpass` directly, or speak the
  protocol itself, and read the password you send. Everything the dialog
  shows except the certificate name and source address is asserted by the
  client and can be forged by such a process. The dialog is the security
  boundary: approve only requests you expect, and treat a surprising one
  (or a WARNING line) as a reason to deny and investigate.
- **sudo caches credentials.** After one successful prompt, sudo by default
  won't ask again for 15 minutes on the same terminal (`timestamp_timeout`).
  askpass caches nothing, but sudo does. If every sudo should prompt, set
  `Defaults timestamp_timeout=0` in sudoers.
- **Zeroing is best effort.** Go can't guarantee that no copies exist. Copies
  can remain in TLS library record buffers, the kernel's pipe buffers,
  zenity's (GTK's) own memory, and sudo's. The process memory isn't locked,
  so it could be swapped out; use encrypted swap if that matters to you.
- **No revocation list.** To revoke a client certificate, create a new CA in
  a fresh `-dir`, then reissue the server certificate and every remaining
  client certificate.
- **No rate limiting.** A client holding a valid certificate can queue dialog
  after dialog. Anyone on the private network can open TLS handshakes, but
  those are dropped after 10 seconds without a valid certificate.
- **Who is "sudo" is checked by name and EUID.** The WARNING line relies on
  `/proc/<parent>/status` showing a process named `sudo` with effective UID 0.
  It catches accidental and casual direct use, not a deliberate forgery (see
  the first point).

## Development

```sh
go vet ./...
go test ./...
```

The tests cover everything except a real dialog and a real sudo:

- the wire format and its limits
- certificate issuance and verification, including wrong CA, wrong address
  and wrong usage
- sanitising of dialog text
- the zenity exec path (send, deny, zenity timeout, kill on deadline,
  oversized output), driven by a shell script standing in for zenity
- full mTLS exchanges over loopback: relay, deny, timeout, client hangup,
  serialised dialogs, no caching, and rejection of foreign or missing
  certificates

To try the whole thing by hand on one machine, put a stand-in for zenity on
the server:

```sh
D=$(mktemp -d)
export ASKPASS_SERVER_DIR=$D/laptop ASKPASS_CONFIG_DIR=$D/vps
bin/askpass-server init-ca
bin/askpass-server issue-server -ip 127.0.0.1
bin/askpass-server issue-client -name test -server 127.0.0.1:7676 -out "$ASKPASS_CONFIG_DIR"
printf '#!/bin/sh\necho hunter2\n' > "$D/zenity" && chmod +x "$D/zenity"
bin/askpass-server serve -listen 127.0.0.1:7676 -zenity "$D/zenity" &
sleep 1
bin/askpass 'test prompt: '    # prints hunter2
kill %1
```

## License

Apache 2.0, see [LICENSE](LICENSE).
