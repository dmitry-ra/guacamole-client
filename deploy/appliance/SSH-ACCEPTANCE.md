# Private mixed RDP/SSH acceptance design

This document defines gates, not completed native acceptance. No production
SSH login, key installation, image build or network change is authorized by
preparing these sources. Keep actual users, endpoints, host keys, private keys,
DATA and evidence outside tracked source. The example catalog's host key and
unit-test key structures are synthetic and must never be installed as identities.

The exact clean image must expose native RDP and SSH guacd plugins and compile
its updated Java provider/tests. Preserve the existing two RDP aliases, native
parameters, numeric IDs, default alias and personal TOTP identity. Schema 2 adds
one SSH alias, an exact endpoint-bound full known-host entry, an external
unencrypted OpenSSH Ed25519 private-key filename and a fixed absolute launcher.
The native libssh2 handshake may prefer ECDSA nistp256 to Ed25519 for the server
host key; obtain the actual negotiated key through a trusted operator channel
and pin it explicitly. A changed or missing key must fail before authentication.

Use a dedicated application key, distinct from transport/admin/agent keys.
The server's authorized-key entry forces the reviewed root-managed launcher,
disables forwarding/agent forwarding/X11/user rc, and permits only the PTY needed
for the terminal. The launcher must reject unexpected original commands, unset
TMUX/TMUX_PANE, select an explicit separate private tmux socket/config/session,
and start a clean shell without automatic profile/rc loading. Never select,
attach to, send keys into or kill default/agent tmux servers or panes. Using an
existing owner account does not make a separate socket an account isolation
boundary. Root must inspect noninteractive shell startup and session cleanup
policy before installing the application key.

Reuse the restricted host transport through one additional exact gateway
listener/remote destination. Both authorized-key PermitOpen and sshd policy
must enumerate only the approved tuples; local appliance INPUT policy permits
only that gateway listener. Do not add direct public SSH egress or public RDP,
SSH-proxy or guacd listeners. A transport update must preserve all old rules,
keys/configuration and rollback, and may not interrupt active owner sessions.

Required isolated synthetic gates before mixed production:

1. Fresh schema-2 preparation and independently restored current-format
   migration preserve old RDP IDs/parameters, account/TOTP rows and default.
   Wrong old config/preparation mapping or modified old targets fail closed.
2. Real native SSH accepts the exact host pin and application key. Wrong pin,
   wrong key, encrypted/malformed/oversized key and an unapproved command fail;
   no fallback password is supplied or accepted. Check that server NONE auth
   is unavailable. No private key reaches JDBC JSON, logs, screenshots or receipts.
3. Native username/TOTP and alias selection reach both synthetic RDP canvases
   and the SSH terminal with the same browser identity. Existing RDP/browser
   regression checks remain independently required for the rebuilt exact image.
4. In the fixture's dedicated tmux session, create one harmless controlled
   process and retain only its PID/start identity and a synthetic counter. Close
   the owned browser/SSH tunnel, reconnect once and prove the same process and
   counter survive. Test native resize/UTF-8 on synthetic output. Export no
   real terminal history, desktop text, screenshots or credential material.
5. Prove that separate/default/agent socket and process identities remain
   untouched; wrong-pin/key failure cannot affect the two RDP targets. Confirm
   owned token logout and full owned browser/container/process cleanup.
6. Independently back up/restore the mixed DATA with external secrets handled
   separately, rerun identity/census/connection acceptance, and retain a working
   RDP-only rollback. Root then reviews exact image/config/network/release/CID/run
   proofs before any production change or fresh public mixed acceptance.

The current two-target live driver and RDP cutover admission require explicit
mixed-target extensions before they can admit a three-target deployment. A
transport pass, structural key parser, Java fake-connect harness or terminal
protocol activity does not replace these native/browser/persistence gates.
