# Conditional passive handshake audit

`audit_guacd_handshake.py` is prepared for a separately reviewed fresh isolated
synthetic RDP trial. Preparation and inert tests do not authorize invocation.
Root and the deployment reviewer own fixture lifecycle and the finite capture.
No completed trial should be restarted merely to collect these observations.

Run the helper as host root with no arguments, feeding a bounded private JSON
admission as one newline-terminated line on stdin. Keep the stdin pipe open
throughout the trial; close it in the parent's finally block to end observation
cleanly (including incomplete flow reports). Any extra stdin byte is rejected.
Do not use file redirection, which closes stdin at the initial admission.
Do not include secret values in command arguments,
environment, admission or logs. Required exact keys:

* `cid`: full 64-character owned fixture container ID.
* `image`: exact selected image SHA256 (without prefix), pinned in the helper.
* `token`: existing fixture ownership label token, 32 lowercase hexadecimal digits.
* `pid`, `start_ticks`, `netns_inode`: admitted init process identity integers.
* `config_path`: exactly `/proc/PID/root/config/config.json`.
* `config_sha256`: SHA256 of that mounted synthetic catalog.
* `targets_path`: exactly `/proc/PID/root/targets.json`.
* `targets_sha256`: SHA256 of those mounted synthetic credentials.
* `seconds`: integer from 1 through 180; no retry or reconnect exists.

The helper verifies exact Podman ID/image/running PID/fixture label, init start
ticks, cgroup membership and a distinct network namespace before setns. It reads
only the two exact mounted files: config root0644, targets root/UID1000 mode0600,
regular bounded files with exact SHA256 and duplicate-free JSON. The existing
catalog parser validates configuration. Only two synthetic loopback TLS targets
on ports33389/33390, usernames `pa`/`pb` plus ten lowercase hexadecimal digits,
matching synthetic certificate/credential records and exact secret references
are admitted. Actual passwords exist only in process memory for equality checks.

It enters only that admitted network namespace and creates a passive AF_PACKET
socket bound to `lo`. A classic kernel BPF filter admits only unfragmented IPv4
TCP with both addresses127.0.0.1 and source/destination port4822, excluding HTTP
before userspace. It does not proxy traffic, connect, change routing, install a
service, start/stop a container, execute in a guest or write a capture file.

Wait for `{"capture_ready":true,...}` before starting the already authorized
browser authentication trial. Preserve only stdout as sanitized evidence. There
are at most eight SYN-observed flows. Each direction retains at most128KiB of
stream state (256KiB per flow); duplicate/out-of-order/consistent overlapping TCP
segments and sequence wrap are supported. Conflicting overlaps, missing SYN,
malformed framing or bounds stop or reject the affected observation. Ports are
not reused within one invocation; use fresh fixture connections. Packet loss or
late attachment can therefore produce incomplete evidence, never inferred
success. Raw packets, arguments, connection IDs and unknown parameter names are
never serialized. No persistent raw buffer, PCAP or secret file is created.

Each emitted flow contains its ordinal, inferred fixed target alias, phase epochs,
per-known-parameter equality booleans (password included), password-placeholder
boolean, unknown-key count, ready boolean and numeric error status. Unknown keys
are counted only. `comparison_observed` is true only when a connect parameter
mapping and exactly one expected target port were observed. A ready boundary
without that mapping retains ready=true but complete=false; absent equality
evidence must never be inferred from ready. Error status is limited to0..65535.
Parsing stops at the first ready/error and immediately clears
retained raw stream buffers. Subsequent packets can transiently reach the shared
filtered socket but are discarded by flow identity without protocol decoding,
payload retention or output. A received packet can contain bytes beyond ready;
these are discarded without interpreting subsequent instructions. Deadline,
close, unexpected instruction or rejected stream yields incomplete evidence.
Ready means the guacd handshake boundary only: the pinned server sends ready
before backend logon. It does not prove RDP authentication or display acceptance.

The helper's195-second process alarm includes input/inspect overhead. The parent
must additionally enforce an external finite process deadline and stop its own
fixture only under its existing identity guards. The helper has no cleanup or
lifecycle authority and does not verify identity after entering the namespace;
the parent must retain the exact fixture throughout the bounded observation.

Inert checks (no sockets, inspect, namespaces or guest operations):

```
python3 -B -m unittest discover -s deploy/appliance/tools -p test_audit_guacd_handshake.py -v
```

Source compilation can use Python `compile()` without writing bytecode. No
dependencies, build, installation, network access or live capture are needed.
