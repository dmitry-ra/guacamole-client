# Synthetic RDP browser acceptance

`tools/test_rdp.py` exercises the exact complete candidate image against two
explicitly supplied disposable XRDP targets. Use Python with aiohttp and a local
Chrome, a new private evidence directory, and noninteractive sudo for Podman,
network namespace entry and ownership of the generated synthetic config.

```sh
python3 deploy/appliance/tools/test_rdp.py \
  --image EXACT_LOCAL_SHA256 --directory NEW_PRIVATE_DIRECTORY \
  --targets PRIVATE_SYNTHETIC_CREDENTIAL_JSON \
  --targets-sha256 EXPECTED_CREDENTIAL_SHA256 --address EXPECTED_FIXTURE_IPV4
```

For a separately authorized A/B investigation, --markers-only omits the
independent beta-stop stage. Its receipt always keeps passed=false; require
both diagnostic_complete=true and cleanup_verified=true for a completed
marker diagnostic. Diagnostic mode never emits both-connected.json. Numeric
per-alias state, status, dimensions and marker counts are retained even when a
marker fails; no desktop screenshot or content is retained by that telemetry.
This diagnostic is not full RDP or independent-failure acceptance.

The credential file must be mode0600, match its independently supplied digest,
contain exactly alpha and beta in that order, and use the explicitly supplied
IPv4 on 3389 and 3390. Its schema is the output of `synthetic_rdp_targets.py`:
each target contains alias, username, password, address, port and
certificate_sha256. Duplicate and unknown fields are rejected. Verify the
guest hostname and DMI UUID through the target fixture before supplying this
file; this driver does not open SSH or discover credentials.

The candidate runs read-only with networknone, two CPUs, bounded memory/PIDs,
six explicit runtime capabilities and a 510-second runtime lease. It has fresh
tmpfs PostgreSQL data and secrets, a synthetic confirmed TOTP identity and the
exact read-only target credential file. Only the driver and external config
are mounted; all runtime components come from the exact image.

The candidate catalog names only 127.0.0.1:33389 and 33390. A helper enters only
the owned candidate's network namespace and binds those exact loopback ports.
It uses the host filesystem to connect to two AF_UNIX sockets inside the
mode0700 evidence directory. The application has no mount of those sockets or
the host filesystem. Host-side async listeners forward each socket only to
the corresponding declared fixture IPv4/port. Concurrency is bounded at eight,
connections at 120 seconds and the namespace helper at 480 seconds. HTTP reaches
candidate loopback 8080 through the separate bounded namespace relay inherited
from the complete-image fixture. Exact CID, image, ownership label, PID and
namespace inode are checked before relay setup and each new host relay. There
are no host firewall, bridge, route or production service changes.

A disposable Chrome logs in through the native username/TOTP forms and opens
both target links. Each must reach native CONNECTED with status 0, receive a
nonblack desktop and contain thousands of pixels matching its distinct target
marker: darkgreen for alpha and navy for beta. The exact target certificate
pins are passed through the real catalog to the native RDP client.

After `both-connected.json` appears, an independent operator runs the target
fixture's `stop-beta` action and writes `beta-stopped.json` in this evidence
directory only after checking its successful receipt. The browser requires
beta to disconnect while alpha remains CONNECTED and accepts a mouse event.
The driver then logs out its own session and requires enrolled healthy runtime
state. It records only nonsecret states/pixel counts, hashes and cleanup status.
It does not save passwords, tokens, TOTP codes, request bodies or container logs.

Finally all listeners, relay children and its Chrome close. Only the exact
owned container is stopped/removed and its absence is verified. Failed attempts
retain separate receipts and must use a new evidence directory on retry.

This is synthetic TLS XRDP acceptance. It does not establish Windows NLA,
production routing, independent restore/migration, SSH or deployment acceptance.

## Current-main synthetic result, 2026-11-14

The exact candidate image
`55f55e7abbc8ececed4f9f5ce69ca956469b584f0003bd59c8f4a0e713e63991`
passes the full synthetic TLS two-target gate: both native clients reach
CONNECTED/status0 and render their distinct green/navy canvases. Independently
stopping beta disconnects beta while alpha remains connected. Own logout,
enrolled runtime health and exact owned cleanup also pass. The private receipt
binds the fixture source SHA256
`d5db05087e491a8a28bf0beeda36c38e52644678f2e615097fbd4ddaea8c31f8`.

Earlier ordinal timeouts were caused by the test HTTP relay retaining its
eight active slots after backend EOF. The fixture now cancels the remaining
client-to-backend pipe on backend EOF and releases the slot; client half-close
still permits the backend response to finish. No product or image change was
needed. This result is full synthetic acceptance, not a markers-only diagnostic.
The same image separately passes a private-loopback actual Windows NLA browser
run on a fresh genuine installation: both native clients reach CONNECTED/status0
with nonblack canvases, twenty-second holds, authenticated refresh and logout204.
Read-only guest observations confirm Active sessions during the holds and
Disconnected sessions after cleanup. An independent host lifecycle separately
passes reboot, recovery and owned removal with synthetic pre-enrolled DATA.
These separate results retain their scopes. An ensuing integrated same-VM
run passes actual Windows and dedicated external synthetic SSH/tmux access
through reboot, independent restore, matched rollback and owned removal,
including separate first-route failure isolation. Matched native correct-pin
and sole-wrong-pin controls establish certificate rejection with a fixed
source-derived diagnostic. Those private results do not establish a fresh
published-main build or its production HTTPS acceptance.

## Historical result, 2026-11-12

The exact clean image
`ee6a15e51c8afce00ee51364e3e4280e5caee69ffb5b59189ba1db0b466a6d65`
passed the complete synthetic two-target browser run. Both native clients
reported CONNECTED/status 0 with 1100x800 displays. Alpha contained 126900 green
pixels and no navy pixels; beta contained 127365 navy pixels and no green
pixels. Both had 140454 nonblack pixels. Correct, distinct target certificate
fingerprints were used by the actual native RDP connections.

The independently stopped beta changed to DISCONNECTED/status 0 while alpha
remained CONNECTED/status 0 and received a mouse event. Own native logout
completed, and database_ready, web_ready and enrolled were all true afterwards.
The exact owned candidate container was removed, its absence checked, and no
driver, namespace helper or Chrome process from the run remained. No host
network changes were made. Private receipts bind the image, generated config,
credential digest and exact driver SHA256
`38393ca3a0a0f3374d0099cffc5d2e7a3aebb1baf6293f01dcfd18beb093b214`.

An earlier attempt failed before target connections because the driver tried
to create target secret files twice. Its cleanup passed; the successful retry
used a separate evidence directory after correcting that fixture defect.
Wrong-certificate rejection has not been established by this run.
