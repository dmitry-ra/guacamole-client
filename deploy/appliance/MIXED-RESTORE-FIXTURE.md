# Already-mixed physical backup and restore fixture

`tools/test_mixed_restore.py` closes the separate already-MIXED backup/restore
gate. Schema1 restore followed by append migration is different evidence and
does not satisfy this gate. Earlier passed receipts remain immutable.

This fixture uses the exact candidate image and disposable endpoint image from
the reviewed native/mixed fixtures. Its new root-private case must be outside
production DATA, secrets, code and configuration namespaces. All accounts,
TOTP material, Windows password placeholders and application keys are generated
synthetic inputs; no owner credentials or endpoint is read or contacted.

```
sudo /absolute/python-with-aiohttp tools/test_mixed_restore.py \
  --image sha256:EXACT_CANDIDATE_IMAGE_ID \
  --endpoint-image sha256:EXACT_ENDPOINT_IMAGE_ID \
  --native-receipt /absolute/native-case/result.json \
  --native-receipt-sha256 EXACT_NATIVE_RESULT_SHA256 \
  --browser-uid EXPLICIT_NONROOT_UID \
  --directory /absolute/new-protected-private-case
```

For an isolated cross-version rehearsal, add
`--source-image sha256:EXACT_ACCEPTED_OLD_IMAGE_ID`. The producer then uses that
immutable old image; the restored runtime and native refusal evidence remain
bound to `--image`. Without this option, both roles use `--image` as before.
Both selected images must already exist locally and pass exact ID inspection.
The result retains `image` as the restored target and records `source_image`
plus the explicit producer/restored `application_images` map. Container state
and cleanup retain each role's own image identity. No existing DATA, image or
passed receipt is changed; this option only prepares fresh synthetic old-image
DATA in a new isolated case. A same-image pass is not cross-version evidence.

The real source producer prepares a fresh schema2 PG16 cluster through the
packaged runtime, with two RDP entries and one SSH entry, IDs1/2/3 and confirmed
synthetic TOTP. Full principal/account/TOTP rows and the complete native JDBC
census are hashed, never exported. Its root preparation receipt and exact
configuration hashes are recorded. The producer shuts down its actual PG16,
exits0 and is removed only after full CID/image/run-label/network verification.
No postmaster.pid or container bind consumer may remain before copying.

The tool invokes the existing cold_copy.stopped_and_exclusive, validate_cluster,
copy_tree and full manifest primitives against three retained bind directories:
source-data -> backup-data -> restored-data. Before restored startup, all three
complete manifests must match and their directory identities must be distinct.
The normal CURRENT prepared receipt is retained without stripping, rewriting or
migration. Source and backup remain frozen through the entire restored browser
test. The synthetic secrets directory is a separate root0700 directory of
root0600 files, excluded from every DATA copy and manifest; no secret value,
length or hash is put in the result. Retain it separately for controlled lab
reproduction; never include it in an evidence transfer bundle.

This is an explicitly lab-only physical-copy primitive gate. It does not call
the production backup CLI, fabricate a loaded/inactive systemd unit or produce
a production cold_copy backup/restore receipt. Actual producer shutdown,
ownership, container absence, exclusive mounts and full frozen trees provide
the isolated fixture's stop proof. Production service/lifecycle backup admission
remains the separate operator workflow.

Only restored DATA is served, in a new owned exact-image container sharing the
disposable endpoint's loopback-only network namespace. Before authentication,
the same packaged runtime queries must reproduce the source identity/census/
prepared/config proof exactly and confirm IDs1/2/3 and enrolled state. Ordinary
native TOTP authentication later updates replay/account state as expected; full
row equality is asserted before that authentication, not falsely claimed after.

The existing accepted mixed browser implementation is reused unchanged:
nonroot sandboxed own Chrome, native username/TOTP and three-entry JDBC tree,
actual SSH via packaged Java key injection, exact received Cyrillic/lambda/CJK
BMP UTF-8 bytes, measured PTY resize and same pane PID/start/counter after owned
disconnect/reconnect. Own logout204 and packaged post-browser health are
required. RDP entries are checked for native alias routing only; actual Windows
or synthetic RDP canvas acceptance is not claimed. Supplementary Unicode and
visual glyph correctness remain outside this test.

The restored runtime is stopped gracefully and must remove postmaster.pid.
All owned containers, relays and browser processes are cleaned up; original and
backup full manifests must still match the frozen source. All three DATA trees
and the separate synthetic secrets are retained in the private case. Failure
keeps incomplete copies for review and never overwrites/replays an existing
case. The whole controller alarm is360seconds plus bounded cleanup; container
leases independently bound interrupted execution. No product module is
overlaid, rebuilt or changed, and no host network, service or owner browser is
modified.

The result records hashes, exact image/source identities, three DATA directory
identities, frozen manifest hash, before/after identity proof, safe browser
observations, health and cleanup. Raw SQL rows, keys, tokens, TOTP codes,
terminal text, screenshots and container logs are not retained. The source must
receive independent review before a fresh actual run. Inert proof boundary tests
are in tools/test_mixed_restore_boundaries.py; they do not replace the native run.
