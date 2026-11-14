# Complete candidate-image fixture

`test_image.py` accepts an exact local clean-build image digest and a new private
evidence directory. Run with Python containing aiohttp and an installed Chrome:

```sh
python3 deploy/appliance/tools/test_image.py --image EXACT_LOCAL_SHA256 --directory NEW_PRIVATE_DIRECTORY
```

The caller needs noninteractive sudo for Podman, namespace entry, stat and
ownership of the one generated synthetic configuration file. The fixture creates
one labeled rootful container, without any network interface except loopback,
with read-only root and configuration, private tmpfs data/secrets, two CPUs,
bounded memory/processes and a runtime lease below 600 seconds. Only the test
driver is mounted separately; candidate runtime modules, native binaries, WAR,
Java extensions and browser resources come from the exact image. Preparation
uses the real runtime integrity/configuration entrypoint. Synthetic confirmed
TOTP attributes are seeded into its new disposable PostgreSQL cluster.

A temporary host listener binds only loopback in lab ports 10820 through 10839.
Each connection revalidates container ID, image, ownership label, running PID
and network namespace inode before entering only that namespace and relaying
to its fixed loopback port 8080. Concurrency is limited to eight. The container
has no route to configured documentation-only RDP addresses or any real target.
The listener is a test transport, not a production reverse proxy test.

The assertions cover the packaged WAR startup hold, username/optional target
form without a portal password, native TOTP challenge/wrong/valid/replay cases,
two authorized JDBC connections, native logout, and actual Chrome/Angular
resource registration, dynamic alias dropdown, dropdown-over-link selection
through TOTP, both native client identifiers with an existing token, and an
invalid link that remains pending with a fatal error instead of opening default.
Chrome uses a fresh disposable profile; no owner browser is attached.

Finally, the listener, relay children and browser close. Only the container with
the fresh ownership label and exact image/ID is stopped and removed, and its
absence is verified. Container logs, keys, codes, tokens and request bodies are
not saved. `receipt.json` records assertion names, image/configuration/driver
hashes, health, success or failure type and verified container cleanup. The
private synthetic configuration remains with that receipt; it contains no keys.

This establishes complete image startup and authentication/frontend acceptance.
It does not establish actual RDP success, two independent Windows desktops,
production proxy behavior, migration/restore or SSH acceptance. Those require
separate independently isolated target and migration rehearsals.
