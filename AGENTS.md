# Personal portal fork

This checkout starts from Apache guacamole-client main, pinned initially to
a8daafeb38b60b0acb4059c5218e6d5bacfaeb8f. Preserve upstream history, LICENSE
and NOTICE. The owner requests a maintained personal fork, not an Apache submission.

Port the accepted personal portal from the private preparation repository.
Build the actual selected client source, not a released 1.6.0 WAR. Support
current Java LTS only; do not add old-Java compatibility work. Keep changes
separated by component for review. No public PR/Jira requests to Apache.

Read deploy/appliance/README.md and tools/README.md before appliance changes.
Some copied documents describe the former 1.6.0 implementation and historical
intermediate states; they are not proof that the new main-based build works.
Record actual new build and acceptance evidence outside tracked source.

All new source/docs are English ASCII. Keep actual hosts, usernames, endpoints,
passwords, keys, instance data and evidence outside Git. Use synthetic fixtures.
At most two build workers globally. PR checks may use bounded standard free
public GitHub-hosted runners with read-only permissions and no private inputs.
No paid/larger runners, hosted deployment, cache/artifact or image publication.
Do not commit, push or publish until the concrete reviewed scope is authorized.

Preserve the accepted deployed portal and the clean private repository. No
production activation before independent restore/migration rehearsal, all RDP
and SSH/tmux acceptance, preserved TOTP identity and a working rollback.
Never expose RDP or guacd publicly or terminate the owner's active session.
