# Browser target selection

This is a resource for our current-main Guacamole fork, not a replacement
frontend. The initial source baseline is
`a8daafeb38b60b0acb4059c5218e6d5bacfaeb8f`. Authentication events, native
`userPageService`, and the native form insertion API used below are unchanged
from the accepted private implementation. Source compatibility does not prove
packaged authentication or desktop acceptance.
Package `target-selection.js` in the provider JAR at its root and list it in
`guac-manifest.json` as `"js": ["target-selection.js"]`. Package
`translations/en.json` and list it under `"translations"`. No replacement HTML is required; the packaged CSS aligns only the target
field with the native login form: the Java provider supplies the native dynamic `wrdp-target` EnumField.
The `js` key matches the upstream TOTP manifest. The generic login header is
`Server`. A narrow form-service decorator renders validated aliases directly as
escaped select-option text, without treating them as translation keys. It only
handles this one enum in the LOGIN namespace and retains native select model
normalization. No instance-specific labels are baked into the image.

The login link is `/desktop/#/?wrdp-target=desktop-a` (adjust only the application
base path). A proxy may redirect `/desktop/connect/desktop-a` to that link.
Only hash-route query parameters are consumed; ordinary pre-hash query strings
are not interpreted by this resource. Aliases follow the catalog grammar:
lowercase letter first, lowercase alphanumeric segments separated by single
hyphens, at most 48 characters. Duplicate query values become arrays in Angular
and are rejected. A general `/desktop/` with no selected field retains native
connection chooser, including with a saved authentication token or a single
available connection. Native permission and tree loading still run; the
resulting default client route is replaced with `/`. An explicitly empty target is invalid.

The eager service reads the hash query before the first authentication attempt.
`guacLoginPending` supplies a promise; its callback is registered before native
request serialization. A nonempty dropdown value overrides the link. A blank
enum retains an existing link selection. An untouched blank enum without URL
intent retains the native connection list. The remembered alias is injected into
later requests which omit it, including TOTP challenges and login retries. On
`guacLogin`, the selected alias replaces the hash query in this tab, so the
native route reload cannot restore an old link alias over the dropdown choice.
Fresh explicit hash-query navigation also updates the selected alias. Removing
the query field clears explicit intent and restores the connection chooser;
an authentication continuation which merely omits the field preserves intent.
Selection revisions and request generations discard late parameter callbacks and
late lookup success/failure from an earlier selection. Stale home resolutions
remain pending and cannot navigate or display an old error over the new target.

All state is in the tab's Angular service and URL. No target cookies, session
storage, localStorage, token changes or cross-tab target state are introduced.
Native authentication-token storage remains unchanged.

After authentication, only `getHomePage()` is decorated. It requests the current
authenticated PostgreSQL connection tree filtered by `READ`, searches child
connections recursively, and requires exactly one `connection.name` equal to
the alias with a decimal-string JDBC identifier. Provisioning must set JDBC
`connection.name` to the alias exactly; database identifiers may change freely.
Other data sources, balancing groups, host/port/password parameters and arbitrary
URL forwarding are never used. The resulting page uses native `ClientIdentifier`
and `PageDefinition`. The server remains responsible for authorization on every
connection and for validating configured target aliases.

Invalid, unauthorized, missing, duplicate or failed lookups broadcast the native
fatal-page event and deliberately leave the home-route promise pending. Native
home-route rejection falls through to home, and route success clears fatal-page
state; neither is appropriate for explicit invalid intent. This follows native
`userPageService`'s own pending deferred on `requestService.DIE`. It never calls
the native default selector for an explicit target. Recovery is a valid link or
a page reload after correcting the link.

Run isolated checks from the repository root:

```sh
node --test deploy/appliance/web/test-target-selection.cjs
```

Tests load the real upstream `ClientIdentifier` and `PageDefinition` factories
with inert Angular/service mocks. They cover target IDs, READ lookup arguments,
dropdown/link precedence, parameter-promise timing, TOTP/retries, independent
tabs, fresh URL selection, malformed/duplicate query values, duplicate names,
authorization failure, wrong data source, malformed trees/identifiers, encoding
exceptions, URL removal, deferred/out-of-order callbacks and alias-only dropdown
rendering. They make no network requests. Browser/real Angular digest integration,
proxy redirects, Java EnumField rendering and full authentication/RDP acceptance
still require the appliance's isolated end-to-end rehearsal.


A focused real-Angular rendering check is also available:

```sh
python3 deploy/appliance/web/browser/test-target-selection.py --artifacts /path/to/new-evidence
```

This standalone fixture uses current source login/form templates, controllers,
formService and styles, together with the actual portal JavaScript/CSS. It
checks all three synthetic aliases, direct-link preselection, actual Angular
selection updates, disabled state, label association and initial/continuation
layout. Exact npm inputs are taken from the frontend lockfile and verified by
SHA512. It uses a new temporary sandboxed Chrome profile and loopback HTTP;
its temporary downloads/profile are removed on exit. Evidence is retained only
at the explicit output path and may be removed after review.

REST and navigation services are inert fixture inputs. This is not a complete
WAR, API authentication, TOTP, RDP, SSH/tmux or mobile acceptance test. The
source-built image must still pass those independent gates. The command is
operator-invoked, not automatically discovered by Maven or CI.
