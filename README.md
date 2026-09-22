# OIE TOTP MFA

TOTP multi-factor authentication for Open Integration Engine administrator login.
After a successful password login, new users enroll an authenticator; enrolled
users enter a current six-digit code. The web administrator supplies the built-in
OTP login UI. The plugin also ships a **Two-Factor Authentication** Settings panel
for authorized administrators to reset lost or replaced devices.

## Compatibility and installation

Requires an OIE 4.6-compatible engine, Java 17 or later, and a web administrator
with the `builtin:otp` handler. **Stock Swing Administrator login is unsupported**:
it cannot load that web authenticator. Enrollment is mandatory, so confirm the
web login UI is available before enabling the extension.

```sh
OIE_HOME=/path/to/oie mvn verify
```

Install the generated extension ZIP from Extensions and restart. The web support
plugin must be available to discover the bundled recovery Settings panel.

The extension ships its own JAR, five database mappers, descriptors, and one web
bundle. The engine supplies its APIs, MyBatis, Jackson, logging, and servlet
libraries. React comes from the web host. Node, npm, esbuild, database test
drivers, and test frameworks are build/test tools and are excluded from the ZIP.

## Login and recovery

1. Sign in with your existing credentials.
2. At first enrollment, scan the QR code or enter the displayed key in an
   authenticator app, then confirm a code.
3. Subsequent logins ask for the current authenticator code.
4. A user with the engine's `manageUsers` permission can reset a lost or replaced
   device from Settings. The next login starts enrollment again.

Each challenge expires after five minutes and can complete only once. Starting
another primary login replaces that user's previous pending challenge. Five
invalid attempts in a five-minute window temporarily block further challenges.
Starting another login or resetting a device does not clear the attempt budget.
Database and decryption failures reject authentication.

Reset requests carry the enrollment generation shown by the panel. A request for
an older generation receives HTTP 409 and cannot remove a newly enrolled factor.
Reload the list before retrying. Both recovery endpoints and the generic TOTP
property endpoints require `manageUsers`.

If the web client or MFA storage prevents recovery, an operator with server
access can explicitly bypass MFA by restarting with
`-Dorg.openintegrationengine.totp.disabled=true` or `OIE_TOTP_DISABLED=true`.
Logins then use primary authentication only. Resolve the problem, remove the
switch, and restart to restore MFA.

## Authentication and storage

The first authentication leg records a random, opaque challenge in the engine
database. Only a SHA-256 token hash is stored for lookup. The pending payload,
including any enrollment secret, is encrypted with the engine's encryptor.
The second leg sends `X-Mirth-Login-Data: base64(JSON{challenge,code})`.

A transaction locks the user's MFA state, checks the current identity and
password state, enforces the attempt budget, verifies the code, persists the
accepted time step, and consumes the challenge before returning success.
Enrollment, verification, challenge replacement, and reset serialize on the same
row across engine nodes. A reset preserves a state row so old challenges cannot
recreate a removed factor. No challenge-signing key is needed or trusted.

`USER_TOTP_STATE` holds encrypted credentials, the last accepted time step,
enrollment generation, pending challenge, and attempt counters.
`USER_TOTP_META` records migration completion. The only supported plugin
property is the public authenticator issuer label, `totp.issuer`.

Keep the engine encryption keys and a consistent backup of the complete engine
database. Copying only one TOTP table does not constitute a valid restore.

## Upgrading earlier TOTP versions

Startup imports the legacy `USER_TOTP` table once. Both the older username-keyed
schema and the numeric-user-ID schema are supported. Existing encrypted secrets,
enrollment timestamps, and replay counters are preserved. The migration marker
prevents later restarts from reimporting a factor that has been reset.

Migration uses a transaction and a shared migration lock. Incomplete work rolls
back and is retried at startup. Identity ambiguity, unreadable secrets, and
database errors prevent authentication. Correct the underlying problem before
retrying. The legacy table remains as an upgrade input; it is no longer
authoritative after successful migration.

Enrollments belonging to confirmed deleted accounts remain archived in the
legacy table and are not imported. Lookup failures and ambiguous identities are
errors, rather than treated as deleted accounts.

The database user needs permission to create the state/metadata tables and read
and update them. On a fresh SQL Server installation, proving that no legacy
table is hidden requires database `VIEW DEFINITION` permission (`db_owner`
already covers it). For Oracle, a fresh install must use the database user's own
current schema without an inaccessible `USER_TOTP` synonym. An accessible legacy
table is detected through its actual unqualified SQL name, including a PostgreSQL
search path. A table that exists outside that path is reported as an error.

Deploy the new plugin to all nodes sharing the database together. Mixed old/new
versions use different state tables and are unsupported. Pending login
challenges from older versions are invalidated; users start a fresh login.

## API

- `GET /api/extensions/totpmfa/enrolled` returns JSON text containing
  `{users:[{id,username,generation}]}`. The engine wraps Java String responses;
  clients decode that envelope and then parse the JSON text.
- `POST /api/extensions/totpmfa/reset/{userId}?generation=...` resets only the
  displayed generation. Missing input returns 400; stale state returns 409.

## Validation

`mvn verify` compiles Java and the web bundle, runs Java/database regressions and
Node's built-in web tests, then inspects the actual ZIP for missing resources or
unexpected dependencies. Test databases are isolated and removed after use.
Release builds run the same verification before publication.

MPL-2.0.
