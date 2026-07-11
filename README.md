# OIE TOTP MFA

A **TOTP (RFC 6238) multi-factor authentication** plugin for Open Integration
Engine administrator login. Enrolled users are challenged for a time-based one-time
code after their password; per-user secrets are stored encrypted in a dedicated
`USER_TOTP` database table, with one-time-use (replay) protection.

**Self-enrollment as a login step — no admin configuration, no settings page.**

1. Install the plugin and restart the engine.
2. A user's **first login**: after their password, the login screen shows a secret
   (key) to add to an authenticator app and asks for a confirming 6-digit code. On
   success the secret is stored (encrypted) for that user.
3. **Every login after**: after their password, they're prompted for the current
   6-digit code.

The setup UI *is* the login flow — the same `ExtendedLoginStatus` → authenticator
handshake, distinguished by a `mode` (`enroll` first, `verify` after).

## How it works

Two stateless server legs (`MultiFactorAuthenticationPlugin`):

- **Leg 1** `authenticate(username, primaryStatus, serverURL)` runs after a
  successful password login. It returns an `ExtendedLoginStatus` naming the
  client-side authenticator (`clientPluginClass`) with a JSON message: either
  `{mode:"verify", challenge}` or, for a new user, `{mode:"enroll", challenge,
  secret, otpauthUri}`. `challenge` is a **signed token** ([`Challenge`](src/main/java/org/openintegrationengine/plugins/totp/Challenge.java))
  carrying the user's numeric id, the mode, and (for enrollment) the pending
  secret — so leg 2 needs no server-side session.
- **Leg 2** `authenticate(loginData)` runs with only the `X-Mirth-Login-Data`
  header the client sends (`base64(JSON{challenge, code})`). It verifies the
  challenge signature to recover a trusted payload, validates the TOTP code, and
  for enrollment persists the secret.

There is **no web half to ship**. The plugin returns the well-known
`clientPluginClass` `builtin:otp`, so the OIE web administrator's built-in generic
OTP authenticator renders the enroll/verify UI. Install the engine plugin and it
works — nothing to bundle or rebuild in the web admin. (The web admin must be a
build that includes the built-in OTP handler; current builds do.)

## Storage

Per-user secrets live in a dedicated **`USER_TOTP` database table** via MyBatis —
the engine's own persistence, not the plugin properties blob:

| Column | Purpose |
|---|---|
| `USER_ID` | primary key — the user's **numeric id** (the engine `PERSON` table PK) |
| `SECRET` | the base32 secret, **encrypted** with the engine's configured `Encryptor` |
| `ENROLLED_AT` | enrollment timestamp |
| `LAST_USED_STEP` | the last accepted TOTP time-step — **replay protection** (a code can't be reused) |

Keying by numeric id (not username) means a **rename keeps** the enrollment, and a
**delete/re-add** of the same username starts fresh (the new account gets a new id).
The admin Settings tab cross-references enrollments against the current user set, so
a removed user's row never shows and is pruned.

The mapped statements are per-vendor mapper files
([`mapper/<db>-usertotp.xml`](mapper/), namespace `UserTotp`) declared in
`plugin.xml`'s `<sqlMapConfigs>`; the engine merges the mapper for the running
database (Derby / MySQL / PostgreSQL / SQL Server / Oracle) into its shared MyBatis
config, so reads/writes run on the engine's own connection pool. The table is
created on first `start()` (idempotent). The only thing in plugin properties is the
single install-level HMAC key that signs login challenges (and the issuer label).

## ⚠️ Before you install: read this

Enrollment is **mandatory on first login**. That means the moment this plugin is
active, every administrator login requires completing the TOTP step — so the web
administrator must be able to render it:

1. **Use a web administrator build that includes the built-in OTP handler**
   (`core/otp-auth.js`) and reload it before installing the engine plugin. An older
   build can't show the setup step, which would lock you out. No per-plugin bundling
   is needed — the handler is part of the web admin, not this plugin.
2. If you ever get locked out (broken web client, lost device), recover WITHOUT
   deleting files: set the kill switch on the server and restart —
   `-Dorg.openintegrationengine.totp.disabled=true` (JVM arg) or
   `OIE_TOTP_DISABLED=true` (environment). While set, every login passes straight
   through. Removing the `totpmfa` extension folder from the engine and restarting
   also works.

## Build & install

```bash
OIE_HOME=/path/to/oie mvn package        # -> target/totpmfa-0.3.1.zip
```

Install the zip from the web administrator's **Extensions** page (or the Swing
Administrator) and **restart the engine**.

### No web administrator integration needed

Because the plugin returns `builtin:otp`, the web admin's built-in generic OTP
authenticator handles the enroll/verify UI. There is no per-plugin JavaScript to
copy or register — the earlier "bundle authenticator.js" step is gone.

A method that can't use the generic OTP UI (WebAuthn, push) would return its own
`clientPluginClass` and bundle a matching authenticator in the web admin — but a
standard TOTP/OTP plugin like this one does not.

## Try it

1. Install the plugin, restart the engine, reload the web admin.
2. Log in. After your password you'll see **Set up two-factor authentication** with
   a key — add it to an authenticator app (or the `otpauth://` link), enter the
   6-digit code, **Activate**.
3. Log out and back in — now you're asked for the current code.

## Included (production-grade)

- **MyBatis `USER_TOTP` table** — per-vendor mappers, engine connection pool,
  encrypted secrets (see *Storage*).
- **Replay protection** — `LAST_USED_STEP` rejects reusing a code.
- **Emergency kill switch** — `-Dorg.openintegrationengine.totp.disabled=true` (or
  `OIE_TOTP_DISABLED=true`) bypasses MFA for recovery (see the recovery section).
- **QR enrollment** — the OIE web administrator's built-in OTP UI renders a QR from
  the `otpauth://` URI (server-only plugin; nothing to bundle).

- **Admin device-reset** — a **Two-Factor Authentication** tab in Settings lists
  enrolled users and resets one (clears their secret so their next login
  re-enrolls) — the lost/changed-device path. Backed by
  `GET/POST /extensions/totpmfa/{enrolled,reset}`, gated by the engine's
  `USERS_MANAGE` permission.

## Still out of scope (deliberately)

- **Uninstall DROP** — uninstalling the plugin leaves the `USER_TOTP` table in place;
  a `plugin.xml` `<sqlScript>` uninstall section could drop it.

## License

MPL-2.0
