# TOTP MFA

**Time-based one-time-password (RFC 6238) multi-factor authentication** for Open
Integration Engine administrator login.

- **Self-enrollment as a login step** — no admin configuration and no settings
  page. A user's *first* login (after their password) shows a QR code / key to add
  to an authenticator app and asks for a confirming code; every login after asks for
  the current code.
- **Encrypted, database-backed** — per-user secrets live in a dedicated `USER_TOTP`
  table (MyBatis), encrypted with the engine's configured encryptor. Never stored in
  the clear.
- **Replay protection** — a one-time code can't be reused.
- **Server-only** — the web administrator's built-in OTP UI renders the
  enrollment/verification (QR + code), so there's nothing extra to install on the
  web side.

## ⚠️ Before you install

Enrollment is **mandatory on first login**, so make sure the web administrator can
render the setup step (a current build includes the built-in OTP handler). If you
ever get locked out (lost device, etc.), recover without deleting files by starting
the engine with `-Dorg.openintegrationengine.totp.disabled=true` (or the
environment variable `OIE_TOTP_DISABLED=true`) — every login passes through while
it's set. See the [README](https://github.com/gibson9583/oie-totp-plugin#readme)
for full details.

## Compatibility

Works with the Swing Administrator too, if a matching client-side MFA plugin is
built; the web administrator needs no per-plugin code.
