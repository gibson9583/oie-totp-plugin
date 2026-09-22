# TOTP MFA

Time-based one-time-password multi-factor authentication for Open Integration
Engine web administrator login.

- Users enroll an authenticator after their first successful password login.
- Later logins require a current six-digit code.
- Credentials and pending enrollment secrets are encrypted in the engine database.
- Single-use challenges, transactional replay checks, and persistent attempt
  limits protect enrollment and verification.
- A bundled Two-Factor Authentication Settings panel lets users with
  `manageUsers` reset lost or replaced devices. Stale resets cannot delete a new
  enrollment.
- Existing username-keyed and user-ID-keyed enrollments are migrated at startup.

Requires an OIE 4.6-compatible engine and a web administrator with the built-in
OTP handler. **Stock Swing Administrator login is unsupported.** Enrollment is
mandatory while the plugin is enabled. The engine plugin supplies the Settings
panel; the web host supplies the login UI and React.

Upgrade all nodes sharing a database together and retain a complete database/key
backup. For operator recovery, restart with
`-Dorg.openintegrationengine.totp.disabled=true` or `OIE_TOTP_DISABLED=true`.
Remove the switch after recovery to restore MFA.

See the [README](https://github.com/gibson9583/oie-totp-plugin#readme) for
installation, migration, backup, and recovery details.
