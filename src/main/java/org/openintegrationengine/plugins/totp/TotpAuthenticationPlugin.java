/*
 * OIE TOTP MFA — multi-factor authentication plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.totp;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.mirth.connect.model.ExtendedLoginStatus;
import com.mirth.connect.model.ExtensionPermission;
import com.mirth.connect.model.LoginStatus;
import com.mirth.connect.model.User;
import com.mirth.connect.model.LoginStatus.Status;
import com.mirth.connect.plugins.MultiFactorAuthenticationPlugin;
import com.mirth.connect.server.controllers.ControllerFactory;

/**
 * TOTP (RFC 6238) multi-factor authentication plugin — the server half.
 *
 * <b>Self-enrollment as a login step.</b> There is no admin configuration and no
 * settings page: a user configures their own authenticator during their first
 * login, then is challenged for a code on every login after. Both are delivered
 * through the same {@link ExtendedLoginStatus} → web-authenticator mechanism —
 * the setup UI is just the login flow with {@code mode:"enroll"}.
 *
 * Two stateless legs (the engine's MFA contract):
 *
 *  1) {@link #authenticate(String, LoginStatus, String)} runs after a successful
 *     password login. Returns an {@link ExtendedLoginStatus} whose message is a
 *     small JSON the client renders:
 *       enrolled  -> {"mode":"verify","challenge":TOKEN}
 *       first time-> {"mode":"enroll","challenge":TOKEN,"secret":B32,"otpauthUri":URI}
 *     TOKEN is a signed {@link Challenge} carrying the username, the mode, and (for
 *     enrollment) the pending secret — so leg 2 needs no server-side session.
 *
 *  2) {@link #authenticate(String)} runs on the second leg with only the login-data
 *     header: base64(JSON{challenge, code}). It verifies the challenge to recover a
 *     trusted payload, validates the code, and for enrollment persists the secret.
 *
 * Per-user secrets are persisted in the USER_TOTP table (MyBatis) via
 * {@link TotpCredentialDao}, encrypted at rest, with one-time-use (replay)
 * protection via the stored last-used time-step.
 */
public class TotpAuthenticationPlugin extends MultiFactorAuthenticationPlugin {

    private static final Logger logger = LogManager.getLogger(TotpAuthenticationPlugin.class);

    public static final String PLUGIN_POINT = "TOTP MFA";

    /**
     * The well-known identifier that tells the OIE web administrator to render the
     * standard enroll/verify UI with its BUILT-IN generic OTP authenticator — so this
     * plugin ships no web code and needs no web-admin rebuild. (A Swing client would
     * still load a MultiFactorAuthenticationClientPlugin by FQCN; if you build one,
     * return its class name instead when the caller is Swing.)
     */
    public static final String CLIENT_PLUGIN_CLASS = "builtin:otp";

    /**
     * Emergency recovery kill switch. Because enrollment is mandatory on first login,
     * a broken or not-yet-updated web administrator could otherwise lock everyone out.
     * An admin with SERVER access can bypass MFA without deleting files: set the
     * system property {@code -Dorg.openintegrationengine.totp.disabled=true} (or the
     * environment variable {@code OIE_TOTP_DISABLED=true}) and restart. While set,
     * every login passes straight through.
     */
    private static boolean disabled() {
        return Boolean.getBoolean("org.openintegrationengine.totp.disabled")
                || "true".equalsIgnoreCase(System.getenv("OIE_TOTP_DISABLED"));
    }

    private volatile TotpStore store = new TotpStore(new Properties());
    private final TotpCredentialDao credentials = new TotpCredentialDao();

    /* ---- ServicePlugin lifecycle ---- */

    @Override
    public String getPluginPointName() {
        return PLUGIN_POINT;
    }

    @Override
    public void init(Properties properties) {
        this.store = new TotpStore(properties);
        store.hmacKey();   // generate + record the signing key on first load
        persist();
    }

    @Override
    public void update(Properties properties) {
        this.store = new TotpStore(properties);
        store.hmacKey();
        persist();
    }

    @Override
    public Properties getDefaultProperties() {
        Properties defaults = new Properties();
        defaults.setProperty(TotpStore.PROP_ISSUER, "Open Integration Engine");
        return defaults;
    }

    @Override
    public ExtensionPermission[] getExtensionPermissions() {
        return new ExtensionPermission[0];
    }

    @Override
    public void start() {
        // Create the USER_TOTP table on first start (idempotent — see the DAO).
        credentials.ensureTable();
    }

    @Override
    public void stop() {}

    /* ---- MFA leg 1: enroll (first login) or challenge (thereafter) ---- */

    @Override
    public LoginStatus authenticate(String username, LoginStatus primaryStatus, String serverURL) {
        // Emergency bypass (see disabled()) — never gate login while set.
        if (disabled()) {
            logger.warn("TOTP MFA: disabled by kill switch — login passing through without a second factor.");
            return primaryStatus;
        }
        // Only proceed once primary auth actually succeeded.
        if (primaryStatus == null
                || (primaryStatus.getStatus() != Status.SUCCESS && primaryStatus.getStatus() != Status.SUCCESS_GRACE_PERIOD)) {
            return primaryStatus;
        }

        // Enrollments are keyed by the user's numeric id, so resolve it now (primary
        // auth already succeeded, so the user exists). If we can't, don't block login.
        Integer userId = resolveUserId(username);
        if (userId == null) {
            logger.warn("TOTP MFA: could not resolve a user id for '" + username + "'; passing login through.");
            return primaryStatus;
        }

        TotpStore s = store;
        Challenge challenge = new Challenge(s.hmacKey());
        long now = System.currentTimeMillis();

        if (credentials.find(userId) == null) {
            // First login: self-enroll. Generate a secret and carry it (signed) in the
            // challenge; the client shows it as a QR/key, the user confirms a code,
            // and leg 2 persists it. Nothing is stored until that confirmation.
            String secret = Totp.generateSecret();
            String token = challenge.issue(payload(userId, username, "enroll", secret), now);
            String message = "{\"mode\":\"enroll\",\"challenge\":" + jsonStr(token)
                    + ",\"secret\":" + jsonStr(secret)
                    + ",\"otpauthUri\":" + jsonStr(Totp.otpauthUri(s.issuer(), username, secret)) + "}";
            return new ExtendedLoginStatus(Status.FAIL, message, username, CLIENT_PLUGIN_CLASS);
        }

        // Enrolled: challenge for the current code.
        String token = challenge.issue(payload(userId, username, "verify", null), now);
        String message = "{\"mode\":\"verify\",\"challenge\":" + jsonStr(token) + "}";
        return new ExtendedLoginStatus(Status.FAIL, message, username, CLIENT_PLUGIN_CLASS);
    }

    /* ---- MFA leg 2: verify the code (and persist on enrollment) ---- */

    @Override
    public LoginStatus authenticate(String loginData) {
        TotpStore s = store;
        String challengeToken;
        String code;
        try {
            String json = new String(Base64.getDecoder().decode(loginData), StandardCharsets.UTF_8);
            challengeToken = jsonField(json, "challenge");
            code = jsonField(json, "code");
        } catch (RuntimeException e) {
            return new LoginStatus(Status.FAIL, "Malformed authentication data.");
        }

        String payload = new Challenge(s.hmacKey()).verify(challengeToken, System.currentTimeMillis());
        if (payload == null) {
            return new LoginStatus(Status.FAIL, "Your authentication session expired. Please sign in again.");
        }
        String username = jsonField(payload, "u");
        String mode = jsonField(payload, "m");
        String uidStr = jsonField(payload, "uid");
        int userId;
        try {
            userId = Integer.parseInt(uidStr);
        } catch (NumberFormatException e) {
            return new LoginStatus(Status.FAIL, "Invalid authentication session.");
        }
        if (username == null || mode == null) {
            return new LoginStatus(Status.FAIL, "Invalid authentication session.");
        }

        if ("enroll".equals(mode)) {
            String secret = jsonField(payload, "s");
            long step = secret == null ? -1 : Totp.matchStep(secret, code);
            if (step < 0) {
                return new LoginStatus(Status.FAIL, "That code didn't match. Scan the key again and enter a fresh code.");
            }
            credentials.enroll(userId, secret, System.currentTimeMillis());
            credentials.updateLastStep(userId, step);   // the enrolling code can't be reused
            logger.info("TOTP MFA: user '" + username + "' (id " + userId + ") completed self-enrollment.");
            return new LoginStatus(Status.SUCCESS, "", username);
        }

        // verify
        TotpCredentialDao.Credential cred = credentials.find(userId);
        if (cred == null) {
            return new LoginStatus(Status.FAIL, "Multi-factor authentication is not set up for this account.");
        }
        long step = Totp.matchStep(cred.secret, code);
        if (step < 0) {
            return new LoginStatus(Status.FAIL, "Invalid authentication code.");
        }
        // Replay protection: a code (time-step) may be used at most once.
        if (step <= cred.lastUsedStep) {
            return new LoginStatus(Status.FAIL, "That code was already used. Wait for the next code and try again.");
        }
        credentials.updateLastStep(userId, step);
        return new LoginStatus(Status.SUCCESS, "", username);
    }

    /* ---- helpers ---- */

    private void persist() {
        try {
            ControllerFactory.getFactory().createExtensionController()
                    .setPluginProperties(PLUGIN_POINT, store.raw());
        } catch (Exception e) {
            logger.warn("TOTP MFA: could not persist plugin properties: " + e.getMessage());
        }
    }

    private static String payload(int userId, String username, String mode, String secret) {
        StringBuilder sb = new StringBuilder("{\"u\":").append(jsonStr(username))
                .append(",\"uid\":").append(jsonStr(String.valueOf(userId)))
                .append(",\"m\":").append(jsonStr(mode));
        if (secret != null) {
            sb.append(",\"s\":").append(jsonStr(secret));
        }
        return sb.append("}").toString();
    }

    /** The user's numeric id, or null if it can't be resolved. */
    private static Integer resolveUserId(String username) {
        try {
            User user = ControllerFactory.getFactory().createUserController().getUser(null, username);
            return user != null ? user.getId() : null;
        } catch (Exception e) {
            logger.warn("TOTP MFA: user id lookup failed for '" + username + "': " + e.getMessage());
            return null;
        }
    }

    private static String jsonStr(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        return b.append('"').toString();
    }

    /** Minimal flat-JSON string reader (payloads are tiny, controlled objects). */
    private static String jsonField(String json, String field) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("\"" + java.util.regex.Pattern.quote(field) + "\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"")
                .matcher(json);
        if (!m.find()) {
            return null;
        }
        return m.group(1).replace("\\\"", "\"").replace("\\\\", "\\");
    }
}
