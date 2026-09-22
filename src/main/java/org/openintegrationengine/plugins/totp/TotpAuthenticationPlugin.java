/* Published under the terms of the Mozilla Public License 2.0. */
package org.openintegrationengine.plugins.totp;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mirth.connect.model.ExtendedLoginStatus;
import com.mirth.connect.model.ExtensionPermission;
import com.mirth.connect.model.LoginStatus;
import com.mirth.connect.model.LoginStatus.Status;
import com.mirth.connect.plugins.MultiFactorAuthenticationPlugin;
import com.mirth.connect.server.controllers.ControllerFactory;

/** Mandatory self-enrollment and TOTP verification using single-use database challenges. */
public class TotpAuthenticationPlugin extends MultiFactorAuthenticationPlugin {
    private static final Logger logger = LogManager.getLogger(TotpAuthenticationPlugin.class);
    private static final ObjectMapper JSON = new ObjectMapper();
    public static final String PLUGIN_POINT = "TOTP MFA";
    /** Login uses the web administrator's built-in OTP flow; Swing login is unsupported. */
    public static final String CLIENT_PLUGIN_CLASS = "builtin:otp";

    private volatile TotpStore store = new TotpStore(new Properties());
    private final TotpCredentialDao credentials;
    private final SettingsWriter settingsWriter;

    @FunctionalInterface
    interface SettingsWriter {
        void write(Properties properties) throws Exception;
    }

    public TotpAuthenticationPlugin() {
        this(new TotpCredentialDao());
    }

    TotpAuthenticationPlugin(TotpCredentialDao credentials) {
        this(credentials, properties -> ControllerFactory.getFactory().createExtensionController()
                .setPluginProperties(PLUGIN_POINT, properties));
    }

    TotpAuthenticationPlugin(TotpCredentialDao credentials, SettingsWriter settingsWriter) {
        this.credentials = credentials;
        this.settingsWriter = settingsWriter;
    }

    @Override
    public String getPluginPointName() {
        return PLUGIN_POINT;
    }

    @Override
    public void init(Properties properties) {
        configure(properties);
    }

    @Override
    public void update(Properties properties) {
        configure(properties);
    }

    private void configure(Properties properties) {
        TotpStore replacement = new TotpStore(properties);
        try {
            settingsWriter.write(replacement.raw());
        } catch (Exception e) {
            // Engine init exceptions unregister an MFA plugin. Cleanup of a now-
            // unused legacy signing key must never remove the authentication hook.
            // Only the issuer is used; old keys cannot authenticate opaque tokens.
            logger.warn("TOTP MFA could not persist public settings or remove obsolete properties.", e);
        }
        store = replacement;
    }

    @Override
    public Properties getDefaultProperties() {
        Properties defaults = new Properties();
        defaults.setProperty(TotpStore.PROP_ISSUER, "Open Integration Engine");
        return defaults;
    }

    @Override
    public ExtensionPermission[] getExtensionPermissions() {
        return TotpPermissions.permissions();
    }

    @Override
    public void start() {
        if (!disabled()) {
            credentials.ensureTable();
        }
    }

    @Override
    public void stop() {}

    @Override
    public LoginStatus authenticate(String username, LoginStatus primaryStatus, String serverURL) {
        if (disabled()) {
            logger.warn("TOTP MFA is disabled by the server recovery switch.");
            return primaryStatus;
        }
        if (primaryStatus == null || !primaryStatus.isSuccess()) {
            return primaryStatus;
        }
        try {
            TotpCredentialDao.IssuedChallenge issued = credentials.issue(username, primaryStatus);
            ObjectNode message = JSON.createObjectNode();
            message.put("mode", issued.secret == null ? "verify" : "enroll");
            message.put("challenge", issued.token);
            if (issued.secret != null) {
                message.put("secret", issued.secret);
                message.put("otpauthUri", Totp.otpauthUri(store.issuer(), issued.username, issued.secret));
            }
            return new ExtendedLoginStatus(Status.FAIL, message.toString(), issued.username, CLIENT_PLUGIN_CLASS);
        } catch (Exception e) {
            // Never turn an unavailable credential/identity into a fresh enrollment or login.
            logger.error("TOTP MFA could not establish authentication state.", e);
            return unavailable();
        }
    }

    @Override
    public LoginStatus authenticate(String loginData) {
        if (disabled()) {
            return new LoginStatus(Status.FAIL, "Please restart your sign-in.");
        }
        String token;
        String code;
        try {
            if (loginData == null || loginData.length() > 4096) {
                throw new IllegalArgumentException("Authentication input is too large or absent.");
            }
            JsonNode data = JSON.readTree(new String(Base64.getDecoder().decode(loginData), StandardCharsets.UTF_8));
            if (data == null || !data.isObject() || !data.path("challenge").isTextual()
                    || !data.path("code").isTextual()) {
                throw new IllegalArgumentException("Invalid authentication object.");
            }
            token = data.get("challenge").textValue();
            code = data.get("code").textValue();
        } catch (Exception e) {
            return new LoginStatus(Status.FAIL, "Malformed authentication data.");
        }
        try {
            return credentials.complete(token, code);
        } catch (Exception e) {
            logger.error("TOTP MFA could not complete authentication.", e);
            return unavailable();
        }
    }

    private static boolean disabled() {
        return Boolean.getBoolean("org.openintegrationengine.totp.disabled")
                || "true".equalsIgnoreCase(System.getenv("OIE_TOTP_DISABLED"));
    }

    private static LoginStatus unavailable() {
        return new LoginStatus(Status.FAIL,
                "Multi-factor authentication is unavailable or temporarily locked. Please wait five minutes and sign in again.");
    }
}
