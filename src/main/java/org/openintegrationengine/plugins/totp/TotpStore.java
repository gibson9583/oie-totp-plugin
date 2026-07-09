/*
 * OIE TOTP MFA — multi-factor authentication plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.totp;

import java.util.Base64;
import java.util.Properties;

/**
 * Install-level TOTP config, held in the plugin's properties (persisted to the
 * engine's CONFIGURATION table): the challenge-signing HMAC key and the issuer
 * label shown in authenticator apps.
 *
 * This is NOT where per-user secrets live — those are in the USER_TOTP database
 * table via {@link TotpCredentialDao}. This holds only the single install-level
 * HMAC key (generated once) and the issuer.
 *
 * Property layout:
 *   totp.hmacKey   base64 per-install HMAC key (challenge signing)
 *   totp.issuer    label shown in the authenticator app
 */
public class TotpStore {

    public static final String PROP_HMAC_KEY = "totp.hmacKey";
    public static final String PROP_ISSUER = "totp.issuer";

    private final Properties props;

    public TotpStore(Properties props) {
        this.props = (props != null) ? props : new Properties();
    }

    public Properties raw() {
        return props;
    }

    public String issuer() {
        String v = props.getProperty(PROP_ISSUER);
        return (v != null && !v.isBlank()) ? v : "Open Integration Engine";
    }

    /** Per-install HMAC key for {@link Challenge}, generated + recorded on first use. */
    public byte[] hmacKey() {
        String stored = props.getProperty(PROP_HMAC_KEY);
        if (stored != null && !stored.isBlank()) {
            try {
                return Base64.getDecoder().decode(stored);
            } catch (RuntimeException ignored) {
                // fall through and regenerate
            }
        }
        byte[] key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);
        props.setProperty(PROP_HMAC_KEY, Base64.getEncoder().encodeToString(key));
        return key;
    }
}
