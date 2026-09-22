/* Published under the terms of the Mozilla Public License 2.0. */
package org.openintegrationengine.plugins.totp;

import java.util.Properties;

/** Public install-level display settings. Authentication secrets never live here. */
public class TotpStore {
    public static final String PROP_ISSUER = "totp.issuer";
    private final Properties props = new Properties();

    public TotpStore(Properties supplied) {
        // Allowlist settings: discard obsolete exposed HMAC keys during upgrade.
        if (supplied != null && supplied.getProperty(PROP_ISSUER) != null) {
            props.setProperty(PROP_ISSUER, supplied.getProperty(PROP_ISSUER));
        }
    }

    public Properties raw() {
        Properties copy = new Properties();
        copy.putAll(props);
        return copy;
    }

    public String issuer() {
        String value = props.getProperty(PROP_ISSUER);
        return value != null && !value.isBlank() ? value : "Open Integration Engine";
    }
}
