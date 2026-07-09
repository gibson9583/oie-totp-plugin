/*
 * OIE TOTP MFA — multi-factor authentication plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.totp;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * A short-lived, tamper-evident token carrying an opaque payload between the two
 * stateless MFA legs.
 *
 * The second leg ({@code authenticate(loginData)}) has NO memory of the primary
 * login — not the username, and for first-login self-enrollment, not the pending
 * secret either. So the first leg mints a token carrying whatever the second leg
 * will need (a small JSON: username, mode, and for enrollment the new secret),
 * signed with a per-install HMAC key. The client echoes it back; this class
 * verifies the signature to recover a TRUSTED payload without re-checking the
 * password. The payload is signed (integrity), not encrypted — for enrollment the
 * client legitimately needs to see the new secret to build its QR; TLS covers the
 * wire, and HMAC prevents the client from altering the username or secret.
 *
 * Format: base64url(payload) "." expiryEpochMillis "." base64url(HMAC-SHA256 over
 * the first two dot-joined fields).
 */
public final class Challenge {

    /** Token lifetime — long enough to scan + type a code, short enough to limit replay. */
    public static final long TTL_MILLIS = 5 * 60 * 1000L;

    private final byte[] hmacKey;

    public Challenge(byte[] hmacKey) {
        this.hmacKey = hmacKey;
    }

    public String issue(String payload, long nowMillis) {
        String signed = b64(payload.getBytes(StandardCharsets.UTF_8)) + "." + (nowMillis + TTL_MILLIS);
        return signed + "." + b64(sign(signed.getBytes(StandardCharsets.UTF_8)));
    }

    /** Returns the payload if the token is valid and unexpired, else null. */
    public String verify(String token, long nowMillis) {
        if (token == null) {
            return null;
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return null;
        }
        String signed = parts[0] + "." + parts[1];
        byte[] sig;
        try {
            sig = Base64.getUrlDecoder().decode(parts[2]);
        } catch (RuntimeException e) {
            return null;
        }
        if (!constantTimeEquals(sig, sign(signed.getBytes(StandardCharsets.UTF_8)))) {
            return null;
        }
        long expiry;
        try {
            expiry = Long.parseLong(parts[1]);
        } catch (NumberFormatException e) {
            return null;
        }
        if (nowMillis > expiry) {
            return null;
        }
        try {
            return new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private byte[] sign(byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    private static String b64(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }
}
