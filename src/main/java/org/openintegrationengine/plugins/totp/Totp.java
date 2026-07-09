/*
 * OIE TOTP MFA — multi-factor authentication plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.totp;

import java.security.SecureRandom;
import java.time.Instant;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * RFC 6238 TOTP (and its RFC 4648 base32 secret encoding), dependency-free.
 *
 * Defaults match Google Authenticator / Authy / 1Password: HMAC-SHA1, 6 digits,
 * a 30-second step. Verification accepts a small window of steps on either side
 * to tolerate clock skew.
 */
public final class Totp {

    public static final int DIGITS = 6;
    public static final int STEP_SECONDS = 30;
    /** Accept codes from this many steps before/after now (clock-skew tolerance). */
    public static final int WINDOW = 1;

    private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final SecureRandom RANDOM = new SecureRandom();

    private Totp() {}

    /** A new random base32 secret (160 bits — the RFC 6238 recommended length). */
    public static String generateSecret() {
        byte[] bytes = new byte[20];
        RANDOM.nextBytes(bytes);
        return base32Encode(bytes);
    }

    /**
     * The otpauth:// URI an authenticator app scans to enroll. `issuer` and
     * `account` are display labels; `secretBase32` is the shared secret.
     */
    public static String otpauthUri(String issuer, String account, String secretBase32) {
        String label = urlEncode(issuer) + ":" + urlEncode(account);
        return "otpauth://totp/" + label
                + "?secret=" + secretBase32
                + "&issuer=" + urlEncode(issuer)
                + "&algorithm=SHA1&digits=" + DIGITS + "&period=" + STEP_SECONDS;
    }

    /** True when `code` is valid for `secretBase32` at the current time (± WINDOW steps). */
    public static boolean verify(String secretBase32, String code) {
        return matchStep(secretBase32, code) >= 0;
    }

    /**
     * The time-step `code` matches for `secretBase32` (within ± WINDOW of now), or -1 if
     * it doesn't match. The step is monotonic, so callers enforce one-time use (replay
     * protection) by rejecting any code whose step is not strictly greater than the last
     * accepted step for that user.
     */
    public static long matchStep(String secretBase32, String code) {
        if (secretBase32 == null || code == null) {
            return -1;
        }
        String trimmed = code.trim();
        if (trimmed.length() != DIGITS || !trimmed.chars().allMatch(Character::isDigit)) {
            return -1;
        }
        byte[] key;
        try {
            key = base32Decode(secretBase32);
        } catch (RuntimeException e) {
            return -1;
        }
        long step = Instant.now().getEpochSecond() / STEP_SECONDS;
        for (int offset = -WINDOW; offset <= WINDOW; offset++) {
            if (constantTimeEquals(trimmed, generate(key, step + offset))) {
                return step + offset;
            }
        }
        return -1;
    }

    private static String generate(byte[] key, long step) {
        byte[] data = new byte[8];
        long value = step;
        for (int i = 7; i >= 0; i--) {
            data[i] = (byte) (value & 0xff);
            value >>= 8;
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);
            int off = hash[hash.length - 1] & 0x0f;
            int binary = ((hash[off] & 0x7f) << 24) | ((hash[off + 1] & 0xff) << 16)
                    | ((hash[off + 2] & 0xff) << 8) | (hash[off + 3] & 0xff);
            int otp = binary % (int) Math.pow(10, DIGITS);
            return String.format("%0" + DIGITS + "d", otp);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA1 unavailable", e);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length(); i++) {
            diff |= a.charAt(i) ^ b.charAt(i);
        }
        return diff == 0;
    }

    /* ---- RFC 4648 base32 ---- */

    public static String base32Encode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int buffer = 0;
        int bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                sb.append(BASE32.charAt((buffer >> bits) & 0x1f));
            }
        }
        if (bits > 0) {
            sb.append(BASE32.charAt((buffer << (5 - bits)) & 0x1f));
        }
        return sb.toString();
    }

    public static byte[] base32Decode(String s) {
        String clean = s.trim().replace("=", "").replace(" ", "").toUpperCase();
        int buffer = 0;
        int bits = 0;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (char c : clean.toCharArray()) {
            int val = BASE32.indexOf(c);
            if (val < 0) {
                throw new IllegalArgumentException("Not a base32 character: " + c);
            }
            buffer = (buffer << 5) | val;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                out.write((buffer >> bits) & 0xff);
            }
        }
        return out.toByteArray();
    }

    private static String urlEncode(String s) {
        try {
            return java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20");
        } catch (Exception e) {
            return s;
        }
    }
}
