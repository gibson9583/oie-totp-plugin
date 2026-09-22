package org.openintegrationengine.plugins.totp;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Properties;
import org.junit.jupiter.api.Test;

class TotpTest {
    @Test void rfc4226VectorsAndLocaleIndependence() {
        byte[] key = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
        String[] expected = { "755224", "287082", "359152", "969429", "338314", "254676",
                "287922", "162583", "399871", "520489" };
        Locale original = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("ar-EG"));
            for (int i = 0; i < expected.length; i++) assertEquals(expected[i], Totp.generate(key, i));
            assertEquals(1, Totp.matchStep(Totp.base32Encode(key), "287082", 30_000));
            assertEquals(-1, Totp.matchStep(Totp.base32Encode(key), "٢٨٧٠٨٢", 30_000));
        } finally { Locale.setDefault(original); }
    }

    @Test void base32AndAsciiParsing() {
        byte[] input = "foo bar".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(input, Totp.base32Decode(Totp.base32Encode(input)));
        assertEquals(-1, Totp.matchStep("invalid!", "123456", 30_000));
        assertEquals(-1, Totp.matchStep(null, "123456", 30_000));
        assertEquals(-1, Totp.matchStep(Totp.base32Encode(input), null, 30_000));
    }

    @Test void settingsDiscardLegacySigningKeyAndDefendInternalProperties() {
        Properties properties = new Properties();
        properties.setProperty("totp.hmacKey", "compromised-key");
        properties.setProperty(TotpStore.PROP_ISSUER, "Hospital");
        TotpStore store = new TotpStore(properties);
        assertNull(store.raw().getProperty("totp.hmacKey"));
        store.raw().setProperty(TotpStore.PROP_ISSUER, "different");
        assertEquals("Hospital", store.issuer());
        assertEquals("Open Integration Engine", new TotpStore(null).issuer());
    }
}
