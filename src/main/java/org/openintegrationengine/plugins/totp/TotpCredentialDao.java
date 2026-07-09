/*
 * OIE TOTP MFA — multi-factor authentication plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.totp;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.ibatis.session.SqlSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.mirth.connect.server.controllers.ConfigurationController;
import com.mirth.connect.server.util.SqlConfig;

/**
 * Per-user TOTP credentials, persisted in the engine's own database via MyBatis —
 * a dedicated {@code USER_TOTP} table, not the plugin properties blob.
 *
 * The mapped statements live in per-vendor mapper files (mapper/&lt;db&gt;-usertotp.xml),
 * registered through the plugin's {@code <sqlMapConfigs>} in plugin.xml; the engine
 * merges them into its shared MyBatis config, so the statements run on the same
 * connection pool as the rest of the engine (namespace {@code UserTotp}).
 *
 * Secrets are stored ENCRYPTED with the engine's configured Encryptor; the
 * {@code LAST_USED_STEP} column enforces one-time-use (replay) protection.
 */
public class TotpCredentialDao {

    private static final Logger logger = LogManager.getLogger(TotpCredentialDao.class);
    private static final String NS = "UserTotp.";

    /** One user's stored credential (secret already DECRYPTED for use). */
    public static final class Credential {
        public final String secret;
        public final long lastUsedStep;

        Credential(String secret, long lastUsedStep) {
            this.secret = secret;
            this.lastUsedStep = lastUsedStep;
        }
    }

    private SqlSession openSession() {
        // autoCommit=true: each call is a single statement.
        return SqlConfig.getInstance().getSqlSessionManager().openSession(true);
    }

    /**
     * Creates the USER_TOTP table if it doesn't exist. Run once at plugin start().
     * The mapped `createTable` DDL is plain CREATE TABLE (portable across vendors);
     * a second run fails with "table already exists", which we swallow — the
     * self-contained, vendor-agnostic idiom (Derby/Oracle lack CREATE TABLE IF NOT
     * EXISTS, so we can't rely on it).
     */
    public void ensureTable() {
        SqlSession session = openSession();
        try {
            session.update(NS + "createTable");
            logger.info("TOTP MFA: created the USER_TOTP table.");
        } catch (Exception e) {
            // Table already exists (the common case), or a real DDL problem — either
            // way subsequent reads/writes will surface a genuine failure loudly.
            logger.debug("TOTP MFA: USER_TOTP table already present (or create skipped): " + e.getMessage());
        } finally {
            session.close();
        }
    }

    /** All enrolled usernames (for the admin panel). */
    public List<String> listEnrolled() {
        SqlSession session = openSession();
        try {
            List<String> names = session.selectList(NS + "listEnrolled");
            return names != null ? names : Collections.emptyList();
        } catch (Exception e) {
            logger.warn("TOTP MFA: could not list enrolled users: " + e.getMessage());
            return Collections.emptyList();
        } finally {
            session.close();
        }
    }

    /** The user's credential (secret decrypted), or null if not enrolled. */
    public Credential find(String username) {
        Map<String, Object> row;
        SqlSession session = openSession();
        try {
            row = session.selectOne(NS + "find", username);
        } catch (Exception e) {
            logger.warn("TOTP MFA: could not read the credential for '" + username + "': " + e.getMessage());
            return null;
        } finally {
            session.close();
        }
        if (row == null) {
            return null;
        }
        // MyBatis hashmap keys are the JDBC column labels, whose case varies by
        // vendor (uppercase on Derby/Oracle, lowercase on Postgres). Look up
        // case-insensitively so the same mapper works everywhere.
        Object encObj = caseInsensitive(row, "SECRET");
        Object step = caseInsensitive(row, "LAST_USED_STEP");
        if (encObj == null) {
            return null;
        }
        String enc = String.valueOf(encObj);
        long lastStep = (step instanceof Number) ? ((Number) step).longValue() : 0L;
        String secret;
        try {
            secret = ConfigurationController.getInstance().getEncryptor().decrypt(enc);
        } catch (Exception e) {
            logger.warn("TOTP MFA: could not decrypt the secret for '" + username + "'.");
            return null;
        }
        return new Credential(secret, lastStep);
    }

    /** Stores (encrypted) a user's secret, replacing any existing enrollment. */
    public void enroll(String username, String base32Secret, long nowMillis) {
        String enc = ConfigurationController.getInstance().getEncryptor().encrypt(base32Secret);
        Map<String, Object> params = new HashMap<>();
        params.put("username", username);
        params.put("secret", enc);
        params.put("enrolledAt", new java.sql.Timestamp(nowMillis));
        params.put("lastUsedStep", 0L);
        SqlSession session = openSession();
        try {
            int updated = session.update(NS + "updateSecret", params);
            if (updated == 0) {
                session.insert(NS + "insert", params);
            }
        } catch (Exception e) {
            logger.error("TOTP MFA: failed to persist enrollment for '" + username + "': " + e.getMessage());
            throw new IllegalStateException("Could not save your authenticator enrollment. Try again.", e);
        } finally {
            session.close();
        }
    }

    /** Records the most recently accepted time-step (one-time-use / replay guard). */
    public void updateLastStep(String username, long step) {
        Map<String, Object> params = new HashMap<>();
        params.put("username", username);
        params.put("lastUsedStep", step);
        SqlSession session = openSession();
        try {
            session.update(NS + "updateLastStep", params);
        } catch (Exception e) {
            logger.warn("TOTP MFA: could not update the last-used step for '" + username + "': " + e.getMessage());
        } finally {
            session.close();
        }
    }

    private static Object caseInsensitive(Map<String, Object> row, String column) {
        Object v = row.get(column);
        if (v != null) {
            return v;
        }
        for (Map.Entry<String, Object> e : row.entrySet()) {
            if (e.getKey() != null && e.getKey().equalsIgnoreCase(column)) {
                return e.getValue();
            }
        }
        return null;
    }

    /** Removes a user's enrollment (e.g. a lost-device reset). */
    public void remove(String username) {
        SqlSession session = openSession();
        try {
            session.delete(NS + "delete", username);
        } catch (Exception e) {
            logger.warn("TOTP MFA: could not remove the credential for '" + username + "': " + e.getMessage());
        } finally {
            session.close();
        }
    }
}
