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
 * a dedicated {@code USER_TOTP} table keyed by the user's numeric id (the PERSON
 * table PK). Keying by id (not username) means a rename keeps the enrollment and a
 * delete/re-add of the same username starts fresh (the new account has a new id).
 *
 * The mapped statements live in per-vendor mapper files (mapper/&lt;db&gt;-usertotp.xml),
 * registered through the plugin's {@code <sqlMapConfigs>} in plugin.xml; the engine
 * merges them into its shared MyBatis config (namespace {@code UserTotp}). Secrets
 * are stored ENCRYPTED with the engine's configured Encryptor; {@code LAST_USED_STEP}
 * enforces one-time-use (replay) protection.
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
     * a second run fails with "table already exists", which we swallow (Derby/Oracle
     * lack CREATE TABLE IF NOT EXISTS, so we can't rely on it).
     */
    public void ensureTable() {
        SqlSession session = openSession();
        try {
            session.update(NS + "createTable");
            logger.info("TOTP MFA: created the USER_TOTP table.");
        } catch (Exception e) {
            logger.debug("TOTP MFA: USER_TOTP table already present (or create skipped): " + e.getMessage());
        } finally {
            session.close();
        }
    }

    /** All enrolled user ids (for the admin panel, then cross-referenced with the user list). */
    public List<Integer> listEnrolledIds() {
        SqlSession session = openSession();
        try {
            List<Integer> ids = session.selectList(NS + "listEnrolledIds");
            return ids != null ? ids : Collections.emptyList();
        } catch (Exception e) {
            logger.warn("TOTP MFA: could not list enrolled users: " + e.getMessage());
            return Collections.emptyList();
        } finally {
            session.close();
        }
    }

    /** The user's credential (secret decrypted), or null if not enrolled. */
    public Credential find(int userId) {
        Map<String, Object> row;
        SqlSession session = openSession();
        try {
            row = session.selectOne(NS + "find", userId);
        } catch (Exception e) {
            logger.warn("TOTP MFA: could not read the credential for user " + userId + ": " + e.getMessage());
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
        long lastStep = (step instanceof Number) ? ((Number) step).longValue() : 0L;
        String secret;
        try {
            secret = ConfigurationController.getInstance().getEncryptor().decrypt(String.valueOf(encObj));
        } catch (Exception e) {
            logger.warn("TOTP MFA: could not decrypt the secret for user " + userId + ".");
            return null;
        }
        return new Credential(secret, lastStep);
    }

    /** Stores (encrypted) a user's secret, replacing any existing enrollment. */
    public void enroll(int userId, String base32Secret, long nowMillis) {
        String enc = ConfigurationController.getInstance().getEncryptor().encrypt(base32Secret);
        Map<String, Object> params = new HashMap<>();
        params.put("userId", userId);
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
            logger.error("TOTP MFA: failed to persist enrollment for user " + userId + ": " + e.getMessage());
            throw new IllegalStateException("Could not save your authenticator enrollment. Try again.", e);
        } finally {
            session.close();
        }
    }

    /** Records the most recently accepted time-step (one-time-use / replay guard). */
    public void updateLastStep(int userId, long step) {
        Map<String, Object> params = new HashMap<>();
        params.put("userId", userId);
        params.put("lastUsedStep", step);
        SqlSession session = openSession();
        try {
            session.update(NS + "updateLastStep", params);
        } catch (Exception e) {
            logger.warn("TOTP MFA: could not update the last-used step for user " + userId + ": " + e.getMessage());
        } finally {
            session.close();
        }
    }

    /** Removes a user's enrollment (a reset / lost-device, or pruning an orphan). */
    public void remove(int userId) {
        SqlSession session = openSession();
        try {
            session.delete(NS + "delete", userId);
        } catch (Exception e) {
            logger.warn("TOTP MFA: could not remove the credential for user " + userId + ": " + e.getMessage());
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
}
