/* Published under the terms of the Mozilla Public License 2.0. */
package org.openintegrationengine.plugins.totp;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import org.apache.ibatis.session.SqlSession;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mirth.connect.model.LoginStatus;
import com.mirth.connect.model.LoginStatus.Status;
import com.mirth.connect.server.controllers.ConfigurationController;
import com.mirth.connect.server.util.SqlConfig;

/**
 * Transactional, shared-database MFA state. A row lock serializes issue, completion,
 * and reset for each account across nodes. Rows survive reset as tombstones. The
 * legacy table is imported exactly once under a global migration lock.
 */
public class TotpCredentialDao {
    static final long CHALLENGE_TTL_MILLIS = 5 * 60 * 1000L;
    static final long ATTEMPT_WINDOW_MILLIS = 5 * 60 * 1000L;
    static final int MAX_ATTEMPTS = 5;
    private static final String NS = "UserTotp.";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Supplier<SqlSession> sessions;
    private final Function<String, String> encrypt;
    private final Function<String, String> decrypt;
    private final TotpIdentity.Source identities;
    private final LongSupplier clock;

    public TotpCredentialDao() {
        this(() -> SqlConfig.getInstance().getSqlSessionManager().openSession(false),
                value -> ConfigurationController.getInstance().getEncryptor().encrypt(value),
                value -> ConfigurationController.getInstance().getEncryptor().decrypt(value),
                TotpIdentity::read, System::currentTimeMillis);
    }

    TotpCredentialDao(Supplier<SqlSession> sessions, Function<String, String> encrypt,
            Function<String, String> decrypt, TotpIdentity.Source identities, LongSupplier clock) {
        this.sessions = sessions;
        this.encrypt = encrypt;
        this.decrypt = decrypt;
        this.identities = identities;
        this.clock = clock;
    }

    /** Mapper result; secrets and pending challenge data remain encrypted here. */
    public static final class State {
        public int userId;
        public String secret;
        public Timestamp enrolledAt;
        public long lastUsedStep;
        public String generation;
        public String tokenHash;
        public String challengeData;
        public long expiresAt;
        public int attempts;
        public long attemptWindow;
        public long revision;
    }

    public static final class Enrollment {
        public final int userId;
        public final String generation;
        Enrollment(int userId, String generation) {
            this.userId = userId;
            this.generation = generation;
        }
    }

    static final class IssuedChallenge {
        final String username;
        final String token;
        final String secret;
        IssuedChallenge(String username, String token, String secret) {
            this.username = username;
            this.token = token;
            this.secret = secret;
        }
    }

    /** Stored only encrypted, including enrollment secret and primary status. */
    public static final class Pending {
        public int userId;
        public String username;
        public String securityStamp;
        public String secret;
        public String status;
        public String message;
    }

    public void ensureTable() {
        ensureSchema("probeMeta", "createMeta");
        ensureMetaRow();
        try (SessionHandle handle = open()) {
            Number migrated = handle.session.selectOne(NS + "migrationStatus");
            if (migrated.intValue() == 1) {
                // A completed migration proves this installation already had state.
                // Never silently recreate a lost table and discard enrolled factors.
                handle.session.selectList(NS + "probeState");
            } else {
                ensureSchema("probeState", "createState");
            }
        }
        try (SessionHandle handle = open()) {
            SqlSession session = handle.session;
            requireOne(session.update(NS + "lockMeta"));
            Number migrated = session.selectOne(NS + "migrationStatus");
            if (migrated.intValue() == 0) {
                migrateLegacy(session);
                requireOne(session.update(NS + "migrationComplete"));
            }
            session.commit();
        }
    }

    private void ensureSchema(String probe, String create) {
        try (SessionHandle handle = open()) {
            SqlSession session = handle.session;
            try {
                session.selectList(NS + probe);
                session.commit();
                return;
            } catch (RuntimeException absentOrInvalid) {
                session.rollback(true);
            }
            try {
                session.update(NS + create);
                session.commit();
            } catch (RuntimeException creationFailure) {
                session.rollback(true);
                // Another node may have created it. Only accept a fully valid schema.
                try {
                    session.selectList(NS + probe);
                    session.commit();
                } catch (RuntimeException invalid) {
                    creationFailure.addSuppressed(invalid);
                    throw creationFailure;
                }
            }
        }
    }

    private void ensureMetaRow() {
        try (SessionHandle handle = open()) {
            SqlSession session = handle.session;
            if (session.selectOne(NS + "migrationStatus") != null) {
                return;
            }
            try {
                requireOne(session.insert(NS + "insertMeta"));
                session.commit();
            } catch (RuntimeException failure) {
                session.rollback(true);
                if (session.selectOne(NS + "migrationStatus") == null) {
                    throw failure;
                }
            }
        }
    }

    private void migrateLegacy(SqlSession session) {
        Connection connection = session.getConnection();
        try {
            if (!LegacyTotpTable.exists(connection)) {
                return;
            }
            List<Map<String, Object>> legacy = new ArrayList<>();
            boolean usesId;
            try (Statement statement = connection.createStatement();
                    ResultSet rows = statement.executeQuery("SELECT * FROM USER_TOTP")) {
                ResultSetMetaData metadata = rows.getMetaData();
                Set<String> columns = new HashSet<>();
                for (int i = 1; i <= metadata.getColumnCount(); i++) {
                    columns.add(metadata.getColumnLabel(i).toUpperCase(java.util.Locale.ROOT));
                }
                usesId = columns.contains("USER_ID");
                if ((!usesId && !columns.contains("USERNAME")) || !columns.contains("SECRET")
                        || !columns.contains("LAST_USED_STEP") || !columns.contains("ENROLLED_AT")) {
                    throw new IllegalStateException("Unsupported legacy USER_TOTP schema.");
                }
                while (rows.next()) {
                    Map<String, Object> row = new HashMap<>();
                    row.put("identity", usesId ? rows.getInt("USER_ID") : rows.getString("USERNAME"));
                    row.put("secret", rows.getString("SECRET"));
                    row.put("enrolledAt", rows.getTimestamp("ENROLLED_AT"));
                    row.put("step", rows.getLong("LAST_USED_STEP"));
                    legacy.add(row);
                }
            }
            Set<Integer> importedIds = new HashSet<>();
            for (Map<String, Object> row : legacy) {
                TotpIdentity.Snapshot identity = identities.read(session,
                        usesId ? (Integer) row.get("identity") : null,
                        usesId ? null : (String) row.get("identity"));
                if (identity == null) {
                    // Confirmed deleted accounts stay archived in the legacy input.
                    continue;
                }
                if (!importedIds.add(identity.userId)) {
                    throw new IllegalStateException("Ambiguous legacy TOTP enrollment identity.");
                }
                // Validate ciphertext without changing the existing encrypted value.
                validSecret(decrypt.apply((String) row.get("secret")));
                State existing = session.selectOne(NS + "find", identity.userId);
                if (existing != null) {
                    throw new IllegalStateException("Incomplete TOTP migration conflicts with existing state.");
                }
                State state = blank(identity.userId);
                state.secret = (String) row.get("secret");
                state.enrolledAt = (Timestamp) row.get("enrolledAt");
                state.lastUsedStep = (Long) row.get("step");
                requireOne(session.insert(NS + "insert", state));
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Could not migrate legacy TOTP enrollments.", e);
        }
    }

    IssuedChallenge issue(String username, LoginStatus primary) {
        try (SessionHandle handle = open()) {
            SqlSession session = handle.session;
            assertMigrated(session);
            TotpIdentity.Snapshot identity = identities.read(session, null, username);
            if (identity == null) {
                throw new IllegalStateException("The account no longer exists.");
            }
            State state = lockOrCreate(session, identity.userId);
            // Resolve again after waiting for the account's MFA transaction lock.
            identity = currentIdentity(session, identity.userId, identity.username);
            long now = clock.getAsLong();
            checkAttempts(state, now);
            String secret = state.secret == null ? Totp.generateSecret() : null;
            if (state.secret != null) {
                validSecret(decrypt.apply(state.secret));
            }
            Pending pending = new Pending();
            pending.userId = identity.userId;
            pending.username = identity.username;
            pending.securityStamp = identity.securityStamp;
            pending.secret = secret;
            pending.status = primary.getStatus().name();
            pending.message = primary.getMessage();
            String token = randomToken();
            state.tokenHash = TotpIdentity.hash(token);
            state.challengeData = encrypt.apply(writePending(pending));
            if (state.challengeData == null || state.challengeData.isBlank()) {
                throw new IllegalStateException("Could not encrypt authentication state.");
            }
            state.expiresAt = now + CHALLENGE_TTL_MILLIS;
            save(session, state);
            session.commit();
            return new IssuedChallenge(identity.username, token, secret);
        }
    }

    LoginStatus complete(String token, String code) {
        if (token == null || !token.matches("[A-Za-z0-9_-]{43}")) {
            return failure("Your authentication session expired. Please sign in again.");
        }
        try (SessionHandle handle = open()) {
            SqlSession session = handle.session;
            assertMigrated(session);
            String hash = TotpIdentity.hash(token);
            State found = session.selectOne(NS + "findToken", hash);
            if (found == null) {
                return failure("Your authentication session expired. Please sign in again.");
            }
            State state = lock(session, found.userId);
            long now = clock.getAsLong();
            if (!hash.equals(state.tokenHash) || state.expiresAt <= now) {
                return failure("Your authentication session expired. Please sign in again.");
            }
            checkAttempts(state, now);
            Pending pending = readPending(decrypt.apply(state.challengeData));
            TotpIdentity.Snapshot identity = currentIdentity(session, state.userId, pending.username);
            if (pending.userId != identity.userId || !identity.securityStamp.equals(pending.securityStamp)) {
                clearChallenge(state);
                save(session, state);
                session.commit();
                return failure("Your account changed. Please sign in again.");
            }
            String secret = pending.secret == null ? decrypt.apply(state.secret) : pending.secret;
            validSecret(secret);
            long step = Totp.matchStep(secret, code, now);
            if (step < 0 || step <= state.lastUsedStep) {
                state.attempts++;
                if (state.attempts >= MAX_ATTEMPTS) {
                    clearChallenge(state);
                }
                save(session, state);
                session.commit();
                return failure(state.attempts >= MAX_ATTEMPTS
                        ? "Too many authentication attempts. Please wait five minutes and sign in again."
                        : "Invalid or already used authentication code.");
            }
            Status status = Status.valueOf(pending.status);
            if (status != Status.SUCCESS && status != Status.SUCCESS_GRACE_PERIOD) {
                throw new IllegalStateException("Invalid primary authentication status.");
            }
            if (pending.secret != null) {
                if (state.secret != null) {
                    throw new IllegalStateException("Enrollment already completed.");
                }
                state.secret = encrypt.apply(pending.secret);
                if (state.secret == null || state.secret.isBlank()) {
                    throw new IllegalStateException("Could not encrypt enrollment.");
                }
                state.enrolledAt = new Timestamp(now);
                state.generation = randomToken();
            } else if (state.secret == null) {
                throw new IllegalStateException("Enrollment no longer exists.");
            }
            state.lastUsedStep = step;
            state.attempts = 0;
            state.attemptWindow = 0;
            clearChallenge(state);
            save(session, state);
            session.commit();
            return new LoginStatus(status, pending.message, identity.username);
        }
    }

    public List<Enrollment> listEnrollments() {
        try (SessionHandle handle = open()) {
            SqlSession session = handle.session;
            assertMigrated(session);
            List<State> rows = session.selectList(NS + "listEnrolled");
            List<Enrollment> enrollments = new ArrayList<>();
            for (State row : rows) {
                enrollments.add(new Enrollment(row.userId, row.generation));
            }
            return enrollments;
        }
    }

    /** A stale reset must never remove a replacement enrollment. */
    public boolean remove(int userId, String expectedGeneration) {
        if (expectedGeneration == null || expectedGeneration.isBlank()) {
            return false;
        }
        try (SessionHandle handle = open()) {
            SqlSession session = handle.session;
            assertMigrated(session);
            State state = lock(session, userId);
            if (state == null || !expectedGeneration.equals(state.generation)) {
                return false;
            }
            state.secret = null;
            state.enrolledAt = null;
            state.lastUsedStep = 0;
            // Keep generation until re-enrollment: retry is idempotent and still revokes
            // any enrollment challenge created since the first reset.
            clearChallenge(state);
            save(session, state);
            session.commit();
            return true;
        }
    }

    private TotpIdentity.Snapshot currentIdentity(SqlSession session, int userId, String username) {
        TotpIdentity.Snapshot byId = identities.read(session, userId, null);
        TotpIdentity.Snapshot byName = identities.read(session, null, username);
        if (byId == null || byName == null || byId.userId != userId || byName.userId != userId || !username.equals(byId.username)
                || !username.equals(byName.username) || !byId.securityStamp.equals(byName.securityStamp)) {
            throw new IllegalStateException("The account identity changed. Sign in again.");
        }
        return byId;
    }

    private State lockOrCreate(SqlSession session, int userId) {
        State state = lock(session, userId);
        if (state != null) {
            return state;
        }
        try {
            requireOne(session.insert(NS + "insert", blank(userId)));
        } catch (RuntimeException raceOrFailure) {
            // PostgreSQL aborts the transaction on duplicate insert. Start a new one
            // and confirm that the winner actually created the row before continuing.
            session.rollback(true);
            assertMigrated(session);
            state = lock(session, userId);
            if (state == null) {
                throw raceOrFailure;
            }
            return state;
        }
        return lock(session, userId);
    }

    private State lock(SqlSession session, int userId) {
        int updated = session.update(NS + "lock", userId);
        if (updated == 0) {
            return null;
        }
        requireOne(updated);
        // MyBatis UPDATE clears its first-level cache, so this is the locked row.
        return session.selectOne(NS + "findLocked", userId);
    }

    /** MyBatis 3.1 sessions are not AutoCloseable. Always roll back reads/failures
     * and restore pool connection isolation before returning a borrowed connection. */
    private SessionHandle open() {
        return new SessionHandle(sessions.get());
    }

    private static final class SessionHandle implements AutoCloseable {
        final SqlSession session;
        final Connection connection;
        final int originalIsolation;

        SessionHandle(SqlSession session) {
            this.session = session;
            try {
                connection = session.getConnection();
                originalIsolation = connection.getTransactionIsolation();
                if (originalIsolation != Connection.TRANSACTION_READ_COMMITTED) {
                    connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
                }
            } catch (SQLException | RuntimeException e) {
                session.close();
                throw new IllegalStateException("Could not open an MFA transaction.", e);
            }
        }

        @Override
        public void close() {
            try {
                session.rollback(true);
                if (connection.getTransactionIsolation() != originalIsolation) {
                    connection.setTransactionIsolation(originalIsolation);
                }
            } catch (SQLException e) {
                throw new IllegalStateException("Could not close an MFA transaction.", e);
            } finally {
                session.close();
            }
        }
    }

    private static State blank(int userId) {
        State state = new State();
        state.userId = userId;
        state.generation = randomToken();
        return state;
    }

    private static void checkAttempts(State state, long now) {
        if (state.attemptWindow == 0 || now - state.attemptWindow >= ATTEMPT_WINDOW_MILLIS) {
            state.attemptWindow = now;
            state.attempts = 0;
        }
        if (state.attempts >= MAX_ATTEMPTS) {
            throw new IllegalStateException("Too many authentication attempts. Please wait five minutes.");
        }
    }

    private static void clearChallenge(State state) {
        state.tokenHash = null;
        state.challengeData = null;
        state.expiresAt = 0;
    }

    private static void save(SqlSession session, State state) {
        requireOne(session.update(NS + "save", state));
    }

    private static void assertMigrated(SqlSession session) {
        Number status = session.selectOne(NS + "migrationStatus");
        if (status == null || status.intValue() != 1) {
            throw new IllegalStateException("TOTP database migration has not completed.");
        }
    }

    private static void requireOne(int changed) {
        if (changed != 1) {
            throw new IllegalStateException("TOTP state update did not affect exactly one row.");
        }
    }

    private static void validSecret(String secret) {
        if (secret == null || secret.length() != 32 || !secret.matches("[A-Z2-7]{32}")) {
            throw new IllegalStateException("Stored authenticator secret is invalid.");
        }
    }

    private static String randomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String writePending(Pending pending) {
        try {
            return JSON.writeValueAsString(pending);
        } catch (Exception e) {
            throw new IllegalStateException("Could not encode authentication state.", e);
        }
    }

    private static Pending readPending(String json) {
        try {
            return JSON.readValue(json, Pending.class);
        } catch (Exception e) {
            throw new IllegalStateException("Could not read authentication state.", e);
        }
    }

    private static LoginStatus failure(String message) {
        return new LoginStatus(Status.FAIL, message);
    }
}
