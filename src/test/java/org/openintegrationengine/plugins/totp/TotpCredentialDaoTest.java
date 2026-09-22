package org.openintegrationengine.plugins.totp;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

import org.apache.ibatis.builder.xml.XMLMapperBuilder;
import org.apache.ibatis.datasource.unpooled.UnpooledDataSource;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import org.apache.ibatis.transaction.jdbc.JdbcTransactionFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.mirth.connect.model.ExtendedLoginStatus;
import com.mirth.connect.model.LoginStatus;
import com.mirth.connect.model.LoginStatus.Status;

class TotpCredentialDaoTest {
    static final String SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    static final LoginStatus SUCCESS = new LoginStatus(Status.SUCCESS, "");
    final AtomicLong now = new AtomicLong(1_700_000_000_000L);
    final Map<Integer, TotpIdentity.Snapshot> users = new ConcurrentHashMap<>();
    final AtomicBoolean failSave = new AtomicBoolean();
    final AtomicBoolean zeroSave = new AtomicBoolean();
    final AtomicBoolean failCommit = new AtomicBoolean();
    final AtomicBoolean failIdentity = new AtomicBoolean();
    String url;
    SqlSessionFactory sessions;
    TotpIdentity.Source identities;
    TotpCredentialDao dao;
    final Function<String, String> encrypt = value -> "encrypted:" + Base64.getEncoder()
            .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    final Function<String, String> decrypt = value -> {
        if (value == null || !value.startsWith("encrypted:")) {
            throw new IllegalStateException("Decryption failed");
        }
        return new String(Base64.getDecoder().decode(value.substring(10)), StandardCharsets.UTF_8);
    };

    @BeforeEach
    void setup() throws Exception {
        System.clearProperty("org.openintegrationengine.totp.disabled");
        url = "jdbc:derby:memory:totp_" + UUID.randomUUID().toString().replace("-", "") + ";create=true";
        var source = new UnpooledDataSource("org.apache.derby.jdbc.EmbeddedDriver", url, null, null);
        Configuration config = new Configuration(new Environment("test", new JdbcTransactionFactory(), source));
        try (var mapper = new FileInputStream("mapper/derby-usertotp.xml")) {
            new XMLMapperBuilder(mapper, config, "derby-usertotp.xml", config.getSqlFragments()).parse();
        }
        sessions = new SqlSessionFactoryBuilder().build(config);
        users.put(7, new TotpIdentity.Snapshot(7, "alice", "password-state-1"));
        identities = mock(TotpIdentity.Source.class);
        when(identities.read(any(), nullable(Integer.class), nullable(String.class))).thenAnswer(invocation -> {
            if (failIdentity.get()) {
                throw new IllegalStateException("Identity storage unavailable");
            }
            Integer id = invocation.getArgument(1);
            String name = invocation.getArgument(2);
            if (id != null) {
                return users.get(id);
            }
            List<TotpIdentity.Snapshot> matches = users.values().stream()
                    .filter(user -> user.username.equalsIgnoreCase(name)).toList();
            if (matches.size() > 1) {
                throw new IllegalStateException("Ambiguous identity");
            }
            return matches.isEmpty() ? null : matches.get(0);
        });
        dao = newDao();
    }

    TotpCredentialDao newDao() {
        return new TotpCredentialDao(() -> {
            SqlSession session = spy(sessions.openSession(false));
            doAnswer(invocation -> {
                if (failSave.get()) {
                    throw new IllegalStateException("Injected write failure");
                }
                return zeroSave.get() ? 0 : invocation.callRealMethod();
            }).when(session).update(eq("UserTotp.save"), any());
            doAnswer(invocation -> {
                if (failCommit.get()) {
                    throw new IllegalStateException("Injected commit failure");
                }
                return invocation.callRealMethod();
            }).when(session).commit();
            return session;
        }, encrypt, decrypt, identities, now::get);
    }

    @AfterEach
    void cleanup() throws Exception {
        System.clearProperty("org.openintegrationengine.totp.disabled");
        // Every test owns exactly this in-memory DB; all sessions/executors close
        // before removal, including failed tests. No shared engine resources exist.
        try {
            DriverManager.getConnection(url.replace(";create=true", ";drop=true"));
            fail("Derby drop should report successful destruction via SQLState 08006");
        } catch (SQLException e) {
            assertTrue("08006".equals(e.getSQLState()) || "XJ004".equals(e.getSQLState()),
                    "Owned DB must be dropped or never created: " + e.getSQLState());
        }
    }

    String code(String secret) {
        return Totp.generate(Totp.base32Decode(secret), now.get() / 30_000L);
    }

    String wrongCode(String secret) {
        for (int i = 0; i < 100; i++) {
            String candidate = String.format(Locale.ROOT, "%06d", i);
            if (Totp.matchStep(secret, candidate, now.get()) < 0) return candidate;
        }
        throw new AssertionError("Cannot find an invalid test code");
    }

    TotpCredentialDao.State state() {
        SqlSession session = sessions.openSession();
        try { return session.selectOne("UserTotp.find", 7); }
        finally { session.close(); }
    }

    void sql(String sql) throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
                var statement = connection.createStatement()) { statement.execute(sql); }
    }

    void legacy(boolean idBased, Object identity, String encrypted, long step) throws Exception {
        sql("CREATE TABLE USER_TOTP (" + (idBased ? "USER_ID INTEGER" : "USERNAME VARCHAR(255)")
                + " PRIMARY KEY, SECRET VARCHAR(512) NOT NULL, ENROLLED_AT TIMESTAMP, LAST_USED_STEP BIGINT)");
        legacyRow(identity, encrypted, step);
    }

    void legacyRow(Object identity, String encrypted, long step) throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
                PreparedStatement insert = connection.prepareStatement("INSERT INTO USER_TOTP VALUES (?, ?, ?, ?)")) {
            insert.setObject(1, identity);
            insert.setString(2, encrypted);
            insert.setTimestamp(3, new java.sql.Timestamp(1_600_000_000_000L));
            insert.setLong(4, step);
            insert.executeUpdate();
        }
    }

    TotpCredentialDao.IssuedChallenge enroll() {
        dao.ensureTable();
        var issued = dao.issue("alice", SUCCESS);
        assertEquals(Status.SUCCESS, dao.complete(issued.token, code(issued.secret)).getStatus());
        return issued;
    }

    @Test void firstEnrollmentIsEncryptedAtomicAndSingleUse() {
        dao.ensureTable();
        var issued = dao.issue("alice", SUCCESS);
        var pending = state();
        assertNull(pending.secret);
        assertNotEquals(issued.token, pending.tokenHash);
        assertEquals(TotpIdentity.hash(issued.token), pending.tokenHash);
        assertFalse(pending.challengeData.contains(issued.secret));
        assertEquals(Status.SUCCESS, dao.complete(issued.token, code(issued.secret)).getStatus());
        assertEquals(encrypt.apply(issued.secret), state().secret);
        assertEquals(now.get() / 30_000L, state().lastUsedStep);
        assertNull(state().tokenHash);
        assertEquals(Status.FAIL, dao.complete(issued.token, code(issued.secret)).getStatus());
    }

    @Test void replacementChallengeInvalidatesEarlierEnrollment() {
        dao.ensureTable();
        var first = dao.issue("alice", SUCCESS);
        var second = dao.issue("alice", SUCCESS);
        assertEquals(Status.FAIL, dao.complete(first.token, code(first.secret)).getStatus());
        assertEquals(Status.SUCCESS, dao.complete(second.token, code(second.secret)).getStatus());
        assertEquals(encrypt.apply(second.secret), state().secret);
    }

    @Test void enrolledCodeCannotBeReplayedAcrossNewChallenges() {
        var enrollment = enroll();
        var verify = dao.issue("alice", SUCCESS);
        assertNull(verify.secret);
        assertEquals(Status.FAIL, dao.complete(verify.token, code(enrollment.secret)).getStatus());
        now.addAndGet(30_000L);
        assertEquals(Status.SUCCESS, dao.complete(verify.token, code(enrollment.secret)).getStatus());
    }

    @Test void concurrentCompletionAcrossDaoInstancesAcceptsOnlyOnce() throws Exception {
        dao.ensureTable();
        var issued = dao.issue("alice", SUCCESS);
        assertEquals(1, race(8, () -> newDao().complete(issued.token, code(issued.secret)).isSuccess()));
        now.addAndGet(30_000L);
        var verify = dao.issue("alice", SUCCESS);
        assertEquals(1, race(8, () -> newDao().complete(verify.token, code(issued.secret)).isSuccess()));
    }

    @Test void concurrentStartupImportsLegacyOnlyOnce() throws Exception {
        legacy(true, 7, encrypt.apply(SECRET), 1234);
        assertEquals(4, race(4, () -> { newDao().ensureTable(); return true; }));
        assertEquals(1, dao.listEnrollments().size());
        assertEquals(1234, state().lastUsedStep);
    }

    @Test void concurrentChallengeCreationKeepsOnlyOneUsableToken() throws Exception {
        dao.ensureTable();
        List<TotpCredentialDao.IssuedChallenge> issued = java.util.Collections.synchronizedList(new ArrayList<>());
        race(6, () -> { issued.add(newDao().issue("alice", SUCCESS)); return true; });
        int successes = 0;
        for (var challenge : issued) {
            if (dao.complete(challenge.token, code(challenge.secret)).isSuccess()) successes++;
        }
        assertEquals(1, successes);
    }

    interface Operation { boolean run() throws Exception; }
    int race(int count, Operation operation) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(count);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> results = new ArrayList<>();
        try {
            for (int i = 0; i < count; i++) {
                results.add(pool.submit(() -> { start.await(); return operation.run(); }));
            }
            start.countDown();
            int successes = 0;
            for (Future<Boolean> result : results) if (result.get(30, TimeUnit.SECONDS)) successes++;
            return successes;
        } finally {
            pool.shutdownNow();
            assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        }
    }

    @Test void wrongGuessesAreBoundedAcrossConcurrentNodes() throws Exception {
        dao.ensureTable();
        var issued = dao.issue("alice", SUCCESS);
        assertEquals(0, race(10, () -> newDao().complete(issued.token, wrongCode(issued.secret)).isSuccess()));
        assertEquals(TotpCredentialDao.MAX_ATTEMPTS, state().attempts);
        assertNull(state().tokenHash);
        assertThrows(IllegalStateException.class, () -> newDao().issue("alice", SUCCESS));
        now.addAndGet(TotpCredentialDao.ATTEMPT_WINDOW_MILLIS);
        var fresh = dao.issue("alice", SUCCESS);
        assertEquals(Status.SUCCESS, dao.complete(fresh.token, code(fresh.secret)).getStatus());
    }

    @Test void newChallengesDoNotResetAttemptLimit() {
        dao.ensureTable();
        for (int i = 0; i < TotpCredentialDao.MAX_ATTEMPTS; i++) {
            var challenge = newDao().issue("alice", SUCCESS);
            assertEquals(Status.FAIL, newDao().complete(challenge.token, wrongCode(challenge.secret)).getStatus());
            assertEquals(i + 1, state().attempts);
        }
        assertThrows(IllegalStateException.class, () -> dao.issue("alice", SUCCESS));
    }

    @Test void expiredAndUnknownTokensNeverAuthenticateOrConsumeAttempts() {
        dao.ensureTable();
        var challenge = dao.issue("alice", SUCCESS);
        assertEquals(Status.FAIL, dao.complete("x".repeat(43), code(challenge.secret)).getStatus());
        assertEquals(0, state().attempts);
        now.addAndGet(TotpCredentialDao.CHALLENGE_TTL_MILLIS);
        assertEquals(Status.FAIL, dao.complete(challenge.token, code(challenge.secret)).getStatus());
    }

    @Test void resetRevokesChallengeAndStaleResetCannotDeleteReplacement() {
        var first = enroll();
        String generation = dao.listEnrollments().get(0).generation;
        var pending = dao.issue("alice", SUCCESS);
        assertTrue(dao.remove(7, generation));
        assertTrue(dao.remove(7, generation));
        assertEquals(Status.FAIL, dao.complete(pending.token, code(first.secret)).getStatus());
        var fresh = dao.issue("alice", SUCCESS);
        assertEquals(Status.SUCCESS, dao.complete(fresh.token, code(fresh.secret)).getStatus());
        assertFalse(dao.remove(7, generation));
        assertEquals(encrypt.apply(fresh.secret), state().secret);
    }

    @Test void resetRevokesPendingEnrollmentAndRetainsAttemptAccounting() {
        enroll();
        String generation = state().generation;
        assertTrue(dao.remove(7, generation));
        var pending = dao.issue("alice", SUCCESS);
        dao.complete(pending.token, wrongCode(pending.secret));
        assertTrue(dao.remove(7, generation));
        assertEquals(1, state().attempts);
        assertEquals(Status.FAIL, dao.complete(pending.token, code(pending.secret)).getStatus());
    }

    @Test void enrollmentWriteAndCommitFailuresCannotGrantLoginOrLosePendingState() {
        dao.ensureTable();
        var issued = dao.issue("alice", SUCCESS);
        failSave.set(true);
        assertThrows(IllegalStateException.class, () -> dao.complete(issued.token, code(issued.secret)));
        assertNull(state().secret);
        failSave.set(false);
        failCommit.set(true);
        assertThrows(IllegalStateException.class, () -> dao.complete(issued.token, code(issued.secret)));
        assertNull(state().secret);
        failCommit.set(false);
        assertEquals(Status.SUCCESS, dao.complete(issued.token, code(issued.secret)).getStatus());
    }

    @Test void zeroAffectedRowsAndVerificationPersistenceFailureFailClosed() {
        var enrollment = enroll();
        now.addAndGet(30_000L);
        var verify = dao.issue("alice", SUCCESS);
        long before = state().lastUsedStep;
        zeroSave.set(true);
        assertThrows(IllegalStateException.class, () -> dao.complete(verify.token, code(enrollment.secret)));
        assertEquals(before, state().lastUsedStep);
        zeroSave.set(false);
        assertEquals(Status.SUCCESS, dao.complete(verify.token, code(enrollment.secret)).getStatus());
    }

    @Test void storageFailureCannotLookLikeAbsentEnrollmentOrSuccessfulReset() throws Exception {
        enroll();
        String generation = state().generation;
        failSave.set(true);
        assertThrows(IllegalStateException.class, () -> dao.remove(7, generation));
        assertNotNull(state().secret);
        failSave.set(false);
        sql("DROP TABLE USER_TOTP_STATE");
        assertThrows(RuntimeException.class, () -> dao.issue("alice", SUCCESS));
        assertThrows(RuntimeException.class, dao::listEnrollments);
        assertThrows(RuntimeException.class, () -> dao.remove(7, generation));
    }

    @Test void corruptSecretAndPendingCiphertextFailClosed() throws Exception {
        enroll();
        sql("UPDATE USER_TOTP_STATE SET SECRET = 'broken'");
        assertThrows(IllegalStateException.class, () -> dao.issue("alice", SUCCESS));
        sql("UPDATE USER_TOTP_STATE SET SECRET = '" + encrypt.apply(SECRET) + "'");
        var challenge = dao.issue("alice", SUCCESS);
        sql("UPDATE USER_TOTP_STATE SET CHALLENGE_DATA = 'broken'");
        assertThrows(IllegalStateException.class, () -> dao.complete(challenge.token, code(SECRET)));
    }

    @Test void missingIdentityAndLookupFailureCannotBypassMfa() {
        dao.ensureTable();
        var plugin = new TotpAuthenticationPlugin(dao);
        users.clear();
        assertEquals(Status.FAIL, plugin.authenticate("alice", SUCCESS, "").getStatus());
        failIdentity.set(true);
        assertEquals(Status.FAIL, plugin.authenticate("alice", SUCCESS, "").getStatus());
    }

    @Test void renameDeletionNameReuseAndPasswordChangesInvalidatePendingChallenges() {
        dao.ensureTable();
        var challenge = dao.issue("alice", SUCCESS);
        users.put(7, new TotpIdentity.Snapshot(7, "renamed", "password-state-1"));
        users.put(99, new TotpIdentity.Snapshot(99, "alice", "new-account"));
        assertThrows(IllegalStateException.class, () -> dao.complete(challenge.token, code(challenge.secret)));
        users.remove(7);
        assertThrows(IllegalStateException.class, () -> dao.complete(challenge.token, code(challenge.secret)));
        users.remove(99);
        users.put(7, new TotpIdentity.Snapshot(7, "alice", "password-state-2"));
        assertEquals(Status.FAIL, dao.complete(challenge.token, code(challenge.secret)).getStatus());
        assertNull(state().tokenHash);
    }

    @Test void graceStatusMessageAndUnicodeIdentitySurviveCompletion() {
        dao.ensureTable();
        users.put(7, new TotpIdentity.Snapshot(7, "a\"\\é\n", "password-state-1"));
        LoginStatus grace = new LoginStatus(Status.SUCCESS_GRACE_PERIOD, "Password expires soon: \"today\".");
        var issued = dao.issue(users.get(7).username, grace);
        var result = dao.complete(issued.token, code(issued.secret));
        assertEquals(grace.getStatus(), result.getStatus());
        assertEquals(grace.getMessage(), result.getMessage());
        assertEquals(users.get(7).username, result.getUpdatedUsername());
    }

    @Test void migrationPreservesUsernameSchemaAndNeverResurrectsReset() throws Exception {
        legacy(false, "alice", encrypt.apply(SECRET), 1234);
        dao.ensureTable();
        assertEquals(encrypt.apply(SECRET), state().secret);
        assertEquals(1234, state().lastUsedStep);
        assertEquals(1_600_000_000_000L, state().enrolledAt.getTime());
        assertTrue(dao.remove(7, state().generation));
        dao.ensureTable();
        assertNull(state().secret);
        assertTrue(dao.listEnrollments().isEmpty());
    }

    @Test void migrationPreservesUserIdSchemaAcrossRenameAndRepeatedStartup() throws Exception {
        legacy(true, 7, encrypt.apply(SECRET), 4321);
        users.put(7, new TotpIdentity.Snapshot(7, "renamed", "same-password"));
        dao.ensureTable();
        String generation = state().generation;
        dao.ensureTable();
        assertEquals(4321, state().lastUsedStep);
        assertEquals(generation, state().generation);
        assertNull(dao.issue("renamed", SUCCESS).secret);
    }

    @Test void interruptedMigrationRollsBackAllRowsAndRetries() throws Exception {
        legacy(false, "alice", encrypt.apply(SECRET), 1);
        legacyRow("bob", encrypt.apply(SECRET), 2);
        users.put(8, new TotpIdentity.Snapshot(8, "bob", "p"));
        doThrow(new IllegalStateException("Injected identity read error")).when(identities)
                .read(any(), isNull(), eq("bob"));
        assertThrows(IllegalStateException.class, dao::ensureTable);
        assertNull(state());
        assertThrows(IllegalStateException.class, () -> dao.issue("alice", SUCCESS));
        doReturn(users.get(8)).when(identities).read(any(), isNull(), eq("bob"));
        dao.ensureTable();
        assertEquals(2, dao.listEnrollments().size());
    }

    @Test void ambiguousUsernameMigrationFailsClosedWithoutPartialRows() throws Exception {
        legacy(false, "alice", encrypt.apply(SECRET), 1);
        users.put(8, new TotpIdentity.Snapshot(8, "ALICE", "p"));
        assertThrows(IllegalStateException.class, dao::ensureTable);
        assertNull(state());
    }

    @Test void orphanUsernameMigrationDoesNotTransferToFutureAccount() throws Exception {
        legacy(false, "deleted", encrypt.apply(SECRET), 1);
        dao.ensureTable();
        users.put(8, new TotpIdentity.Snapshot(8, "deleted", "p"));
        dao.ensureTable();
        assertNotNull(dao.issue("deleted", SUCCESS).secret);
    }

    @Test void orphanIdMigrationIsArchivedWithoutBlockingOtherAccounts() throws Exception {
        legacy(true, 8, encrypt.apply(SECRET), 1);
        legacyRow(7, encrypt.apply(SECRET), 2);
        dao.ensureTable();
        assertEquals(1, dao.listEnrollments().size());
        assertEquals(2, state().lastUsedStep);
    }

    @Test void corruptMigrationCiphertextAndInvalidExistingSchemaFailClosed() throws Exception {
        legacy(true, 7, "broken", 1);
        assertThrows(IllegalStateException.class, dao::ensureTable);
        assertNull(state());
        sql("DROP TABLE USER_TOTP_STATE");
        sql("CREATE TABLE USER_TOTP_STATE (USER_ID INTEGER)");
        assertThrows(RuntimeException.class, dao::ensureTable);
    }

    @Test void completedMigrationMustNeverRecreateLostCredentialTable() throws Exception {
        enroll();
        sql("DROP TABLE USER_TOTP_STATE");
        assertThrows(RuntimeException.class, dao::ensureTable);
        assertThrows(RuntimeException.class, () -> dao.issue("alice", SUCCESS));
    }

    @Test void startupMustFinishBeforeAuthenticationCanProceed() {
        assertThrows(RuntimeException.class, () -> dao.issue("alice", SUCCESS));
    }

    @Test void recoverySwitchAllowsPrimaryLoginWithoutStartingDatabase() {
        System.setProperty("org.openintegrationengine.totp.disabled", "true");
        var plugin = new TotpAuthenticationPlugin(dao);
        assertDoesNotThrow(plugin::start);
        assertSame(SUCCESS, plugin.authenticate("alice", SUCCESS, ""));
        assertEquals(Status.FAIL, plugin.authenticate("anything").getStatus());
    }

    @Test void settingsCleanupFailureCannotUnregisterMfaDuringEngineInitialization() {
        var plugin = new TotpAuthenticationPlugin(dao, properties -> {
            assertNull(properties.getProperty("totp.hmacKey"));
            throw new IllegalStateException("Settings unavailable");
        });
        var properties = new java.util.Properties();
        properties.setProperty("totp.hmacKey", "obsolete-known-key");
        assertDoesNotThrow(() -> plugin.init(properties));
        plugin.start();
        assertInstanceOf(ExtendedLoginStatus.class, plugin.authenticate("alice", SUCCESS, ""));
        failIdentity.set(true);
        assertEquals(Status.FAIL, plugin.authenticate("alice", SUCCESS, "").getStatus());
    }

    @Test void primaryFailurePassesThroughAndMalformedSecondLegFails() {
        var plugin = new TotpAuthenticationPlugin(dao);
        var failed = new LoginStatus(Status.FAIL_LOCKED_OUT, "locked");
        assertSame(failed, plugin.authenticate("alice", failed, ""));
        assertNull(plugin.authenticate("alice", null, ""));
        for (String value : new String[] { null, "%%%", "", "x".repeat(5000), "e30=" }) {
            assertEquals(Status.FAIL, plugin.authenticate(value).getStatus());
        }
    }

    @Test void pluginCompletesActualBase64JsonContract() throws Exception {
        dao.ensureTable();
        var plugin = new TotpAuthenticationPlugin(dao);
        var first = plugin.authenticate("alice", SUCCESS, "");
        assertInstanceOf(ExtendedLoginStatus.class, first);
        var json = new com.fasterxml.jackson.databind.ObjectMapper().readTree(first.getMessage());
        String payload = "{\"challenge\":\"" + json.get("challenge").asText()
                + "\",\"code\":\"" + code(json.get("secret").asText()) + "\"}";
        assertEquals(Status.SUCCESS, plugin.authenticate(Base64.getEncoder()
                .encodeToString(payload.getBytes(StandardCharsets.UTF_8))).getStatus());
    }
}
