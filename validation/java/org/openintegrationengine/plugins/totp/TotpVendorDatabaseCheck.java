/* Published under the terms of the Mozilla Public License 2.0. */
package org.openintegrationengine.plugins.totp;

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

import org.apache.ibatis.builder.xml.XMLMapperBuilder;
import org.apache.ibatis.datasource.pooled.PooledDataSource;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import org.apache.ibatis.transaction.jdbc.JdbcTransactionFactory;
import com.mirth.connect.model.LoginStatus;
import com.mirth.connect.model.LoginStatus.Status;

/** External-vendor contract check. Run only through the owned-container runner. */
public final class TotpVendorDatabaseCheck {
    private static final String SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    private static final LoginStatus SUCCESS = new LoginStatus(Status.SUCCESS, "");
    private final String vendor = required("TOTP_VENDOR");
    private final String url = required("TOTP_JDBC_URL");
    private final String user = required("TOTP_DB_USER");
    private final String password = required("TOTP_DB_PASSWORD");
    private final AtomicLong now = new AtomicLong(1_700_000_000_000L);
    private final Map<Integer, TotpIdentity.Snapshot> users = new ConcurrentHashMap<>();
    private final Function<String, String> encrypt = value -> "fixture:" + Base64.getEncoder()
            .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    private final Function<String, String> decrypt = value -> {
        if (value == null || !value.startsWith("fixture:")) throw new IllegalStateException("Bad fixture ciphertext");
        return new String(Base64.getDecoder().decode(value.substring(8)), StandardCharsets.UTF_8);
    };
    private SqlSessionFactory sessions;
    private PooledDataSource source;
    private volatile String failIdentity;
    private int passed;

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Missing " + name);
        return value;
    }
    private Connection connect() throws SQLException {
        return source == null ? DriverManager.getConnection(url, user, password) : source.getConnection();
    }
    private TotpCredentialDao dao() {
        return new TotpCredentialDao(() -> sessions.openSession(false), encrypt, decrypt,
                (session, id, name) -> {
                    if (name != null && name.equals(failIdentity)) throw new IllegalStateException("Injected lookup failure");
                    if (id != null) return users.get(id);
                    var matches = users.values().stream().filter(u -> u.username.equalsIgnoreCase(name)).toList();
                    if (matches.size() > 1) throw new IllegalStateException("Ambiguous account");
                    return matches.isEmpty() ? null : matches.get(0);
                }, now::get);
    }
    private void configure() throws Exception {
        // Match the engine's bounded connection reuse. Unpooled Oracle churn can
        // exhaust listener handlers before recently closed sessions deregister.
        source = new PooledDataSource(required("TOTP_JDBC_DRIVER"), url, user, password);
        source.setPoolMaximumActiveConnections(12);
        source.setPoolMaximumIdleConnections(12);
        source.setPoolMaximumCheckoutTime(60_000);
        var configuration = new Configuration(new Environment("vendor", new JdbcTransactionFactory(), source));
        configuration.setDefaultStatementTimeout(30);
        try (var mapper = new FileInputStream("mapper/" + vendor + "-usertotp.xml")) {
            new XMLMapperBuilder(mapper, configuration, vendor + "-usertotp.xml", configuration.getSqlFragments()).parse();
        }
        sessions = new SqlSessionFactoryBuilder().build(configuration);
    }
    private TotpCredentialDao.State state(int id) {
        SqlSession session = sessions.openSession();
        try { return session.selectOne("UserTotp.find", id); }
        finally { session.close(); }
    }
    private String code(String secret) { return Totp.generate(Totp.base32Decode(secret), now.get() / 30_000L); }
    private String wrong(String secret) {
        for (int i = 0; i < 100; i++) {
            String candidate = String.format(Locale.ROOT, "%06d", i);
            if (Totp.matchStep(secret, candidate, now.get()) < 0) return candidate;
        }
        throw new AssertionError("No invalid code");
    }
    private static void check(boolean value, String message) { if (!value) throw new AssertionError(message); }
    private static void throwsFailure(Runnable operation) {
        try { operation.run(); }
        catch (RuntimeException expected) { return; }
        throw new AssertionError("Expected fail-closed exception");
    }
    private void sql(String command) throws Exception {
        try (Connection connection = connect(); var statement = connection.createStatement()) { statement.execute(command); }
    }
    private void clear() throws Exception {
        // The launcher creates a unique isolated container and requires its
        // matching ownership token. Never accept a shared database URL by itself.
        check(required("TOTP_OWNED_VALIDATION").startsWith("totp-vendor-"), "Owned-container receipt required");
        for (String table : new String[] { "USER_TOTP_STATE", "USER_TOTP_META", "USER_TOTP" }) {
            try { sql("DROP TABLE " + table); }
            catch (SQLException e) {
                // Exact absent-table states/codes for the supported vendor, not
                // a blanket ignored cleanup failure.
                boolean absent = (vendor.equals("postgres") && "42P01".equals(e.getSQLState()))
                        || (vendor.equals("mysql") && e.getErrorCode() == 1051)
                        || (vendor.equals("oracle") && e.getErrorCode() == 942)
                        || (vendor.equals("sqlserver") && e.getErrorCode() == 3701);
                if (!absent) throw e;
            }
        }
        users.clear();
        users.put(7, new TotpIdentity.Snapshot(7, "alice", "password-state-1"));
        now.set(1_700_000_000_000L);
        failIdentity = null;
    }
    private void legacy(boolean idBased) throws Exception {
        String number = vendor.equals("oracle") ? "NUMBER(19)" : "BIGINT";
        String timestamp = vendor.equals("sqlserver") ? "DATETIME2" : "TIMESTAMP";
        sql("CREATE TABLE USER_TOTP (" + (idBased ? "USER_ID INTEGER" : "USERNAME VARCHAR(255)")
                + " PRIMARY KEY, SECRET VARCHAR(512) NOT NULL, ENROLLED_AT " + timestamp + ", LAST_USED_STEP " + number + ")");
        legacyRow(idBased ? 7 : "alice", 1234);
    }
    private void legacyRow(Object identity, long step) throws Exception {
        try (Connection connection = connect(); PreparedStatement insert = connection.prepareStatement("INSERT INTO USER_TOTP VALUES (?, ?, ?, ?)")) {
            insert.setObject(1, identity);
            insert.setString(2, encrypt.apply(SECRET));
            insert.setTimestamp(3, new Timestamp(1_600_000_000_000L));
            insert.setLong(4, step);
            check(insert.executeUpdate() == 1, "Legacy insert");
        }
    }
    private void observe(String scenario) throws Exception {
        System.out.println("OBSERVATION " + scenario);
        try (Connection connection = connect(); var statement = connection.createStatement();
                ResultSet rows = statement.executeQuery("SELECT USER_ID, SECRET, LAST_USED_STEP, GENERATION, TOKEN_HASH, ATTEMPTS, REVISION FROM USER_TOTP_STATE ORDER BY USER_ID")) {
            while (rows.next()) {
                String secret = rows.getString("SECRET");
                System.out.println("ROW user=" + rows.getInt("USER_ID") + " secretSha256="
                        + (secret == null ? "null" : TotpIdentity.hash(secret)) + " step=" + rows.getLong("LAST_USED_STEP")
                        + " generation=" + rows.getString("GENERATION") + " tokenPresent=" + (rows.getString("TOKEN_HASH") != null)
                        + " attempts=" + rows.getInt("ATTEMPTS") + " revision=" + rows.getLong("REVISION"));
            }
        }
        try (Connection connection = connect(); var statement = connection.createStatement();
                ResultSet rows = statement.executeQuery("SELECT ID, MIGRATED, REVISION FROM USER_TOTP_META")) {
            while (rows.next()) System.out.println("META id=" + rows.getInt(1) + " migrated=" + rows.getInt(2) + " revision=" + rows.getLong(3));
        }
    }
    private interface Action { void run() throws Exception; }
    private interface ConcurrentAction { boolean run() throws Exception; }
    private void scenario(String name, Action action) throws Exception {
        clear();
        try {
            action.run();
            observe(name);
            passed++;
            System.out.println("PASS " + name);
        } catch (Throwable failure) {
            try { observe("FAILED " + name); }
            catch (Exception evidenceFailure) { failure.addSuppressed(evidenceFailure); }
            throw failure;
        }
    }
    private int race(int count, ConcurrentAction action) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(count);
        CountDownLatch ready = new CountDownLatch(count), start = new CountDownLatch(1);
        List<Future<Boolean>> results = new ArrayList<>();
        try {
            for (int i = 0; i < count; i++) results.add(executor.submit(() -> { ready.countDown(); start.await(); return action.run(); }));
            check(ready.await(10, TimeUnit.SECONDS), "Workers did not start");
            start.countDown();
            int successes = 0;
            for (Future<Boolean> result : results) if (result.get(45, TimeUnit.SECONDS)) successes++;
            return successes;
        } finally {
            executor.shutdownNow();
            check(executor.awaitTermination(45, TimeUnit.SECONDS), "Workers did not exit");
        }
    }
    private void run() throws Exception {
        scenario("clean startup, enrollment, replay rejection, verify, generation reset", () -> {
            var dao = dao(); dao.ensureTable(); dao.ensureTable();
            var enrollment = dao.issue("alice", SUCCESS);
            check(enrollment.secret != null, "New enrollment missing secret");
            check(dao.complete(enrollment.token, code(enrollment.secret)).isSuccess(), "Enrollment failed");
            check(!dao.complete(enrollment.token, code(enrollment.secret)).isSuccess(), "Enrollment replay accepted");
            check(encrypt.apply(enrollment.secret).equals(state(7).secret), "Ciphertext changed");
            var verify = dao.issue("alice", SUCCESS);
            check(verify.secret == null, "Existing factor became enrollment");
            check(!dao.complete(verify.token, code(enrollment.secret)).isSuccess(), "Timestep replay accepted");
            now.addAndGet(30_000);
            check(dao.complete(verify.token, code(enrollment.secret)).isSuccess(), "Verification failed");
            String generation = state(7).generation;
            check(dao.remove(7, generation), "Reset failed");
            check(dao.remove(7, generation), "Reset retry not idempotent");
            var next = dao.issue("alice", SUCCESS);
            check(dao.complete(next.token, code(next.secret)).isSuccess(), "Reenrollment failed");
            check(!dao.remove(7, generation), "Stale reset removed replacement");
        });
        for (boolean ids : new boolean[] { false, true }) {
            scenario((ids ? "ID" : "username") + " migration, restart and no resurrection", () -> {
                legacy(ids);
                var dao = dao(); dao.ensureTable();
                check(state(7).lastUsedStep == 1234, "Replay counter lost");
                check(state(7).enrolledAt.getTime() == 1_600_000_000_000L, "Enrollment timestamp lost");
                check(encrypt.apply(SECRET).equals(state(7).secret), "Legacy ciphertext changed");
                String generation = state(7).generation;
                dao().ensureTable();
                check(generation.equals(state(7).generation), "Restart remigrated account");
                check(dao.issue("alice", SUCCESS).secret == null, "Migrated factor missing");
                check(dao.remove(7, generation), "Migrated enrollment reset failed");
                dao().ensureTable();
                check(dao.listEnrollments().isEmpty(), "Restart resurrected legacy secret");
                check(state(7).secret == null, "Reset tombstone lost");
            });
        }
        scenario("interrupted migration rolls back and resumes", () -> {
            legacy(false); legacyRow("bob", 1235);
            users.put(8, new TotpIdentity.Snapshot(8, "bob", "password-state-2"));
            failIdentity = "bob";
            throwsFailure(() -> dao().ensureTable());
            check(state(7) == null && state(8) == null, "Partial legacy migration committed");
            throwsFailure(() -> dao().issue("alice", SUCCESS));
            failIdentity = null;
            dao().ensureTable();
            check(dao().listEnrollments().size() == 2, "Migration did not resume");
        });
        scenario("ambiguous migration fails closed", () -> {
            legacy(false);
            users.put(8, new TotpIdentity.Snapshot(8, "ALICE", "password-state-2"));
            throwsFailure(() -> dao().ensureTable());
            check(state(7) == null, "Ambiguous migration inserted account");
        });
        scenario("concurrent enrollment and verification are single use", () -> {
            dao().ensureTable();
            var enrollment = dao().issue("alice", SUCCESS);
            check(race(6, () -> dao().complete(enrollment.token, code(enrollment.secret)).isSuccess()) == 1, "Concurrent enrollment not single use");
            now.addAndGet(30_000);
            var verify = dao().issue("alice", SUCCESS);
            check(race(6, () -> dao().complete(verify.token, code(enrollment.secret)).isSuccess()) == 1, "Concurrent verification not single use");
        });
        scenario("concurrent new-account challenges leave one usable token", () -> {
            dao().ensureTable();
            var challenges = java.util.Collections.synchronizedList(new ArrayList<TotpCredentialDao.IssuedChallenge>());
            race(6, () -> { challenges.add(dao().issue("alice", SUCCESS)); return true; });
            int successes = 0;
            for (var challenge : challenges) if (dao().complete(challenge.token, code(challenge.secret)).isSuccess()) successes++;
            check(successes == 1, "Superseded challenge remained usable");
        });
        scenario("attempt limit across concurrent DAO instances and cooldown", () -> {
            dao().ensureTable();
            var challenge = dao().issue("alice", SUCCESS);
            check(race(8, () -> dao().complete(challenge.token, wrong(challenge.secret)).isSuccess()) == 0, "Wrong code accepted");
            check(state(7).attempts == TotpCredentialDao.MAX_ATTEMPTS, "Attempt limit bypassed");
            check(state(7).tokenHash == null, "Exhausted challenge survived");
            throwsFailure(() -> dao().issue("alice", SUCCESS));
            now.addAndGet(TotpCredentialDao.ATTEMPT_WINDOW_MILLIS);
            var fresh = dao().issue("alice", SUCCESS);
            check(dao().complete(fresh.token, code(fresh.secret)).isSuccess(), "Cooldown never recovered");
        });
        scenario("reset revokes pending challenge and replacement secret", () -> {
            dao().ensureTable();
            var enrollment = dao().issue("alice", SUCCESS);
            check(dao().complete(enrollment.token, code(enrollment.secret)).isSuccess(), "Enrollment failed");
            var pending = dao().issue("alice", SUCCESS);
            String generation = state(7).generation;
            check(dao().remove(7, generation), "Reset failed");
            now.addAndGet(30_000);
            check(!dao().complete(pending.token, code(enrollment.secret)).isSuccess(), "Reset did not revoke token");
        });
        System.out.println("RESULT vendor=" + vendor + " scenarios=" + passed + " passed=" + passed);
    }
    public static void main(String[] args) throws Exception {
        DriverManager.setLoginTimeout(5);
        var check = new TotpVendorDatabaseCheck();
        Class.forName(required("TOTP_JDBC_DRIVER"));
        try (Connection connection = check.connect()) {
            var metadata = connection.getMetaData();
            System.out.println("DATABASE " + metadata.getDatabaseProductName() + " " + metadata.getDatabaseProductVersion());
            System.out.println("DRIVER " + metadata.getDriverName() + " " + metadata.getDriverVersion());
            System.out.println("ISOLATION " + connection.getTransactionIsolation());
        }
        if (args.length > 0 && args[0].equals("--probe")) return;
        check.configure();
        try { check.run(); }
        finally { check.source.forceCloseAll(); }
    }
}
