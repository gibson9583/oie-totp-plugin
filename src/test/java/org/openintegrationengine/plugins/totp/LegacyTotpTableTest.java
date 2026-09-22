/* Published under the terms of the Mozilla Public License 2.0. */
package org.openintegrationengine.plugins.totp;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.sql.Statement;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

class LegacyTotpTableTest {
    @Test
    void actualTableResolutionWorksWithoutSchemaOrMetadataPrivilege() throws Exception {
        Fixture db = new Fixture("unknown", null);
        assertTrue(LegacyTotpTable.exists(db.connection()));
        assertEquals(0, db.metadataCalls);
        assertEquals(0, db.savepointRollbacks);
        assertEquals(0, db.transactionEnds);
    }

    @Test
    void recognizedAbsenceRequiresVendorSpecificErrorAndCorroboration() throws Exception {
        for (Fixture db : new Fixture[] {
                new Fixture("Apache Derby", new SQLException("absent", "42X05")),
                new Fixture("MySQL", new SQLException("absent", "42S02", 1146)),
                new Fixture("MariaDB", new SQLException("absent", "42S02", 1146)),
                new Fixture("PostgreSQL", new SQLException("absent", "42P01")),
                new Fixture("Oracle", new SQLException("absent", "42000", 942)),
                new Fixture("Microsoft SQL Server", new SQLException("absent", "S0002", 208)) }) {
            assertFalse(LegacyTotpTable.exists(db.connection()), db.product);
            assertEquals(1, db.savepointRollbacks, db.product);
            assertEquals(0, db.transactionEnds, db.product);
        }
    }

    @Test
    void permissionConnectionAndUnknownVendorFailuresNeverMeanAbsence() {
        for (Fixture db : new Fixture[] {
                new Fixture("Apache Derby", new SQLException("denied", "42502")),
                new Fixture("MySQL", new SQLException("denied", "42000", 1142)),
                new Fixture("PostgreSQL", new SQLException("denied", "42501")),
                new Fixture("Microsoft SQL Server", new SQLException("denied", "S0005", 229)),
                new Fixture("Oracle", new SQLException("connection lost", "08006", 17002)),
                new Fixture("unknown", new SQLException("absent", "42P01")) }) {
            assertSame(db.probeFailure, assertThrows(SQLException.class,
                    () -> LegacyTotpTable.exists(db.connection())), db.product);
            assertEquals(1, db.savepointRollbacks);
            assertEquals(0, db.transactionEnds);
        }
    }

    @Test
    void invisibleOrOutOfSearchPathPostgresTableIsNotAFreshInstall() {
        Fixture db = new Fixture("PostgreSQL", new SQLException("absent", "42P01"));
        db.objectCount = 1;
        assertThrows(SQLException.class, () -> LegacyTotpTable.exists(db.connection()));
        assertEquals(1, db.savepointRollbacks);
    }

    @Test
    void sqlServerHiddenMetadataAndExistingObjectsFailClosed() {
        Fixture db = new Fixture("Microsoft SQL Server", new SQLException("absent", "S0002", 208));
        db.visibility = 0;
        assertThrows(SQLException.class, () -> LegacyTotpTable.exists(db.connection()));
        db.visibility = 1;
        db.objectCount = 1;
        assertThrows(SQLException.class, () -> LegacyTotpTable.exists(db.connection()));
    }

    @Test
    void oracleInaccessibleObjectSynonymAndForeignCurrentSchemaFailClosed() {
        Fixture db = new Fixture("Oracle", new SQLException("absent or denied", "42000", 942));
        db.visibility = 0;
        assertThrows(SQLException.class, () -> LegacyTotpTable.exists(db.connection()));
        db.visibility = 1;
        db.objectCount = 1;
        assertThrows(SQLException.class, () -> LegacyTotpTable.exists(db.connection()));
        db.objectCount = 0;
        db.synonymCount = 1;
        assertThrows(SQLException.class, () -> LegacyTotpTable.exists(db.connection()));
    }

    @Test
    void visibleUnresolvedLegacyObjectDoesNotBecomeFreshEnrollment() {
        Fixture db = new Fixture("Apache Derby", new SQLException("absent", "42X05"));
        db.objectCount = 1;
        assertThrows(SQLException.class, () -> LegacyTotpTable.exists(db.connection()));
    }

    @Test
    void metadataFailureFailsClosedAndRetainsOriginalProbeFailure() {
        Fixture db = new Fixture("PostgreSQL", new SQLException("absent", "42P01"));
        db.catalogFailure = new SQLException("catalog denied", "42501");
        SQLException error = assertThrows(SQLException.class, () -> LegacyTotpTable.exists(db.connection()));
        assertSame(db.catalogFailure, error);
        assertArrayEquals(new Throwable[] { db.probeFailure }, error.getSuppressed());
    }

    @Test
    void rollbackFailureCannotBeMisclassifiedAsAbsence() {
        Fixture db = new Fixture("PostgreSQL", new SQLException("absent", "42P01"));
        db.rollbackFailure = new SQLException("rollback failed", "08006");
        SQLException error = assertThrows(SQLException.class, () -> LegacyTotpTable.exists(db.connection()));
        assertSame(db.probeFailure, error);
        assertArrayEquals(new Throwable[] { db.rollbackFailure }, error.getSuppressed());
        assertEquals(0, db.metadataCalls);
    }

    @Test
    void autoCommitCannotDiscardTheMigrationLock() {
        Fixture db = new Fixture("Apache Derby", null);
        db.autoCommit = true;
        assertThrows(SQLException.class, () -> LegacyTotpTable.exists(db.connection()));
        assertEquals(0, db.probes);
    }

    @Test
    void realDerbyMissingProbePreservesPriorWorkAndExistingTableIsDetected() throws Exception {
        String url = "jdbc:derby:memory:totpProbe" + UUID.randomUUID().toString().replace("-", "");
        try {
            try (Connection db = DriverManager.getConnection(url + ";create=true");
                    Statement sql = db.createStatement()) {
                db.setAutoCommit(false);
                sql.executeUpdate("CREATE TABLE MIGRATION_GUARD (ID INTEGER PRIMARY KEY, REVISION INTEGER)");
                sql.executeUpdate("INSERT INTO MIGRATION_GUARD VALUES (1, 0)");
                db.commit();
                sql.executeUpdate("UPDATE MIGRATION_GUARD SET REVISION = 1 WHERE ID = 1");
                assertFalse(LegacyTotpTable.exists(db));
                try (ResultSet rows = sql.executeQuery("SELECT REVISION FROM MIGRATION_GUARD WHERE ID = 1")) {
                    assertTrue(rows.next());
                    assertEquals(1, rows.getInt(1));
                }
                db.rollback();
                try (ResultSet rows = sql.executeQuery("SELECT REVISION FROM MIGRATION_GUARD WHERE ID = 1")) {
                    assertTrue(rows.next());
                    assertEquals(0, rows.getInt(1));
                }
                sql.executeUpdate("CREATE TABLE USER_TOTP (USER_ID INTEGER PRIMARY KEY)");
                assertTrue(LegacyTotpTable.exists(db));
                db.rollback();
            }
        } finally {
            SQLException dropped = assertThrows(SQLException.class,
                    () -> DriverManager.getConnection(url + ";drop=true"));
            assertEquals("08006", dropped.getSQLState(), "Owned in-memory database was dropped");
        }
    }

    private static final class Fixture {
        final String product;
        SQLException probeFailure;
        SQLException rollbackFailure;
        SQLException catalogFailure;
        long visibility = 1;
        long objectCount;
        long synonymCount;
        int savepointRollbacks;
        int transactionEnds;
        int metadataCalls;
        int probes;
        boolean autoCommit;
        final Savepoint savepoint = proxy(Savepoint.class, (name, args) -> 1);

        Fixture(String product, SQLException probeFailure) {
            this.product = product;
            this.probeFailure = probeFailure;
        }

        Connection connection() {
            return proxy(Connection.class, (name, args) -> {
                switch (name) {
                    case "getAutoCommit": return autoCommit;
                    case "setSavepoint": return savepoint;
                    case "getSchema": throw new UnsupportedOperationException("Old driver has no getSchema");
                    case "releaseSavepoint": throw new UnsupportedOperationException("Unsupported by vendor");
                    case "getCatalog": return "engine";
                    case "getMetaData":
                        metadataCalls++;
                        return proxy(DatabaseMetaData.class, (method, values) -> {
                            if (method.equals("getDatabaseProductName")) return product;
                            if (method.equals("getTables")) return rows(objectCount, true);
                            throw new UnsupportedOperationException(method);
                        });
                    case "createStatement":
                        return proxy(Statement.class, (method, values) -> {
                            if (method.equals("close")) return null;
                            if (!method.equals("executeQuery")) throw new UnsupportedOperationException(method);
                            String sql = (String) values[0];
                            if (sql.equals("SELECT * FROM USER_TOTP WHERE 1 = 0")) {
                                probes++;
                                if (probeFailure != null) throw probeFailure;
                                return rows(0, true);
                            }
                            if (catalogFailure != null) throw catalogFailure;
                            return rows(sql.contains("FROM DUAL") || sql.contains("HAS_PERMS_BY_NAME")
                                    ? visibility : sql.contains("ALL_SYNONYMS") ? synonymCount : objectCount, false);
                        });
                    case "rollback":
                        if (args != null && args.length == 1 && args[0] == savepoint) {
                            savepointRollbacks++;
                            if (rollbackFailure != null) throw rollbackFailure;
                        } else transactionEnds++;
                        return null;
                    case "commit": case "close": transactionEnds++; return null;
                    default: throw new UnsupportedOperationException(name);
                }
            });
        }
    }

    private static ResultSet rows(long value, boolean tableNames) {
        AtomicInteger index = new AtomicInteger();
        return proxy(ResultSet.class, (method, args) -> {
            switch (method) {
                case "next": return index.getAndIncrement() < (tableNames ? value : 1);
                case "getLong": return value;
                case "getString": return "USER_TOTP";
                case "wasNull": return false;
                case "close": return null;
                default: throw new UnsupportedOperationException(method);
            }
        });
    }

    @FunctionalInterface
    private interface Call { Object invoke(String method, Object[] args) throws Throwable; }

    private static <T> T proxy(Class<T> type, Call call) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type },
                (ignored, method, args) -> call.invoke(method.getName(), args)));
    }
}
