/* Published under the terms of the Mozilla Public License 2.0. */
package org.openintegrationengine.plugins.totp;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.sql.Statement;
import java.util.Locale;

/** Resolves the same unqualified legacy table name that migration will read. */
final class LegacyTotpTable {
    private LegacyTotpTable() {}

    static boolean exists(Connection connection) throws SQLException {
        if (connection.getAutoCommit()) {
            throw new SQLException("Legacy TOTP detection requires the migration transaction.");
        }
        // A failed SELECT aborts PostgreSQL's transaction. Roll back only this
        // probe, preserving the migration lock acquired before the savepoint.
        // Commit/rollback releases the savepoint; releaseSavepoint itself is not
        // implemented by all supported JDBC drivers (notably Oracle/SQL Server).
        Savepoint probe = connection.setSavepoint();
        try (Statement statement = connection.createStatement();
                ResultSet ignored = statement.executeQuery("SELECT * FROM USER_TOTP WHERE 1 = 0")) {
            return true;
        } catch (SQLException failure) {
            try {
                connection.rollback(probe);
            } catch (SQLException rollbackFailure) {
                failure.addSuppressed(rollbackFailure);
                throw failure;
            }
            String product = connection.getMetaData().getDatabaseProductName().toLowerCase(Locale.ROOT);
            if (!isMissingTable(product, failure)) {
                throw failure;
            }
            try {
                confirmAbsent(connection, product);
            } catch (SQLException ambiguous) {
                ambiguous.addSuppressed(failure);
                throw ambiguous;
            }
            return false;
        }
    }

    private static boolean isMissingTable(String product, SQLException error) {
        if (product.contains("derby")) {
            return "42X05".equals(error.getSQLState());
        }
        if (product.contains("postgresql")) {
            return "42P01".equals(error.getSQLState());
        }
        if (product.contains("mysql") || product.contains("mariadb")) {
            return error.getErrorCode() == 1146 && "42S02".equals(error.getSQLState());
        }
        if (product.contains("oracle")) {
            return error.getErrorCode() == 942;
        }
        if (product.contains("microsoft sql server")) {
            return error.getErrorCode() == 208;
        }
        return false;
    }

    private static void confirmAbsent(Connection connection, String product) throws SQLException {
        if (product.contains("oracle")) {
            // ORA-00942 also means insufficient privilege. Own-schema objects and
            // private/public synonyms remain visible even when a target is not.
            // A different CURRENT_SCHEMA cannot prove absence without DBA grants.
            if (count(connection, "SELECT COUNT(*) FROM DUAL WHERE "
                    + "SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') = "
                    + "SYS_CONTEXT('USERENV', 'SESSION_USER')") != 1) {
                throw ambiguous("Oracle migration must resolve the schema owned by its database user");
            }
            if (count(connection, "SELECT COUNT(*) FROM USER_OBJECTS WHERE OBJECT_NAME = 'USER_TOTP'") != 0
                    || count(connection, "SELECT COUNT(*) FROM ALL_SYNONYMS WHERE SYNONYM_NAME = 'USER_TOTP' "
                            + "AND OWNER IN (SYS_CONTEXT('USERENV', 'SESSION_USER'), 'PUBLIC')") != 0) {
                throw ambiguous("Oracle legacy object or synonym exists but cannot be read");
            }
        } else if (product.contains("microsoft sql server")) {
            // Error 208 and sys.objects can both conceal objects from a restricted
            // account. Require metadata visibility only when proving a fresh install.
            if (count(connection, "SELECT HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'VIEW DEFINITION')") != 1) {
                throw ambiguous("SQL Server requires VIEW DEFINITION to confirm no legacy TOTP table exists");
            }
            if (count(connection, "SELECT COUNT(*) FROM sys.objects WHERE LOWER(name) = 'user_totp'") != 0) {
                throw ambiguous("SQL Server legacy object exists but does not resolve or cannot be read");
            }
        } else if (product.contains("postgresql")) {
            // pg_class is not the privilege-filtered information_schema view.
            // Refuse an inaccessible/out-of-search-path table rather than turn an
            // existing enrollment into a fresh installation after a schema change.
            if (count(connection, "SELECT COUNT(*) FROM pg_catalog.pg_class "
                    + "WHERE LOWER(relname) = 'user_totp'") != 0) {
                throw ambiguous("PostgreSQL legacy object exists outside the accessible search path");
            }
        } else {
            // Derby/MySQL distinguish missing-table from permission errors. Also
            // reject a visible object in another schema or an unresolved view.
            try (ResultSet tables = connection.getMetaData().getTables(connection.getCatalog(), null,
                    "%", new String[] { "TABLE", "VIEW", "SYNONYM" })) {
                while (tables.next()) {
                    if ("USER_TOTP".equalsIgnoreCase(tables.getString("TABLE_NAME"))) {
                        throw ambiguous("Legacy TOTP object exists but does not resolve or cannot be read");
                    }
                }
            }
        }
    }

    private static long count(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(sql)) {
            if (!rows.next()) {
                throw ambiguous("Database did not return legacy metadata visibility");
            }
            long count = rows.getLong(1);
            if (rows.wasNull() || rows.next()) {
                throw ambiguous("Database returned ambiguous legacy metadata visibility");
            }
            return count;
        }
    }

    private static SQLException ambiguous(String detail) {
        return new SQLException(detail + "; refusing to discard existing MFA enrollments.");
    }
}
