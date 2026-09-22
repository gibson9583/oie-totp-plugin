package org.openintegrationengine.plugins.totp;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.UUID;
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

/** Exercises real engine User/Credentials objects and the primary SQL lookup shape. */
class TotpIdentityTest {
    String url;
    SqlSessionFactory sessions;

    @BeforeEach void setup() throws Exception {
        url = "jdbc:derby:memory:identity_" + UUID.randomUUID().toString().replace("-", "") + ";create=true";
        var source = new UnpooledDataSource("org.apache.derby.jdbc.EmbeddedDriver", url, null, null);
        Configuration configuration = new Configuration(new Environment("test", new JdbcTransactionFactory(), source));
        String xml = """
            <?xml version="1.0" encoding="UTF-8" ?>
            <!DOCTYPE mapper PUBLIC '-//mybatis.org//DTD Mapper 3.0//EN' 'http://mybatis.org/dtd/mybatis-3-mapper.dtd'>
            <mapper namespace="User">
              <select id="getUser" parameterType="com.mirth.connect.model.User" resultType="com.mirth.connect.model.User">
                SELECT ID, USERNAME, ROLE FROM PERSON
                <where>
                  <if test="id != null"> ID = #{id} </if>
                  <if test="username != null"> AND LOWER(USERNAME) = LOWER(#{username}) </if>
                </where>
              </select>
              <resultMap id="credential" type="com.mirth.connect.model.Credentials">
                <result property="password" column="PASSWORD"/>
                <result property="passwordDate" column="PASSWORD_DATE"/>
              </resultMap>
              <select id="getUserCredentials" resultMap="credential">
                SELECT PASSWORD, PASSWORD_DATE FROM PERSON_PASSWORD WHERE PERSON_ID = #{id}
                ORDER BY PASSWORD_DATE DESC NULLS LAST
              </select>
            </mapper>
            """;
        new XMLMapperBuilder(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)), configuration,
                "engine-user-test.xml", configuration.getSqlFragments()).parse();
        sessions = new SqlSessionFactoryBuilder().build(configuration);
        sql("CREATE TABLE PERSON (ID INTEGER PRIMARY KEY, USERNAME VARCHAR(128), ROLE VARCHAR(128))");
        sql("CREATE TABLE PERSON_PASSWORD (PERSON_ID INTEGER, PASSWORD VARCHAR(128), PASSWORD_DATE TIMESTAMP)");
        sql("INSERT INTO PERSON VALUES (7, 'alice', 'admin')");
        sql("INSERT INTO PERSON_PASSWORD VALUES (7, 'password-hash-1', TIMESTAMP('2026-01-01 00:00:00'))");
    }

    void sql(String sql) throws Exception {
        try (Connection connection = DriverManager.getConnection(url); var statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    TotpIdentity.Snapshot read(Integer id, String name) {
        SqlSession session = sessions.openSession(false);
        try { return TotpIdentity.read(session, id, name); }
        finally { session.rollback(true); session.close(); }
    }

    @AfterEach void cleanup() throws Exception {
        try {
            DriverManager.getConnection(url.replace(";create=true", ";drop=true"));
            fail("Expected Derby database-dropped result");
        } catch (SQLException e) {
            assertTrue("08006".equals(e.getSQLState()) || "XJ004".equals(e.getSQLState()));
        }
    }

    @Test void primaryIdentityHasCanonicalNameAndPasswordBoundStamp() throws Exception {
        var identity = read(null, "ALICE");
        assertEquals(7, identity.userId);
        assertEquals("alice", identity.username);
        assertEquals(identity.securityStamp, read(7, null).securityStamp);
        sql("INSERT INTO PERSON_PASSWORD VALUES (7, 'password-hash-2', TIMESTAMP('2026-02-01 00:00:00'))");
        var changed = read(7, null);
        assertNotEquals(identity.securityStamp, changed.securityStamp);
        sql("UPDATE PERSON SET ROLE = 'viewer' WHERE ID = 7");
        assertNotEquals(changed.securityStamp, read(7, null).securityStamp);
    }

    @Test void absentAmbiguousAndUnavailableIdentityRemainDistinct() throws Exception {
        assertNull(read(999, null));
        sql("INSERT INTO PERSON VALUES (8, 'ALICE', 'viewer')");
        assertThrows(IllegalStateException.class, () -> read(null, "alice"));
        assertEquals(7, read(7, null).userId);
        sql("DROP TABLE PERSON_PASSWORD");
        assertThrows(RuntimeException.class, () -> read(7, null));
    }
}
