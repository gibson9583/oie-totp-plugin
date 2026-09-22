/* Published under the terms of the Mozilla Public License 2.0. */
package org.openintegrationengine.plugins.totp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import org.apache.ibatis.session.SqlSession;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mirth.connect.model.Credentials;
import com.mirth.connect.model.User;

/** Reads identity and password state from the primary database, never a read replica. */
final class TotpIdentity {
    private static final ObjectMapper JSON = new ObjectMapper();

    interface Source {
        Snapshot read(SqlSession session, Integer userId, String username);
    }

    static final class Snapshot {
        final int userId;
        final String username;
        final String securityStamp;

        Snapshot(int userId, String username, String securityStamp) {
            this.userId = userId;
            this.username = username;
            this.securityStamp = securityStamp;
        }
    }

    static Snapshot read(SqlSession session, Integer userId, String username) {
        User filter = new User();
        filter.setId(userId);
        filter.setUsername(username);
        List<User> users = session.selectList("User.getUser", filter);
        // Ambiguous case-insensitive names cannot safely bind an MFA login session.
        if (users.isEmpty()) {
            return null;
        }
        if (users.size() != 1) {
            throw new IllegalStateException("The account identity is missing or ambiguous.");
        }
        User user = users.get(0);
        if (user.getId() == null || user.getUsername() == null) {
            throw new IllegalStateException("The account identity is incomplete.");
        }
        List<Credentials> credentials = session.selectList("User.getUserCredentials", user.getId());
        List<String> passwords = new ArrayList<>();
        for (Credentials credential : credentials) {
            passwords.add(credential.getPassword() + ":" + (credential.getPasswordDate() == null
                    ? "" : credential.getPasswordDate().getTimeInMillis()));
        }
        passwords.sort(String::compareTo);
        try {
            String stamp = JSON.writeValueAsString(new Object[] { user.getId(), user.getUsername(),
                    user.getRole(), user.getStrikeCount(), user.getLastStrikeTime() == null ? null
                            : user.getLastStrikeTime().getTimeInMillis(), passwords });
            return new Snapshot(user.getId(), user.getUsername(), hash(stamp));
        } catch (Exception e) {
            throw new IllegalStateException("Could not establish account security state.", e);
        }
    }

    static String hash(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
