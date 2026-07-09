/*
 * OIE TOTP MFA — multi-factor authentication plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.totp;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.server.api.MirthServlet;

public class TotpAdminServlet extends MirthServlet implements TotpAdminServletInterface {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final TotpCredentialDao credentials = new TotpCredentialDao();

    public TotpAdminServlet(@Context HttpServletRequest request, @Context SecurityContext sc) {
        super(request, sc, PLUGIN_POINT);
    }

    @Override
    public String listEnrolled() throws ClientException {
        try {
            List<String> users = credentials.listEnrolled();
            ArrayNode arr = MAPPER.createArrayNode();
            for (String u : users) {
                arr.add(u);
            }
            ObjectNode out = MAPPER.createObjectNode();
            out.set("users", arr);
            return out.toString();
        } catch (Exception e) {
            throw new ClientException("Failed to list TOTP enrollments: " + e.getMessage(), e);
        }
    }

    @Override
    public void reset(String username) throws ClientException {
        if (username == null || username.isBlank()) {
            throw new ClientException("A username is required.");
        }
        try {
            credentials.remove(username);
        } catch (Exception e) {
            throw new ClientException("Failed to reset TOTP for '" + username + "': " + e.getMessage(), e);
        }
    }
}
