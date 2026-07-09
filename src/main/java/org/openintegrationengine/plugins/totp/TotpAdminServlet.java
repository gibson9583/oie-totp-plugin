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
import com.mirth.connect.model.User;
import com.mirth.connect.server.api.MirthServlet;
import com.mirth.connect.server.controllers.ControllerFactory;
import com.mirth.connect.server.controllers.UserController;

public class TotpAdminServlet extends MirthServlet implements TotpAdminServletInterface {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final TotpCredentialDao credentials = new TotpCredentialDao();

    public TotpAdminServlet(@Context HttpServletRequest request, @Context SecurityContext sc) {
        super(request, sc, PLUGIN_POINT);
    }

    @Override
    public String listEnrolled() throws ClientException {
        try {
            UserController userController = ControllerFactory.getFactory().createUserController();
            List<Integer> ids = credentials.listEnrolledIds();
            ArrayNode arr = MAPPER.createArrayNode();
            for (Integer id : ids) {
                User user = userController.getUser(id, null);
                if (user != null) {
                    ObjectNode row = MAPPER.createObjectNode();
                    row.put("id", id);
                    row.put("username", user.getUsername());
                    arr.add(row);
                } else {
                    // The user was removed — prune the orphaned enrollment so it can't
                    // be inherited if the id were ever reused, and never shows here.
                    credentials.remove(id);
                }
            }
            ObjectNode out = MAPPER.createObjectNode();
            out.set("users", arr);
            return out.toString();
        } catch (Exception e) {
            throw new ClientException("Failed to list TOTP enrollments: " + e.getMessage(), e);
        }
    }

    @Override
    public void reset(int userId) throws ClientException {
        try {
            credentials.remove(userId);
        } catch (Exception e) {
            throw new ClientException("Failed to reset TOTP for user " + userId + ": " + e.getMessage(), e);
        }
    }
}
