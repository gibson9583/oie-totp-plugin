/*
 * OIE TOTP MFA — multi-factor authentication plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.totp;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.Response;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.core.api.MirthApiException;
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
            ArrayNode arr = MAPPER.createArrayNode();
            for (TotpCredentialDao.Enrollment enrollment : credentials.listEnrollments()) {
                int id = enrollment.userId;
                User user = userController.getUser(id, null);
                if (user != null) {
                    ObjectNode row = MAPPER.createObjectNode();
                    row.put("id", id);
                    row.put("username", user.getUsername());
                    row.put("generation", enrollment.generation);
                    arr.add(row);
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
    public void reset(int userId, String generation) throws ClientException {
        if (userId <= 0 || generation == null || generation.isBlank() || generation.length() > 128) {
            throw new MirthApiException(Response.Status.BAD_REQUEST);
        }
        try {
            if (!credentials.remove(userId, generation)) {
                throw new MirthApiException(Response.Status.CONFLICT);
            }
        } catch (MirthApiException e) {
            throw e;
        } catch (Exception e) {
            throw new ClientException("Failed to reset TOTP for user " + userId + ": " + e.getMessage(), e);
        }
    }
}
