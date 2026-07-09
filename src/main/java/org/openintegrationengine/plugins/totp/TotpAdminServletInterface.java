/*
 * OIE TOTP MFA — multi-factor authentication plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.totp;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.core.Permissions;
import com.mirth.connect.client.core.api.BaseServletInterface;
import com.mirth.connect.client.core.api.MirthOperation;
import com.mirth.connect.client.core.api.Param;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * Admin surface for TOTP enrollments, reachable at /api/extensions/totpmfa.
 *
 * Managing another user's second factor is a user-administration action, so both
 * operations require the engine's existing {@link Permissions#USERS_MANAGE}
 * permission. Enrollments are keyed by the user's numeric id; the list is
 * cross-referenced with the current user set (orphaned rows from removed users are
 * dropped and pruned). Resetting a user clears their enrollment, so their next
 * login restarts the self-enroll flow.
 */
@Path("/extensions/totpmfa")
@Tag(name = "Extension Services")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public interface TotpAdminServletInterface extends BaseServletInterface {

    public static final String PLUGIN_POINT = "TOTP MFA";

    @GET
    @Path("/enrolled")
    @Operation(summary = "Lists the currently-existing users that have a TOTP enrollment ({ users: [{ id, username }] }).")
    @MirthOperation(name = "listTotpEnrolled", display = "List TOTP-enrolled users", permission = Permissions.USERS_MANAGE, auditable = false)
    public String listEnrolled() throws ClientException;

    @POST
    @Path("/reset/{userId}")
    @Operation(summary = "Removes a user's TOTP enrollment (by user id), so their next login re-enrolls them.")
    @MirthOperation(name = "resetTotpEnrollment", display = "Reset a user's TOTP enrollment", permission = Permissions.USERS_MANAGE)
    public void reset(@Param("userId") @PathParam("userId") int userId) throws ClientException;
}
