/* SPDX-License-Identifier: MPL-2.0 */
package org.openintegrationengine.plugins.totp;

import com.mirth.connect.client.core.Permissions;
import com.mirth.connect.client.core.api.servlets.ExtensionServletInterface;
import com.mirth.connect.model.ExtensionPermission;

/** Registers both custom and generic operations under the engine's user-management permission. */
final class TotpPermissions {
    private TotpPermissions() {}

    static ExtensionPermission[] permissions() {
        return new ExtensionPermission[] {
            new ExtensionPermission(TotpAdminServletInterface.PLUGIN_POINT, Permissions.USERS_MANAGE,
                "View and reset authenticator enrollments, and manage TOTP plugin properties.",
                new String[] {
                    "listTotpEnrolled", "resetTotpEnrollment",
                    ExtensionServletInterface.OPERATION_PLUGIN_PROPERTIES_GET,
                    ExtensionServletInterface.OPERATION_PLUGIN_PROPERTIES_SET
                },
                new String[] {
                    "settings_Two-Factor Authentication/doRefresh",
                    "settings_Two-Factor Authentication/doReset"
                })
        };
    }
}
