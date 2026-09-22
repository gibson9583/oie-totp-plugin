/* SPDX-License-Identifier: MPL-2.0 */
package org.openintegrationengine.plugins.totp;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import com.mirth.connect.client.core.Permissions;
import com.mirth.connect.client.core.api.MirthOperation;
import com.mirth.connect.model.ExtensionPermission;

class TotpPermissionsTest {
    @Test
    void allEndpointAndGenericPropertyOperationsRequireManageUsers() {
        Map<String, String> registered = new HashMap<>();
        for (ExtensionPermission p : new TotpAuthenticationPlugin().getExtensionPermissions()) {
            assertEquals(TotpAdminServletInterface.PLUGIN_POINT, p.getExtensionName());
            for (String op : p.getOperationNames()) {
                assertNull(registered.put(p.getExtensionName() + "#" + op, p.getDisplayName()));
            }
            assertTrue(Arrays.stream(p.getTaskNames()).allMatch(t -> t.startsWith("settings_Two-Factor Authentication/")));
        }
        for (var method : TotpAdminServletInterface.class.getDeclaredMethods()) {
            MirthOperation annotation = method.getAnnotation(MirthOperation.class);
            assertNotNull(annotation);
            assertEquals(annotation.permission(), registered.get("TOTP MFA#" + annotation.name()),
                "An endpoint annotation alone does not register an RBAC permission");
        }
        for (String op : Set.of("listTotpEnrolled", "resetTotpEnrollment", "getPluginProperties", "setPluginProperties")) {
            assertEquals(Permissions.USERS_MANAGE, registered.get("TOTP MFA#" + op));
            assertFalse(Set.of(Permissions.DASHBOARD_VIEW).contains(registered.get("TOTP MFA#" + op)));
        }
    }
}
