/*
 * OIE TOTP MFA — web administrator half.
 *
 * Adds a "Two-Factor Authentication" tab to Settings (registerSettingsPanel) that
 * lists users with a TOTP enrollment and lets an admin RESET one — clearing the
 * user's stored secret so their next login restarts the self-enroll flow (the
 * lost-device / device-change path). Talks to the plugin's own servlet:
 *
 *   GET  /extensions/totpmfa/enrolled     -> { users: [{ id, username }, ...] }
 *   POST /extensions/totpmfa/reset/{userId} -> 204
 *
 * Both are gated by the engine's USERS_MANAGE permission. The login flow itself
 * needs no web code (the web admin's built-in OTP handler renders enroll/verify);
 * this half is only the post-login admin surface.
 */

import { platform } from '@oie/web-shell';

const React = platform.React;
const api = platform.api;
const { h, toast, confirmDialog, taskButton } = platform.ui;
const EXT = '/extensions/totpmfa';

const notInstalled = (e) => e && (e.status === 404 || e.status === 501);

function TotpAdminPanel({ setTasks }) {
    const [users, setUsers] = React.useState([]);
    const [loading, setLoading] = React.useState(true);
    const [error, setError] = React.useState(null);

    const load = React.useCallback(async () => {
        setLoading(true);
        try {
            const res = await api.get(`${EXT}/enrolled`);
            // The engine's response unwrapping reduces {users:[...]} to the bare
            // array (single-key objects are unwrapped), so accept either shape.
            const raw = Array.isArray(res) ? res : (res && res.users);
            const list = api.asList(raw).filter((u) => u && u.id != null);
            list.sort((a, b) => String(a.username).localeCompare(String(b.username)));
            setUsers(list);
            setError(null);
        } catch (e) {
            setError(notInstalled(e)
                ? 'The TOTP MFA engine plugin is not installed on this engine.'
                : (e.message || 'Failed to load enrollments.'));
            setUsers([]);
        } finally {
            setLoading(false);
        }
    }, []);

    React.useEffect(() => {
        load();
        setTasks('Two-Factor Authentication Tasks', [
            taskButton('Refresh', 'refresh', () => load())
        ]);
    }, [load, setTasks]);

    const reset = async (user) => {
        const ok = await confirmDialog('Reset Two-Factor Authentication',
            `Remove the authenticator enrollment for "${user.username}"? They will be prompted to set up two-factor authentication again on their next login.`,
            { danger: true, okLabel: 'Reset' });
        if (!ok) return;
        try {
            await api.post(`${EXT}/reset/${encodeURIComponent(user.id)}`);
            toast(`Reset two-factor authentication for "${user.username}".`, 'success');
            load();
        } catch (e) {
            toast(e.message || 'Reset failed.', 'error');
        }
    };

    return (
        <div className="p-4" style={{ maxWidth: 640 }}>
            <div className="text-text-dim mb-3">
                Users enrolled in TOTP two-factor authentication. Resetting a user clears
                their authenticator secret, so their next login restarts enrollment — use it
                when someone loses or changes their device.
            </div>
            {loading ? (
                <div className="text-text-faint">Loading…</div>
            ) : error ? (
                <div style={{ color: 'var(--err)' }}>{error}</div>
            ) : users.length === 0 ? (
                <div className="text-text-faint">No users are currently enrolled.</div>
            ) : (
                <table className="dt" style={{ width: '100%' }}>
                    <thead><tr><th>User</th><th style={{ width: 120 }}></th></tr></thead>
                    <tbody>
                        {users.map((u) => (
                            <tr key={u.id}>
                                <td className="mono">{u.username}</td>
                                <td>
                                    <button className="btn btn-danger" onClick={() => reset(u)}>Reset</button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}
        </div>
    );
}

export function register(platform2) {
    platform2.registerSettingsPanel({
        label: 'Two-Factor Authentication',
        component: TotpAdminPanel
    });
}
