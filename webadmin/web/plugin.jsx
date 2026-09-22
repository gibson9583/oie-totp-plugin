/*
 * TOTP recovery settings. The engine enforces manageUsers for both endpoints.
 * Lists carry a credential generation; resets conditionally remove that exact
 * enrollment so a stale operator view cannot remove a replacement factor.
 */
import { platform } from '@oie/web-shell';
import { createEnrollmentController, initialEnrollmentState } from './enrollments.js';

const React = platform.React;
const api = platform.api;
const { toast, confirmDialog, taskButton } = platform.ui;
const TASK_GROUP = 'settings_Two-Factor Authentication';

function TotpAdminPanel({ setTasks }) {
    const [state, setState] = React.useState(initialEnrollmentState);
    const controller = React.useRef(null);
    const { users, loading, error, resettingId } = state;

    React.useEffect(() => {
        const current = createEnrollmentController({ api, confirmDialog, toast, onChange: setState });
        controller.current = current;
        current.load();
        setTasks('Two-Factor Authentication Tasks', [
            taskButton('Refresh', 'refresh', current.load, { group: TASK_GROUP, task: 'doRefresh' })
        ]);
        return () => current.dispose();
    }, [setTasks]);

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
                <div role="alert" style={{ color: 'var(--err)' }}>{error}</div>
            ) : users.length === 0 ? (
                <div className="text-text-faint">No users are currently enrolled.</div>
            ) : (
                <table className="dt" style={{ width: '100%' }}>
                    <thead><tr><th>User</th><th style={{ width: 120 }}></th></tr></thead>
                    <tbody>
                        {users.map((user) => (
                            <tr key={user.id}>
                                <td className="mono">{user.username}</td>
                                <td>
                                    {platform.checkTask(TASK_GROUP, 'doReset') && (
                                        <button type="button" className="btn btn-danger"
                                            disabled={resettingId !== null}
                                            onClick={() => {
                                                if (platform.checkTask(TASK_GROUP, 'doReset')) controller.current?.reset(user);
                                            }}>
                                            {resettingId === user.id ? 'Resetting…' : 'Reset'}
                                        </button>
                                    )}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}
        </div>
    );
}

export async function register(host) {
    // Match the OIDC panel's endpoint permission probe. Only an authoritative
    // denial hides the tab; other failures remain visible when it is opened.
    try {
        await api.get('/extensions/totpmfa/enrolled');
    } catch (error) {
        if (error?.status === 403) return;
    }
    host.registerSettingsPanel({ label: 'Two-Factor Authentication', component: TotpAdminPanel });
}
