/* Engine String returns are XStream-wrapped JSON text. The host normally
 * unwraps {string: ...}, while direct callers may still receive the envelope. */
export function decodeEnrollments(response) {
    let value = response;
    if (value && typeof value === 'object' && typeof value.string === 'string') {
        value = value.string;
    }
    if (typeof value === 'string') value = JSON.parse(value);
    const users = Array.isArray(value) ? value : value?.users;
    // Never turn an incompatible or corrupt response into an empty enrollment
    // list, or permit resets without the server's current credential generation.
    if (!Array.isArray(users) || users.some((user) => !user
        || !Number.isSafeInteger(user.id) || user.id <= 0
        || typeof user.username !== 'string' || !user.username
        || typeof user.generation !== 'string' || !user.generation)) {
        throw new Error('The engine returned an invalid enrollment list.');
    }
    return [...users].sort((a, b) => a.username.localeCompare(b.username));
}

export const initialEnrollmentState = {
    users: [], loading: true, error: null, resettingId: null
};

function loadError(error) {
    if (error?.status === 403) return 'You do not have permission to manage two-factor authentication.';
    if (error?.status === 404 || error?.status === 501) {
        return 'The TOTP MFA engine plugin is not installed on this engine.';
    }
    return error?.message || 'Failed to load enrollments.';
}

// Keep request ordering and action locks outside render-time state: two clicks
// in the same event turn must not open two dialogs or submit two reset requests.
export function createEnrollmentController({ api, confirmDialog, toast, onChange }) {
    const endpoint = '/extensions/totpmfa';
    let state = initialEnrollmentState;
    let alive = true;
    let sequence = 0;
    let mutating = false;
    const update = (patch) => {
        if (!alive) return;
        state = { ...state, ...patch };
        onChange(state);
    };

    async function load() {
        if (!alive || mutating) return;
        const request = ++sequence;
        update({ loading: true });
        try {
            const users = decodeEnrollments(await api.get(`${endpoint}/enrolled`));
            if (alive && request === sequence) update({ users, error: null, loading: false });
        } catch (error) {
            if (alive && request === sequence) {
                update({ users: [], error: loadError(error), loading: false });
            }
        }
    }

    async function reset(user) {
        if (!alive || state.resettingId !== null || !state.users.includes(user)) return;
        update({ resettingId: user.id });
        try {
            const confirmed = await confirmDialog('Reset Two-Factor Authentication',
                `Remove the authenticator enrollment for "${user.username}"? They will be prompted to set up two-factor authentication again on their next login.`,
                { danger: true, okLabel: 'Reset' });
            if (!alive || !confirmed) return;
            // A refresh while confirmation was open may have replaced the row.
            // Require confirmation against that new snapshot before proceeding.
            if (!state.users.includes(user)) {
                toast('The enrollment list changed. Review the current user and retry the reset.', 'warn');
                return;
            }
            mutating = true;
            ++sequence; // Discard reads begun before the mutation.
            try {
                await api.post(`${endpoint}/reset/${encodeURIComponent(user.id)}?generation=${encodeURIComponent(user.generation)}`);
                if (alive) toast(`Reset two-factor authentication for "${user.username}".`, 'success');
            } catch (error) {
                if (alive) toast(error?.status === 409
                    ? 'This enrollment changed. Review the refreshed list before resetting it.'
                    : (error?.message || 'Reset failed.'), 'error');
            } finally {
                mutating = false;
            }
            // Also refresh after a failed/ambiguous POST so retry uses current
            // enrollment state. A failed refresh remains visible in the panel.
            await load();
        } catch (error) {
            if (alive) toast(error?.message || 'Reset failed.', 'error');
        } finally {
            update({ resettingId: null });
        }
    }

    return { load, reset, dispose() { alive = false; ++sequence; } };
}
