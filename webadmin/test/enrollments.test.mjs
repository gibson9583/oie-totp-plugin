import test from 'node:test';
import assert from 'node:assert/strict';
import { createEnrollmentController, decodeEnrollments } from '../web/enrollments.js';

const alice = { id: 7, username: 'alice', generation: 'enrollment-a' };
const bob = { id: 8, username: 'bob', generation: 'enrollment-b' };
const deferred = () => {
    let resolve, reject;
    const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
    return { promise, resolve, reject };
};
function harness({ get = async () => ({ users: [alice] }), post = async () => {}, confirm = async () => true } = {}) {
    const states = [], toasts = [], posts = [], confirms = [];
    const controller = createEnrollmentController({
        api: { get, post: (...args) => { posts.push(args); return post(...args); } },
        confirmDialog: (...args) => { confirms.push(args); return confirm(...args); },
        toast: (...args) => toasts.push(args),
        onChange: (value) => states.push(value)
    });
    return { ...controller, states, toasts, posts, confirms, get state() { return states.at(-1); } };
}

for (const [name, response] of [
    ['actual engine String envelope', { string: JSON.stringify({ users: [bob, alice] }) }],
    ['host-unwrapped String', JSON.stringify({ users: [bob, alice] })],
    ['decoded object', { users: [bob, alice] }],
    ['host-unwrapped array', [bob, alice]]
]) {
    test(`decodes and sorts ${name}`, () => {
        assert.deepEqual(decodeEnrollments(response), [alice, bob]);
    });
}
test('accepts the exact engine empty-list envelope', () => {
    assert.deepEqual(decodeEnrollments({ string: '{"users":[]}' }), []);
});
for (const [name, response] of [
    ['invalid JSON', { string: '{broken' }],
    ['missing list', {}], ['null', null], ['wrong list type', { users: {} }],
    ['missing generation', { users: [{ id: 7, username: 'alice' }] }],
    ['invalid user ID', { users: [{ ...alice, id: '7' }] }],
    ['missing username', { users: [{ ...alice, username: '' }] }],
    ['mixed invalid row', { users: [alice, null] }]
]) {
    test(`rejects ${name} instead of displaying an empty/safe-looking list`, () => {
        assert.throws(() => decodeEnrollments(response));
    });
}
test('does not reorder caller-owned arrays', () => {
    const users = [bob, alice];
    decodeEnrollments(users);
    assert.deepEqual(users, [bob, alice]);
});

test('late initial GET cannot overwrite a newer refresh', async () => {
    const older = deferred(), newer = deferred();
    let calls = 0;
    const panel = harness({ get: () => (++calls === 1 ? older.promise : newer.promise) });
    const first = panel.load(), second = panel.load();
    newer.resolve({ string: '{"users":[]}' });
    await second;
    older.resolve({ users: [alice] });
    await first;
    assert.deepEqual(panel.state.users, []);
    assert.equal(panel.state.error, null);
    assert.equal(panel.state.loading, false);
});
test('late GET failure cannot overwrite a newer successful refresh', async () => {
    const older = deferred();
    let calls = 0;
    const panel = harness({ get: () => (++calls === 1 ? older.promise : { users: [alice] }) });
    const first = panel.load();
    await panel.load();
    older.reject(new Error('old failure'));
    await first;
    assert.deepEqual(panel.state.users, [alice]);
    assert.equal(panel.state.error, null);
});
test('successful reset sends the observed generation and reloads', async () => {
    let calls = 0;
    const panel = harness({ get: async () => ({ users: ++calls === 1 ? [alice] : [] }) });
    await panel.load();
    await panel.reset(alice);
    assert.deepEqual(panel.posts, [['/extensions/totpmfa/reset/7?generation=enrollment-a']]);
    assert.deepEqual(panel.state.users, []);
    assert.equal(panel.state.resettingId, null);
    assert.equal(panel.toasts[0][1], 'success');
});
test('duplicate clicks cannot open extra confirmations or submit another reset', async () => {
    const confirmation = deferred(), mutation = deferred();
    const panel = harness({ confirm: () => confirmation.promise, post: () => mutation.promise });
    await panel.load();
    const first = panel.reset(alice);
    await panel.reset(alice);
    assert.equal(panel.confirms.length, 1);
    assert.equal(panel.posts.length, 0);
    confirmation.resolve(true);
    await Promise.resolve();
    await panel.reset(alice);
    assert.equal(panel.posts.length, 1);
    mutation.resolve();
    await first;
    assert.equal(panel.state.resettingId, null);
});
test('cancelling confirmation changes no enrollment and releases action lock', async () => {
    const panel = harness({ confirm: async () => false });
    await panel.load();
    await panel.reset(alice);
    assert.equal(panel.posts.length, 0);
    assert.deepEqual(panel.state.users, [alice]);
    assert.equal(panel.state.resettingId, null);
    await panel.reset(alice);
    assert.equal(panel.confirms.length, 2);
});
test('refresh during confirmation prevents resetting a superseded row', async () => {
    const confirmation = deferred();
    let calls = 0;
    const replacement = { ...alice, generation: 'replacement' };
    const panel = harness({
        confirm: () => confirmation.promise,
        get: async () => ({ users: [++calls === 1 ? alice : replacement] })
    });
    await panel.load();
    const reset = panel.reset(alice);
    await panel.load();
    confirmation.resolve(true);
    await reset;
    assert.equal(panel.posts.length, 0);
    assert.deepEqual(panel.state.users, [replacement]);
    assert.equal(panel.toasts[0][1], 'warn');
});
test('stale rendered action cannot begin a confirmation', async () => {
    const panel = harness({ get: async () => ({ users: [] }) });
    await panel.load();
    await panel.reset(alice);
    assert.equal(panel.confirms.length, 0);
});
test('read begun before a reset cannot restore the removed enrollment', async () => {
    const oldRead = deferred();
    let calls = 0;
    const panel = harness({ get: () => {
        calls++;
        return calls === 1 ? { users: [alice] } : calls === 2 ? oldRead.promise : { users: [] };
    } });
    await panel.load();
    const old = panel.load();
    await panel.reset(alice);
    oldRead.resolve({ users: [alice] });
    await old;
    assert.deepEqual(panel.state.users, []);
});
test('refresh while POST is pending waits for the post-mutation load', async () => {
    const mutation = deferred();
    let calls = 0;
    const panel = harness({
        get: async () => ({ users: ++calls === 1 ? [alice] : [] }), post: () => mutation.promise
    });
    await panel.load();
    const reset = panel.reset(alice);
    await Promise.resolve();
    await panel.load();
    assert.equal(calls, 1);
    mutation.resolve();
    await reset;
    assert.equal(calls, 2);
    assert.deepEqual(panel.state.users, []);
});
for (const status of [403, 409, 500]) {
    test(`HTTP ${status} reset fails visibly and refreshes the generation before retry`, async () => {
        let calls = 0;
        const replacement = { ...alice, generation: 'replacement' };
        const panel = harness({
            get: async () => ({ users: [++calls === 1 ? alice : replacement] }),
            post: async () => { throw Object.assign(new Error('Reset unavailable'), { status }); }
        });
        await panel.load();
        await panel.reset(alice);
        assert.equal(panel.toasts.length, 1);
        assert.equal(panel.toasts[0][1], 'error');
        if (status === 409) assert.match(panel.toasts[0][0], /enrollment changed/);
        assert.deepEqual(panel.state.users, [replacement]);
        assert.equal(panel.state.resettingId, null);
    });
}
test('successful mutation followed by failed refresh preserves success and shows read failure', async () => {
    let calls = 0;
    const panel = harness({ get: async () => {
        if (++calls > 1) throw new Error('Refresh unavailable');
        return { users: [alice] };
    } });
    await panel.load();
    await panel.reset(alice);
    assert.equal(panel.toasts[0][1], 'success');
    assert.equal(panel.state.error, 'Refresh unavailable');
    assert.deepEqual(panel.state.users, []);
});
for (const [status, expected] of [[403, /permission/], [404, /not installed/], [501, /not installed/], [500, /unavailable/]]) {
    test(`HTTP ${status} list failure is explicit`, async () => {
        const panel = harness({ get: async () => { throw Object.assign(new Error('unavailable'), { status }); } });
        await panel.load();
        assert.match(panel.state.error, expected);
        assert.deepEqual(panel.state.users, []);
        assert.equal(panel.state.loading, false);
    });
}
test('malformed list response becomes a visible error', async () => {
    const panel = harness({ get: async () => ({ users: [{ id: 7, username: 'alice' }] }) });
    await panel.load();
    assert.match(panel.state.error, /invalid enrollment list/);
});
test('unmount while confirming cancels the unsent reset', async () => {
    const confirmation = deferred();
    const panel = harness({ confirm: () => confirmation.promise });
    await panel.load();
    const reset = panel.reset(alice);
    panel.dispose();
    const stateCount = panel.states.length;
    confirmation.resolve(true);
    await reset;
    assert.equal(panel.posts.length, 0);
    assert.equal(panel.states.length, stateCount);
});
test('unmount while loading discards the response', async () => {
    const read = deferred();
    const panel = harness({ get: () => read.promise });
    const load = panel.load();
    panel.dispose();
    const stateCount = panel.states.length;
    read.resolve({ users: [alice] });
    await load;
    assert.equal(panel.states.length, stateCount);
});
test('unmount after POST suppresses stale toasts, writes, and refreshes', async () => {
    const mutation = deferred();
    let calls = 0;
    const panel = harness({ get: async () => { calls++; return { users: [alice] }; }, post: () => mutation.promise });
    await panel.load();
    const reset = panel.reset(alice);
    await Promise.resolve();
    assert.equal(panel.posts.length, 1);
    panel.dispose();
    const stateCount = panel.states.length;
    mutation.resolve();
    await reset;
    assert.equal(panel.states.length, stateCount);
    assert.deepEqual(panel.toasts, []);
    assert.equal(calls, 1);
});
test('failed confirmation releases lock and reports failure', async () => {
    const panel = harness({ confirm: async () => { throw new Error('Dialog unavailable'); } });
    await panel.load();
    await panel.reset(alice);
    assert.equal(panel.posts.length, 0);
    assert.equal(panel.state.resettingId, null);
    assert.deepEqual(panel.toasts, [['Dialog unavailable', 'error']]);
});
