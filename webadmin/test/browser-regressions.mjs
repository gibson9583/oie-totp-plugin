/* Optional integration run against the existing web administrator checkout:
 * OIE_WEB_CLIENT_HOME=/path/to/oie-web-client npm run test:browser
 * Reuses its React/Playwright tooling; adds no dependencies to this plugin. */
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createServer } from 'node:http';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

if (!process.env.OIE_WEB_CLIENT_HOME) throw new Error('Set OIE_WEB_CLIENT_HOME to the web administrator checkout.');
const client = path.resolve(process.env.OIE_WEB_CLIENT_HOME);
const dir = path.dirname(fileURLToPath(import.meta.url));
const req = createRequire(path.join(client, 'package.json'));
const { chromium, expect } = req('@playwright/test');
const { build } = req('esbuild');
const api = path.join(client, 'web-administrator/client/core/api.ts');
const plugin = path.resolve(dir, '../web/plugin.jsx');
const fixture = [{ id: 7, username: 'alice', generation: 'enrollment-a' }];
const results = [];
const out = await build({
    stdin: { contents: `import React from 'react'; import {createRoot} from 'react-dom/client'; import {register} from ${JSON.stringify(plugin)}; import {platform} from '@oie/web-shell'; (async()=>{await register(platform); if(!platform.panel){window.registrationDone=true;return;} const r=createRoot(document.querySelector('#app')); r.render(React.createElement(React.StrictMode,null,React.createElement(platform.panel.component,{setTasks:(_,tasks)=>{window.tasks=tasks;}}))); window.unmount=()=>r.unmount(); window.registrationDone=true;})();`, resolveDir: client },
    bundle: true, format: 'iife', target: 'es2022', write: false,
    alias: { react: req.resolve('react'), 'react-dom/client': req.resolve('react-dom/client') },
    plugins: [{ name: 'test-platform', setup(b) {
        b.onResolve({ filter: /^@oie\/web-shell$/ }, () => ({ path: 'platform', namespace: 'test' }));
        b.onLoad({ filter: /.*/, namespace: 'test' }, () => ({
            contents: `import React from 'react'; import * as api from ${JSON.stringify(api)}; export const platform={React,api,checkTask:()=>!window.denyReset,ui:{toast:(message,level)=>(window.toasts??=[]).push({message,level}),confirmDialog:async()=>{window.confirmations=(window.confirmations||0)+1;return window.confirmResult!==false;},taskButton:(label,icon,onClick)=>({label,onClick})},registerSettingsPanel(p){platform.panel=p;window.panelRegistered=true;}};`, resolveDir: client
        }));
    }}]
});
const bundle = out.outputFiles[0].text;
const server = createServer((request, response) => {
    response.setHeader('Content-Type', request.url === '/app.js' ? 'text/javascript' : 'text/html');
    response.end(request.url === '/app.js' ? bundle : '<!doctype html><div id="app"></div><script src="/app.js"></script>');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
const respond = (route, body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: typeof body === 'string' ? body : JSON.stringify(body) });
const wire = (users = fixture) => ({ string: JSON.stringify({ users }) });
try {
    browser = await chromium.launch({ headless: true });
    async function check(name, run) {
        const context = await browser.newContext();
        const page = await context.newPage();
        page.setDefaultTimeout(5000);
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        try { await run(page); assert.deepEqual(errors, []); results.push({ name, result: 'PASS' }); }
        catch (error) { results.push({ name, result: 'FAIL', error: error.stack }); throw error; }
        finally { await context.close(); }
    }
    const goto = page => page.goto(`http://127.0.0.1:${server.address().port}/`);
    const enrollments = '**/api/extensions/totpmfa/enrolled';
    const resetRoute = '**/api/extensions/totpmfa/reset/7?generation=enrollment-a';
    await check('Actual host API renders the engine String envelope in React StrictMode', async page => {
        await page.route(enrollments, route => respond(route, wire()));
        await goto(page);
        await expect(page.getByText('alice', { exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Reset', exact: true })).toBeEnabled();
    });
    await check('403 during registration hides the settings panel', async page => {
        await page.route(enrollments, route => respond(route, 'Missing permission', 403));
        await goto(page);
        await expect.poll(() => page.evaluate(() => window.registrationDone)).toBe(true);
        assert.equal(await page.evaluate(() => !!window.panelRegistered), false);
    });
    await check('404 keeps a visible installation error', async page => {
        await page.route(enrollments, route => respond(route, {}, 404));
        await goto(page);
        await expect(page.getByText('The TOTP MFA engine plugin is not installed on this engine.')).toBeVisible();
    });
    await check('Malformed response displays an error and no reset control', async page => {
        await page.route(enrollments, route => respond(route, { string: '{"users":[{"id":7,"username":"alice"}]}' }));
        await goto(page);
        await expect(page.getByRole('alert')).toContainText('invalid enrollment list');
        await expect(page.getByRole('button', { name: 'Reset', exact: true })).toHaveCount(0);
    });
    await check('Render-time reset permission denial hides reset control', async page => {
        await page.addInitScript(() => window.denyReset = true);
        await page.route(enrollments, route => respond(route, wire()));
        await goto(page);
        await expect(page.getByText('alice', { exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Reset', exact: true })).toHaveCount(0);
    });
    await check('Action-time permission denial prevents stale rendered reset', async page => {
        await page.route(enrollments, route => respond(route, wire()));
        await goto(page);
        await expect(page.getByText('alice', { exact: true })).toBeVisible();
        await page.evaluate(() => window.denyReset = true);
        await page.getByRole('button', { name: 'Reset', exact: true }).click();
        assert.equal(await page.evaluate(() => window.confirmations || 0), 0);
    });
    await check('Reset carries the observed generation and refreshes the list', async page => {
        let removed = false, posts = 0;
        await page.route(enrollments, route => respond(route, wire(removed ? [] : fixture)));
        await page.route(resetRoute, route => { removed = true; posts++; return respond(route, '', 204); });
        await goto(page);
        await page.getByRole('button', { name: 'Reset', exact: true }).click();
        await expect(page.getByText('No users are currently enrolled.')).toBeVisible();
        assert.equal(posts, 1);
        assert.equal(await page.evaluate(() => window.toasts.at(-1).level), 'success');
    });
    await check('Cancelled reset sends no mutation', async page => {
        let posts = 0;
        await page.addInitScript(() => window.confirmResult = false);
        await page.route(enrollments, route => respond(route, wire()));
        await page.route(resetRoute, route => { posts++; return respond(route, '', 204); });
        await goto(page);
        await page.getByRole('button', { name: 'Reset', exact: true }).click();
        await expect(page.getByRole('button', { name: 'Reset', exact: true })).toBeEnabled();
        assert.equal(posts, 0);
    });
    await check('409 reset reports stale enrollment and refreshes the current row', async page => {
        let stale = false;
        await page.route(enrollments, route => respond(route, wire(stale ? [{ ...fixture[0], generation: 'replacement' }] : fixture)));
        await page.route(resetRoute, route => { stale = true; return respond(route, 'Enrollment changed', 409); });
        await goto(page);
        await page.getByRole('button', { name: 'Reset', exact: true }).click();
        await expect.poll(() => page.evaluate(() => window.toasts?.at(-1)?.message)).toBe('This enrollment changed. Review the refreshed list before resetting it.');
        await expect(page.getByText('alice', { exact: true })).toBeVisible();
    });
    await check('Successful reset followed by failed refresh preserves success and exposes read failure', async page => {
        let removed = false;
        await page.route(enrollments, route => removed ? respond(route, 'refresh failed', 500) : respond(route, wire()));
        await page.route(resetRoute, route => { removed = true; return respond(route, '', 204); });
        await goto(page);
        await page.getByRole('button', { name: 'Reset', exact: true }).click();
        await expect(page.getByRole('alert')).toHaveText('refresh failed');
        assert.equal(await page.evaluate(() => window.toasts.at(-1).level), 'success');
    });
    await check('Same-turn duplicate clicks yield one confirmation and one POST', async page => {
        const posts = [];
        await page.route(enrollments, route => respond(route, wire()));
        await page.route(resetRoute, route => posts.push(route));
        await goto(page);
        await expect(page.getByRole('button', { name: 'Reset', exact: true })).toBeVisible();
        await page.evaluate(() => { const button = document.querySelector('button'); button.click(); button.click(); });
        await expect.poll(() => posts.length).toBe(1);
        await expect(page.getByRole('button', { name: 'Resetting…', exact: true })).toBeDisabled();
        assert.equal(await page.evaluate(() => window.confirmations), 1);
        await respond(posts[0], '', 204);
    });
    await check('Late refresh cannot restore enrollment after newer response', async page => {
        let delayed, oldRead = false, empty = false;
        await page.route(enrollments, route => {
            if (oldRead) { oldRead = false; delayed = route; return; }
            return respond(route, wire(empty ? [] : fixture));
        });
        await goto(page);
        await expect(page.getByText('alice', { exact: true })).toBeVisible();
        oldRead = true;
        await page.evaluate(() => { window.tasks[0].onClick(); });
        await expect.poll(() => !!delayed).toBe(true);
        empty = true;
        await page.evaluate(() => window.tasks[0].onClick());
        await expect(page.getByText('No users are currently enrolled.')).toBeVisible();
        await respond(delayed, wire());
        await page.evaluate(() => new Promise(resolve => setTimeout(resolve, 30)));
        await expect(page.getByText('No users are currently enrolled.')).toBeVisible();
    });
} finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
    if (process.env.TOTP_BROWSER_RESULTS) await writeFile(process.env.TOTP_BROWSER_RESULTS, JSON.stringify(results, null, 2) + '\n');
    console.log(JSON.stringify(results, null, 2));
}
