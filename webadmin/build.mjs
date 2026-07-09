import { build } from 'esbuild';

// Compile the Settings-tab plugin (web/plugin.jsx -> web/plugin.js). The @oie/*
// packages stay external — the host resolves them at runtime to its single
// framework instance; React comes from platform.React.
await build({
    entryPoints: ['web/plugin.jsx'],
    outfile: 'web/plugin.js',
    bundle: true,
    format: 'esm',
    target: 'es2022',
    jsx: 'transform',
    jsxFactory: 'React.createElement',
    jsxFragment: 'React.Fragment',
    external: ['@oie/web-api', '@oie/web-ui', '@oie/web-shell'],
});
console.log('built web/plugin.js');
