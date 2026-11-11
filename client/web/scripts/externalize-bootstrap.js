import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

const dist = new URL('../dist/', import.meta.url);
const index = new URL('index.html', dist);
const html = await readFile(index, 'utf8');

// SvelteKit emits a classic inline bootstrap. Keep it in the same DOM position
// so hydration can use document.currentScript, and load it under Gate's CSP.
const [bootstrap, ...otherScripts] = html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g);
if (!bootstrap || otherScripts.length || !bootstrap[0].startsWith('<script>')) {
  throw new Error('Expected one inline SvelteKit bootstrap in dist/index.html');
}

const source = bootstrap[1];
const hash = createHash('sha256').update(source).digest('hex').slice(0, 16);
const asset = `_app/immutable/bootstrap.${hash}.js`;
await writeFile(new URL(asset, dist), source);
await writeFile(index, html.replace(bootstrap[0], `<script defer src="/${asset}"></script>`));
