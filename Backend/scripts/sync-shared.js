// Copies Backend/shared/*.js into Frontend/src/shared so the API server and the in-browser Live preview use
// exactly the same rules. Run after editing anything in Backend/shared (a test fails if the copies differ).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const from = path.join(here, '..', 'shared');
const to = path.join(here, '..', '..', 'Frontend', 'src', 'shared');
fs.mkdirSync(to, { recursive: true });
for (const f of fs.readdirSync(from)) fs.copyFileSync(path.join(from, f), path.join(to, f));
console.log(`Synced ${fs.readdirSync(from).length} shared modules to ${path.relative(process.cwd(), to)}`);
