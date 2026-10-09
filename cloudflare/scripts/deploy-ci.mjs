import {spawnSync} from 'node:child_process';
import {homedir} from 'node:os';
import {join, delimiter} from 'node:path';

// Cloudflare runs deploy in a new shell; retain the pinned build tool's PATH.
// Wrangler preserves existing runtime secrets. No keys or D1 data are recreated.
const result = spawnSync(process.execPath, [
  'node_modules/wrangler/bin/wrangler.js', 'deploy', ...process.argv.slice(2),
], {
  stdio: 'inherit',
  env: {
    ...process.env,
    RUSTUP_TOOLCHAIN: '1.95.0',
    PATH: `${join(process.env.CARGO_HOME || join(homedir(), '.cargo'), 'bin')}${delimiter}${process.env.PATH}`,
  },
});
if (result.error) throw result.error;
process.exit(result.status ?? 1);
