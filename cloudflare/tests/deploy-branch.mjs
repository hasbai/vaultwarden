import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {assertProductionBranch} from '../scripts/deploy-branch.mjs';

const cwd = mkdtempSync(join(tmpdir(), 'vaultwarden-deploy-'));
const git = (...args) => execFileSync('git', args, {
  cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
}).trim();
try {
  git('init', '--initial-branch=cloudflare');
  writeFileSync(join(cwd, 'fixture'), 'deployment source');
  git('add', 'fixture');
  git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-m', 'fixture');
  const sha = git('rev-parse', 'HEAD');
  const ci = {WORKERS_CI: '1', WORKERS_CI_BRANCH: 'cloudflare', WORKERS_CI_COMMIT_SHA: sha};
  assertProductionBranch(cwd, {});
  assertProductionBranch(cwd, ci);
  for (const env of [
    {WORKERS_CI: '1'},
    {...ci, WORKERS_CI_BRANCH: 'feature'},
    {...ci, WORKERS_CI_COMMIT_SHA: '0'.repeat(40)},
    {...ci, WORKERS_CI_COMMIT_SHA: undefined},
  ]) assert.throws(() => assertProductionBranch(cwd, env));

  git('switch', '-c', 'main');
  assert.throws(() => assertProductionBranch(cwd, {}));
  assert.throws(() => assertProductionBranch(cwd, ci));
  git('checkout', '--detach', sha);
  assertProductionBranch(cwd, ci);
  assert.throws(() => assertProductionBranch(cwd, {}));
  assert.throws(() => assertProductionBranch(cwd, {...ci, WORKERS_CI_BRANCH: 'main'}));
  assert.throws(() => assertProductionBranch(join(cwd, 'missing'), {}));
  console.log('Deployment guard: local branch, detached CI, missing and conflicting source checks passed.');
} finally {
  rmSync(cwd, {recursive: true, force: true});
}
