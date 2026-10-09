import {execFileSync} from 'node:child_process';

export function assertProductionBranch(cwd, env = process.env) {
  const git = (...args) => execFileSync('git', args, {
    cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
  const branch = git('branch', '--show-current');
  if (branch && branch !== 'cloudflare') {
    throw new Error(`Production deployment requires cloudflare; checkout is ${branch}.`);
  }
  if (env.WORKERS_CI === '1' || env.WORKERS_CI_BRANCH !== undefined || env.WORKERS_CI_COMMIT_SHA !== undefined) {
    if (env.WORKERS_CI_BRANCH !== 'cloudflare' || env.WORKERS_CI_COMMIT_SHA !== git('rev-parse', 'HEAD')) {
      throw new Error('Workers Builds deployment requires branch cloudflare and a matching commit SHA.');
    }
  } else if (branch !== 'cloudflare') {
    throw new Error('Local production deployment requires an attached cloudflare checkout.');
  }
}
