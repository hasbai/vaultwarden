import assert from 'node:assert/strict';import {randomBytes} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';import {execFile} from 'node:child_process';import {promisify} from 'node:util';
const run=promisify(execFile);const origin='https://localhost:8787';
const token=JSON.parse(readFileSync('.secrets/local-session.json','utf8')).access_token;
const profile=await (await fetch(origin+'/api/accounts/profile',{headers:{Authorization:`Bearer ${token}`}})).json();
assert.match(profile.id,/^[a-f0-9-]{36}$/);
const reset=async()=>{writeFileSync('.secrets/verifier-rate.sql',`DELETE FROM throttle WHERE key='vault-password:${profile.id}';`,{mode:0o600});await run('node',['node_modules/wrangler/bin/wrangler.js','d1','execute','vaultwarden','--local','--persist-to','test-results/d1-live','--file','.secrets/verifier-rate.sql']);};
await reset();
try{for(let i=0;i<11;i++){
 const r=await fetch(origin+'/api/accounts/verify-password',{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json','CF-Connecting-IP':`198.51.100.${i+1}`},body:JSON.stringify({masterPasswordHash:randomBytes(32).toString('base64')})});assert.equal(r.status,i<10?400:429);await r.text();
}console.log('Vault recheck account rate limit rejects attempts across different IPs.');}finally{await reset();}
