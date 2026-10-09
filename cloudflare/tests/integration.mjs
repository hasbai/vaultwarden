import assert from 'node:assert/strict';
import {randomBytes,pbkdf2Sync,createCipheriv,createDecipheriv,createHmac} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const execute=promisify(execFile);
const origin='https://localhost:8787';
const vault=JSON.parse(readFileSync('.secrets/local-vault.json','utf8'));
const first={data:JSON.parse(readFileSync('.secrets/local-session.json','utf8'))};
let token=first.data.access_token;
async function api(path,{method='GET',body,auth=true,headers={}}={}){
 const r=await fetch(origin+path,{method,headers:{...(body?{'Content-Type':'application/json'}:{}),...(auth&&token?{Authorization:`Bearer ${token}`} :{}),...headers},body:body?JSON.stringify(body):undefined});
 let data;const raw=await r.text();try{data=JSON.parse(raw);}catch{data=raw;}return {status:r.status,data};
}
async function ok(path,opts){const r=await api(path,opts);assert.ok(r.status<300,`${path}: ${r.status} ${JSON.stringify(r.data)}`);return r.data;}
const profile=await ok('/api/accounts/profile');
assert.equal(profile.emailVerified,true);
const password=vault.password;
const derive=pass=>{
 const master=pbkdf2Sync(pass,profile.email,600000,32,'sha256');
 return {hash:pbkdf2Sync(master,pass,1,32,'sha256').toString('base64'),key:Buffer.concat([createHmac('sha256',master).update(Buffer.from('enc\x01')).digest(),createHmac('sha256',master).update(Buffer.from('mac\x01')).digest()])};
};
const current=derive(password);const passwordHash=current.hash;
const decrypt=(value,key)=>{const [iv,data,mac]=value.slice(2).split('|').map(s=>Buffer.from(s,'base64'));assert.deepEqual(createHmac('sha256',key.subarray(32)).update(Buffer.concat([iv,data])).digest(),mac);const d=createDecipheriv('aes-256-cbc',key.subarray(0,32),iv);return Buffer.concat([d.update(data),d.final()]);};
const userKey=decrypt(profile.key,current.key);
function encrypt(raw,key=userKey){const iv=randomBytes(16);const c=createCipheriv('aes-256-cbc',key.subarray(0,32),iv);const data=Buffer.concat([c.update(raw),c.final()]);const mac=createHmac('sha256',key.subarray(32)).update(Buffer.concat([iv,data])).digest();return `2.${iv.toString('base64')}|${data.toString('base64')}|${mac.toString('base64')}`;}
console.log('Checking Auth0-only identity and one-time vault initialization');
assert.equal((await api('/identity/accounts/register/finish',{method:'POST',body:{email:profile.email},auth:false})).status,403);
const local=await fetch(origin+'/identity/connect/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'password',username:profile.email,password:passwordHash})});assert.equal(local.status,400);
assert.equal((await api('/api/accounts/profile',{method:'POST',body:{name:'forbidden'}})).status,403);
assert.equal((await api('/api/accounts/set-password',{method:'POST',body:{}})).status,409);
assert.equal((await api('/api/sync',{headers:{Authorization:'Bearer forged'}})).status,401);
await ok('/api/accounts/verify-password',{method:'POST',body:{masterPasswordHash:passwordHash}});
const prelogin=await ok('/identity/accounts/prelogin/password',{method:'POST',body:{email:profile.email}});assert.equal(prelogin.kdfSettings.iterations,600000);
const revision=await ok('/api/accounts/revision-date');
console.log('Checking encrypted payload, optimistic concurrency, folders and trash');
const dir=await ok('/api/folders',{method:'POST',body:{name:encrypt(Buffer.from('Test folder'))}});
const input={type:1,name:encrypt(Buffer.from('Test item')),login:{username:encrypt(Buffer.from('person')),password:encrypt(Buffer.from('secret'))},folderId:dir.id,encryptedFor:profile.id,favorite:true,customExtension:{future:'preserve'}};
const item=await ok('/api/ciphers',{method:'POST',body:input});
assert.ok(await ok('/api/accounts/revision-date')>revision);
assert.deepEqual((await ok(`/api/ciphers/${item.id}`)).customExtension,input.customExtension);
assert.equal((await api('/api/ciphers',{method:'POST',body:{...input,folderId:crypto.randomUUID()}})).status,404);
assert.equal((await api('/api/ciphers',{method:'POST',body:{...input,organizationId:crypto.randomUUID()}})).status,400);
const race=await Promise.all([api(`/api/ciphers/${item.id}`,{method:'PUT',body:{...input,notes:encrypt(Buffer.from('a')),lastKnownRevisionDate:item.revisionDate}}),api(`/api/ciphers/${item.id}`,{method:'PUT',body:{...input,notes:encrypt(Buffer.from('b')),lastKnownRevisionDate:item.revisionDate}})]);assert.deepEqual(race.map(r=>r.status).sort(),[200,409]);
await ok(`/api/ciphers/${item.id}/delete`,{method:'PUT'});assert.ok((await ok(`/api/ciphers/${item.id}`)).deletedDate);
assert.equal((await ok(`/api/ciphers/${item.id}/restore`,{method:'PUT'})).id,item.id);assert.equal((await ok(`/api/ciphers/${item.id}`)).deletedDate,null);
await ok(`/api/folders/${dir.id}`,{method:'DELETE'});assert.equal((await ok(`/api/ciphers/${item.id}`)).folderId,null);
const archived=await ok('/api/ciphers/archive',{method:'PUT',body:{ids:[item.id]}});assert.equal(archived.data[0].id,item.id);assert.ok(archived.data[0].archivedDate);
assert.equal((await ok(`/api/ciphers/${item.id}/unarchive`,{method:'PUT'})).archivedDate,null);
const permanent=await ok('/api/ciphers',{method:'POST',body:{...input,folderId:null}});await ok(`/api/ciphers/${permanent.id}/delete`,{method:'POST'});assert.equal((await api(`/api/ciphers/${permanent.id}`)).status,404);
const concurrent=await ok(`/api/ciphers/${item.id}`);const partialRace=await Promise.all([api(`/api/ciphers/${item.id}/partial`,{method:'PUT',body:{folderId:null,favorite:false}}),api(`/api/ciphers/${item.id}`,{method:'PUT',body:{...concurrent,notes:encrypt(Buffer.from('preserved concurrent password')),lastKnownRevisionDate:concurrent.revisionDate}})]);assert.ok(partialRace.some(r=>r.status===200));assert.ok(partialRace.every(r=>r.status===200||r.status===409));
console.log('Checking access to a second subject vault with the same identity email');
const otherUser=crypto.randomUUID(),otherFolder=crypto.randomUUID(),otherCipher=crypto.randomUUID();
const sqlQuote=v=>"'"+String(v).replaceAll("'","''")+"'";
const localSql=async sql=>{writeFileSync('.secrets/isolation.sql',sql,{mode:0o600});await execute('node',['node_modules/wrangler/bin/wrangler.js','d1','execute','vaultwarden','--local','--persist-to','test-results/d1-live','--file','.secrets/isolation.sql'],{stdio:['ignore','pipe','pipe']});};
try {
 await localSql(`INSERT INTO users(id,auth0_sub,email,kdf_salt,name,kdf,iterations,stamp,created,revision) VALUES(${sqlQuote(otherUser)},'auth0|isolated-fixture',${sqlQuote(profile.email)},'other-salt','Fixture',0,600000,'other-stamp','2026-10-09T00:00:00.000Z',1); INSERT INTO folders(id,user_id,name,revision) VALUES(${sqlQuote(otherFolder)},${sqlQuote(otherUser)},${sqlQuote(input.name)},'2026-10-09T00:00:00.000Z'); INSERT INTO ciphers(id,user_id,folder_id,payload,created,revision) VALUES(${sqlQuote(otherCipher)},${sqlQuote(otherUser)},${sqlQuote(otherFolder)},${sqlQuote(JSON.stringify({...input,encryptedFor:otherUser,folderId:otherFolder}))},'2026-10-09T00:00:00.000Z','2026-10-09T00:00:00.000Z');`);
 assert.equal((await api(`/api/ciphers/${otherCipher}`)).status,404);
 assert.equal((await api(`/api/ciphers/${otherCipher}`,{method:'PUT',body:input})).status,404);
 assert.equal((await api(`/api/folders/${otherFolder}`)).status,404);
 assert.equal((await api('/api/ciphers',{method:'POST',body:{...input,folderId:otherFolder}})).status,404);
 assert.equal((await api('/api/ciphers/delete',{method:'PUT',body:{ids:[item.id,otherCipher]}})).status,409);
 assert.equal((await ok(`/api/ciphers/${item.id}`)).deletedDate,null);
 assert.ok(!(await ok('/api/sync')).ciphers.some(c=>c.id===otherCipher));
 assert.equal((await api('/api/ciphers/import',{method:'POST',body:{folders:[],ciphers:[{...input,folderId:otherFolder}],folderRelationships:[]}})).status,400);
} finally {await localSql(`DELETE FROM ciphers WHERE user_id=${sqlQuote(otherUser)}; DELETE FROM folders WHERE user_id=${sqlQuote(otherUser)}; DELETE FROM users WHERE id=${sqlQuote(otherUser)};`);}
console.log('Checking invalid imports roll back and oversized imports write nothing');
const before=(await ok('/api/sync')).ciphers.length;
assert.equal((await api('/api/ciphers/import',{method:'POST',body:{folders:[],ciphers:[input,{...input,type:100}],folderRelationships:[]}})).status,400);
assert.equal((await ok('/api/sync')).ciphers.length,before);
assert.equal((await api('/api/ciphers/import',{method:'POST',body:{folders:[],ciphers:Array(10001).fill({...input,folderId:null}),folderRelationships:[]}})).status,413);
await ok('/api/ciphers/import',{method:'POST',body:{folders:[{name:encrypt(Buffer.from('Imported folder'))}],ciphers:[{...input,folderId:null}],folderRelationships:[{key:0,value:0}]}});
assert.equal((await ok('/api/sync')).ciphers.length,before+1);
console.log('Checking refresh competition, wrong-client recovery, master-password changes and revocation');
async function refresh(refreshToken,client='web'){
 const r=await fetch(origin+'/identity/connect/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'refresh_token',client_id:client,refresh_token:refreshToken})});return {status:r.status,data:await r.json()};
}
assert.equal((await refresh(first.data.refresh_token,'cli')).status,400);
const raceRefresh=await Promise.all([refresh(first.data.refresh_token),refresh(first.data.refresh_token)]);assert.deepEqual(raceRefresh.map(r=>r.status).sort(),[200,400]);
const refreshed=raceRefresh.find(r=>r.status===200).data;token=refreshed.access_token;
const claims=JSON.parse(Buffer.from(token.split('.')[1],'base64url').toString());assert.equal(claims.auth0,undefined);
const nextPassword=randomBytes(32).toString('base64url');const next=derive(nextPassword);
await ok('/api/accounts/password',{method:'POST',body:{masterPasswordHash:passwordHash,authenticationData:{salt:profile.email,kdf:{kdfType:0,iterations:600000,memory:null,parallelism:null},masterPasswordAuthenticationHash:next.hash},unlockData:{salt:profile.email,kdf:{kdfType:0,iterations:600000,memory:null,parallelism:null},masterKeyWrappedUserKey:encrypt(userKey,next.key)}}});
assert.equal((await api('/api/sync')).status,401);assert.equal((await refresh(refreshed.refresh_token)).status,400);
writeFileSync('.secrets/local-vault.json',JSON.stringify({...vault,password:nextPassword}),{mode:0o600});
writeFileSync('test-results/local-acceptance.json',JSON.stringify({passed:true,checks:['Auth0-only login','current SSO payload','initialization one-time','encrypted payload roundtrip','optimistic concurrency','folder removal','trash restore','atomic import','refresh competition','wrong client recovery','current master-password change','session revocation']},null,2)+'\n');
console.log('Local D1 acceptance passed. New master password saved only for the isolated local test vault.');
