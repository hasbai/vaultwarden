// Reuse 北极小站. Append only this application's callback and permission.
import {execFileSync} from 'node:child_process';
import {mkdirSync,writeFileSync,existsSync} from 'node:fs';
const clientId='mdmD7xvX5yay52SRVZeuIOhGHIa0Wdl2';
const audience='https://financial.hasbai.xyz/api';
const permission='access:vaultwarden';
const apply=process.argv.includes('--apply');
function api(method,path,data) {
  try {return JSON.parse(execFileSync('auth0',['--no-input','api',method,path,...(data?['--data',JSON.stringify(data)]:[])],{encoding:'utf8',stdio:['ignore','pipe','pipe'],timeout:30000})||'{}');}
  catch {throw new Error(`Auth0 ${method} ${path} failed (credentials suppressed)`);}
}
const client=api('get',`clients/${clientId}`);
if(client.name!=='北极小站' || client.token_endpoint_auth_method!=='none' || !client.grant_types.includes('authorization_code')) throw new Error('Shared client has changed; review configuration');
const resource=api('get','resource-servers').find(r=>r.identifier===audience);
const admin=api('get','roles').find(r=>r.name==='superadmin');
if(!resource || !admin || resource.enforce_policies!==true || resource.token_dialect!=='access_token_authz') throw new Error('Existing RBAC configuration unavailable');
const grants=api('get',`roles/${admin.id}/permissions`);
const additions={callbacks:['https://bw.hasbai.xyz/identity/connect/oidc-signin','https://localhost:8787/identity/connect/oidc-signin'],web_origins:['https://bw.hasbai.xyz','https://localhost:8787'],allowed_logout_urls:['https://bw.hasbai.xyz','https://localhost:8787']};
const patch=Object.fromEntries(Object.entries(additions).map(([k,v])=>[k,[...new Set([...(client[k]??[]),...v])]]));
const scopes=[...(resource.scopes??[])];if(!scopes.some(s=>s.value===permission)) scopes.push({value:permission,description:'密码库：访问本人加密密码库'});
const grant={resource_server_identifier:audience,permission_name:permission};
const missing=!grants.some(g=>g.resource_server_identifier===audience && g.permission_name===permission);
mkdirSync('.secrets',{recursive:true,mode:0o700});
if(!existsSync('.secrets/auth0-before.json'))writeFileSync('.secrets/auth0-before.json',JSON.stringify({client:{client_id:clientId,...Object.fromEntries(Object.keys(patch).map(k=>[k,client[k]]))},resource:{id:resource.id,scopes:resource.scopes,allow_offline_access:resource.allow_offline_access},role:{id:admin.id,permissions:grants}},null,2),{mode:0o600});
if(apply){
 api('patch',`clients/${clientId}`,patch);
 api('patch',`resource-servers/${resource.id}`,{scopes,allow_offline_access:true});
 if(missing) api('post',`roles/${admin.id}/permissions`,{permissions:[grant]});
 const verifiedClient=api('get',`clients/${clientId}`);const verifiedResource=api('get',`resource-servers/${resource.id}`);const verifiedGrants=api('get',`roles/${admin.id}/permissions`);
 if(Object.entries(patch).some(([k,v])=>v.some(x=>!verifiedClient[k]?.includes(x))) || !verifiedResource.scopes.some(s=>s.value===permission) || !verifiedResource.allow_offline_access || !verifiedGrants.some(g=>g.resource_server_identifier===audience && g.permission_name===permission)) throw new Error('Auth0 configuration verification failed');
}
console.log(JSON.stringify({applied:apply,client:client.name,audience,permission,role:admin.name,callbacks:additions.callbacks,existingConfigurationPreserved:true}));
