import {createRemoteJWKSet,jwtVerify} from 'jose';
const sets=new Map();
function config(raw) {
  const c=JSON.parse(raw);
  if(!/^[a-z0-9.-]+$/.test(c.domain) || !c.clientId || !c.audience || !c.organization || !c.permission) throw new Error('Auth0 configuration incomplete');
  return c;
}
function keys(c) {
  const issuer=`https://${c.domain}/`;
  if(!sets.has(issuer)) sets.set(issuer,createRemoteJWKSet(new URL('.well-known/jwks.json',issuer),{timeoutDuration:5000}));
  return sets.get(issuer);
}
async function access(token,c) {
  const {payload}=await jwtVerify(token,keys(c),{issuer:`https://${c.domain}/`,audience:c.audience,algorithms:['RS256'],requiredClaims:['sub','exp','iat'],clockTolerance:5});
  if(typeof payload.sub!=='string' || payload.sub.endsWith('@clients') || payload.org_id!==c.organization || payload.azp!==c.clientId || !Number.isInteger(payload.iat) || payload.iat>Date.now()/1000+5 || !Array.isArray(payload.permissions) || !payload.permissions.includes(c.permission)) throw new Error('Auth0 authorization denied');
  return payload;
}
export async function verifyAuth0(token,raw) { return JSON.stringify(await access(token,config(raw))); }
export async function exchangeAuth0(code,verifier,nonce,raw) {
  const c=config(raw);
  const r=await fetch(`https://${c.domain}/oauth/token`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({grant_type:'authorization_code',client_id:c.clientId,code,code_verifier:verifier,redirect_uri:c.callback}),signal:AbortSignal.timeout(15000)});
  if(!r.ok) throw new Error('Auth0 code exchange rejected');
  const t=await r.json(); const a=await access(t.access_token,c);
  const {payload:id}=await jwtVerify(t.id_token,keys(c),{issuer:`https://${c.domain}/`,audience:c.clientId,algorithms:['RS256'],requiredClaims:['sub','exp','iat','nonce']});
  if(id.nonce!==nonce || id.sub!==a.sub || id.org_id!==c.organization || id.email_verified!==true || typeof id.email!=='string') throw new Error('Auth0 identity rejected');
  return JSON.stringify({tokens:{access_token:t.access_token,refresh_token:t.refresh_token??null},claims:{...a,email:id.email.trim().toLowerCase(),email_verified:true,name:a.username||id.name||id.email}});
}
export async function refreshAuth0(refreshToken,raw) {
  const c=config(raw);
  const r=await fetch(`https://${c.domain}/oauth/token`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({grant_type:'refresh_token',client_id:c.clientId,refresh_token:refreshToken}),signal:AbortSignal.timeout(15000)});
  if(!r.ok) throw new Error('Auth0 refresh rejected');
  const t=await r.json();const claims=await access(t.access_token,c);
  return JSON.stringify({tokens:{access_token:t.access_token,refresh_token:t.refresh_token??refreshToken},claims});
}
