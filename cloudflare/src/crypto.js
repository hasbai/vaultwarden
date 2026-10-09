// WebCrypto bridge only. API routing and D1 access are implemented in Rust.
const enc = new TextEncoder();
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unb64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
const b64url = bytes => b64(bytes).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
const fromurl = value => unb64(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4));
export function randomId() { return crypto.randomUUID(); }
export function randomSecret() { return b64url(crypto.getRandomValues(new Uint8Array(48))); }
export function now() { return Date.now(); }
export function isoDate(ms) { return new Date(ms).toISOString(); }
export function nextDate(previous) {return new Date(Math.max(Date.now(),Date.parse(previous)+1)).toISOString();}
export async function digest(value) { return b64url(await crypto.subtle.digest('SHA-256', enc.encode(value))); }
export async function equal(a,b) {
  const [ah,bh] = await Promise.all([crypto.subtle.digest('SHA-256',enc.encode(a)),crypto.subtle.digest('SHA-256',enc.encode(b))]);
  return crypto.subtle.timingSafeEqual(ah,bh);
}
export async function passwordHash(clientHash, salt, userId, secret) {
  const bytes=unb64(clientHash);
  if(bytes.length!==32 || b64(bytes)!==clientHash || !userId || fromurl(secret).length!==32) throw new Error('Invalid verifier input');
  const key=await crypto.subtle.importKey('raw',fromurl(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const input=JSON.stringify(['vaultwarden-master-password-recheck','v1',userId,salt,clientHash]);
  return 'hmac-sha256:v1:'+b64url(await crypto.subtle.sign('HMAC',key,enc.encode(input)));
}
export async function signJwt(claims, jwk) {
  claims = JSON.parse(claims);
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)) throw new Error('Invalid claims');
  const key = await crypto.subtle.importKey('jwk', JSON.parse(jwk), {name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'}, false, ['sign']);
  const input = b64url(enc.encode(JSON.stringify({alg:'RS256',typ:'JWT'}))) + '.' + b64url(enc.encode(JSON.stringify(claims)));
  return input + '.' + b64url(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(input)));
}
export async function verifyJwt(token, jwk, issuer, purpose) {
  if (token.length > 8192) throw new Error('Invalid token');
  const parts = token.split('.');
  if(parts.length !== 3) throw new Error('Invalid token');
  const header = JSON.parse(new TextDecoder().decode(fromurl(parts[0])));
  if(header.alg !== 'RS256' || header.typ !== 'JWT') throw new Error('Invalid token');
  const source = JSON.parse(jwk);
  const key = await crypto.subtle.importKey('jwk', {kty:source.kty,n:source.n,e:source.e}, {name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'}, false, ['verify']);
  if(!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,fromurl(parts[2]),enc.encode(parts[0]+'.'+parts[1]))) throw new Error('Invalid token');
  const value = JSON.parse(new TextDecoder().decode(fromurl(parts[1])));
  const at = Date.now()/1000;
  if(value.iss !== issuer || value.purpose !== purpose || !Number.isFinite(value.exp) || value.exp <= at || !Number.isFinite(value.nbf) || value.nbf > at + 30) throw new Error('Invalid token');
  return JSON.stringify(value);
}
async function storageKey(raw) {
  return crypto.subtle.importKey('raw',fromurl(raw),'AES-GCM',false,['encrypt','decrypt']);
}
export async function seal(value,secret,context) {
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const encrypted=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:enc.encode(context)},await storageKey(secret),enc.encode(value));
  return b64url(iv)+'.'+b64url(encrypted);
}
export async function unseal(value,secret,context) {
  const [iv,encrypted]=value.split('.');
  return new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:fromurl(iv),additionalData:enc.encode(context)},await storageKey(secret),fromurl(encrypted)));
}
