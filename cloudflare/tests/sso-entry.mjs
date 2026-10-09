import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
const script=readFileSync(new URL('../web-vault-sso.js',import.meta.url),'utf8');
const initial=new URLSearchParams({clientId:'browser',redirectUri:'https://vault.test/sso-connector.html',state:'test:clientId=browser',codeChallenge:'a'.repeat(43),email:'user+test@example.test',custom:'keep & this? too'});
function rewrite(params) {
  const hash='/sso?'+params;
  let changed;
  runInNewContext(script,{
    URLSearchParams,
    location:{hash:'#'+hash,pathname:'/',search:''},
    history:{replaceState:(_state,_title,url)=>{changed=url;}},
    document:{addEventListener(){},documentElement:{}},
    MutationObserver:class {observe(){}},
  });
  return changed;
}
const selected=new URL('https://vault.test'+rewrite(initial));
const params=new URLSearchParams(selected.hash.split('?')[1]);
assert.equal(params.get('identifier'),'hasbai');
for(const [key,value] of initial)assert.equal(params.get(key),value);
for(const [key,value] of [['identifier','other'],['code','callback-code'],['error','access_denied'],['error_description','cancelled']]) {
  const callback=new URLSearchParams(initial);callback.set(key,value);
  assert.equal(rewrite(callback),undefined,`Do not rewrite ${key}`);
}
for(const key of ['clientId','redirectUri','state','codeChallenge']) {
  const incomplete=new URLSearchParams(initial);incomplete.delete(key);
  assert.equal(rewrite(incomplete),undefined,`Do not rewrite incomplete ${key}`);
}
console.log('External SSO entry: callback/error guards and all external-client parameters preserved.');
