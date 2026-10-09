// Exercise the browser-extension protocol through the real Web Vault and
// Auth0, capturing the connector message in place of an installed extension.
// This authenticates a test device but never initializes or changes vault keys.
import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {readFileSync} from 'node:fs';
import {randomBytes,createHash} from 'node:crypto';

const origin=process.env.VAULT_ORIGIN??'https://localhost:8787';
assert.ok(['https://localhost:8787','https://bw.hasbai.xyz'].includes(origin));
const discovery=await fetch(origin+'/api/organizations/domain/sso/verified',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:'sso-test@example.invalid'})});
assert.equal(discovery.status,200);
assert.deepEqual(await discovery.json(),{data:[],object:'list',continuationToken:null});
assert.equal((await fetch(origin+'/api/sync')).status,401);
const source=readFileSync(process.env.AUTH0_TEST_ENV_FILE??'/Users/yueshi/src/financial/.env','utf8');
const value=k=>source.match(new RegExp(`^${k}=(.*)$`,'m'))?.[1].trim().replace(/^['"]|['"]$/g,'');
const email=value('AUTH0_TEST_EMAIL'),password=value('AUTH0_TEST_PASSWORD');
assert.ok(email&&password,'Existing Auth0 test credentials required');
const verifier=randomBytes(48).toString('base64url');
const challenge=createHash('sha256').update(verifier).digest('base64url');
const state=randomBytes(32).toString('base64url')+':clientId=browser';
const redirect=origin+'/sso-connector.html';
process.env.PLAYWRIGHT_DISABLE_FORCED_CHROMIUM_PROXIED_LOOPBACK='1';
const browser=await chromium.launch({executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true,proxy:{server:'http://127.0.0.1:7890',bypass:'localhost,127.0.0.1,[::1]'},args:['--disable-quic']});
try {
  const page=await browser.newPage({ignoreHTTPSErrors:origin.includes('localhost')});
  const failures=[];
  let authorize;
  page.on('request',r=>{if(r.url().startsWith(origin+'/identity/connect/authorize?'))authorize=new URL(r.url());});
  page.on('response',r=>{if(r.url().startsWith(origin+'/api/')&&r.status()>=400)failures.push({path:new URL(r.url()).pathname,status:r.status()});});
  await page.addInitScript(()=>window.addEventListener('message',event=>{
    if(event.origin===location.origin&&event.data?.command==='authResult')window.ssoTestResult=event.data;
  }));
  await page.goto(origin+'/#/sso?'+new URLSearchParams({clientId:'browser',redirectUri:redirect,state,codeChallenge:challenge,email}),{waitUntil:'domcontentloaded'});
  await page.waitForURL('https://auth.hasbai.xyz/**',{timeout:45000});
  assert.ok(authorize,'Authorization request missing');
  assert.equal(authorize.searchParams.get('client_id'),'browser');
  assert.equal(authorize.searchParams.get('redirect_uri'),redirect);
  assert.equal(authorize.searchParams.get('code_challenge'),challenge);
  assert.equal(authorize.searchParams.get('state'),state+'_identifier=hasbai');
  const username=page.locator('input[name=username]');
  if(await username.count()) {
    await username.fill(email);
    if(!await page.locator('input[name=password]').count())await page.locator('button[type=submit]:visible:not([aria-hidden=true])').first().click();
  }
  await page.locator('input[name=password]').fill(password);
  await page.locator('button[type=submit]:visible:not([aria-hidden=true])').first().click();
  await page.waitForURL(url=>url.origin===origin||url.pathname==='/u/consent',{timeout:45000});
  if(new URL(page.url()).pathname==='/u/consent')await page.getByRole('button',{name:/接受|Accept/}).click();
  await page.waitForURL(origin+'/sso-connector.html?**',{timeout:45000});
  await page.waitForFunction(()=>window.ssoTestResult?.command==='authResult');
  const result=await page.evaluate(()=>window.ssoTestResult);
  assert.equal(result.state,state+'_identifier=hasbai');
  assert.ok(result.code);
  assert.equal(result.lastpass,false);
  assert.deepEqual(failures,[]);
  const exchange=()=>fetch(origin+'/identity/connect/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',client_id:'browser',redirect_uri:redirect,code:result.code,code_verifier:verifier,deviceIdentifier:crypto.randomUUID(),deviceName:'browser-sso-regression',deviceType:'2'})});
  const token=await exchange();assert.equal(token.status,200);
  const data=await token.json();assert.ok(data.access_token);
  assert.equal((await fetch(origin+'/api/accounts/profile',{headers:{Authorization:`Bearer ${data.access_token}`}})).status,200);
  assert.equal((await exchange()).status,400);
  console.log('Browser SSO protocol: automatic provider selection, preserved PKCE/state, real Auth0 callback, connector handoff, token exchange and replay rejection passed.');
} finally {await browser.close();}
