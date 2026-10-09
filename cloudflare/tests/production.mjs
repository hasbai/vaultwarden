import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {readFileSync,writeFileSync} from 'node:fs';
const origin='https://bw.hasbai.xyz';
for(const path of ['/','/api/alive','/api/config','/sso-connector.html']){
 const r=await fetch(origin+path,{redirect:'manual'});assert.equal(r.status,200,path);assert.equal(r.headers.get('X-Content-Type-Options'),'nosniff');
 if(path==='/api/config'){const d=await r.json();assert.equal(d.environment.identity,origin+'/identity');assert.equal(d.settings.disableUserRegistration,true);}
}
assert.equal((await fetch(origin+'/api/sync')).status,401);
assert.equal((await fetch(origin+'/identity/accounts/register/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})).status,403);
const source=readFileSync(process.env.AUTH0_TEST_ENV_FILE??'/Users/yueshi/src/financial/.env','utf8');
const value=k=>source.match(new RegExp(`^${k}=(.*)$`,'m'))?.[1].trim().replace(/^['"]|['"]$/g,'');
process.env.PLAYWRIGHT_DISABLE_FORCED_CHROMIUM_PROXIED_LOOPBACK='1';
const browser=await chromium.launch({executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true,proxy:{server:'http://127.0.0.1:7890',bypass:'localhost,127.0.0.1,[::1]'},args:['--disable-quic']});
let token;
try{
 const page=await browser.newPage({viewport:{width:1440,height:1000}});
 page.on('response',async r=>{if(r.url()===origin+'/identity/connect/token' && r.status()===200){token=await r.json();writeFileSync('.secrets/production-session.json',JSON.stringify(token),{mode:0o600});}});
 await page.goto(origin,{waitUntil:'networkidle'});
 await page.getByRole('button',{name:'使用北极小站登录'}).click();
 await page.waitForURL('https://auth.hasbai.xyz/**');
 await page.locator('input[name=username]').fill(value('AUTH0_TEST_EMAIL'));
 if(!await page.locator('input[name=password]').count())await page.locator('button[type=submit]:visible:not([aria-hidden=true])').first().click();
 await page.locator('input[name=password]').fill(value('AUTH0_TEST_PASSWORD'));await page.locator('button[type=submit]:visible:not([aria-hidden=true])').first().click();
 await page.waitForURL(url=>url.origin===origin || url.pathname==='/u/consent',{timeout:45000});
 if(new URL(page.url()).pathname==='/u/consent'){await page.getByRole('button',{name:/接受|Accept/}).click();}
 await page.waitForURL(/#\/set-initial-password/,{timeout:45000});
 await page.getByRole('button',{name:'初始化保险库',exact:true}).waitFor();
 assert.ok(token);assert.equal(token.UserDecryptionOptions.HasMasterPassword,false);
 const r=await fetch(origin+'/api/sync',{headers:{Authorization:`Bearer ${token.access_token}`}});assert.equal(r.status,200);
 const data=await r.json();assert.equal(data.profile.key,'');assert.deepEqual(data.ciphers,[]);assert.deepEqual(data.folders,[]);
 await page.screenshot({path:'test-results/production-sso.png',fullPage:true});
 writeFileSync('test-results/production-acceptance.json',JSON.stringify({origin,passed:true,checks:['HTTPS/assets/D1 health','registration denied','anonymous sync denied','real Auth0 RBAC SSO','encrypted vault uninitialized'],masterPasswordSet:false},null,2)+'\n');
 console.log('Production HTTPS/D1/Auth0 RBAC SSO passed; master password remains unset for user initialization.');
}finally{await browser.close();}
