import {chromium} from 'playwright';
import {readFileSync,writeFileSync,mkdirSync,existsSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
const origin='https://localhost:8787';
if(process.env.VAULT_ORIGIN && process.env.VAULT_ORIGIN!==origin)throw new Error('Use production.mjs for read-only production SSO validation');
const namespace='local';
const source=readFileSync(process.env.AUTH0_TEST_ENV_FILE??'/Users/yueshi/src/financial/.env','utf8');
const envValue=name=>source.match(new RegExp(`^${name}=(.*)$`,'m'))?.[1].trim().replace(/^['"]|['"]$/g,'');
const email=envValue('AUTH0_TEST_EMAIL');const password=envValue('AUTH0_TEST_PASSWORD');
if(!email || !password) throw new Error('Existing local Auth0 test credentials unavailable');
mkdirSync('.secrets',{recursive:true});mkdirSync('test-results',{recursive:true});
const vault=existsSync(`.secrets/${namespace}-vault.json`)?JSON.parse(readFileSync(`.secrets/${namespace}-vault.json`,'utf8')):{email,password:randomBytes(32).toString('base64url')};
writeFileSync(`.secrets/${namespace}-vault.json`,JSON.stringify(vault),{mode:0o600});
process.env.PLAYWRIGHT_DISABLE_FORCED_CHROMIUM_PROXIED_LOOPBACK='1';
const browser=await chromium.launch({executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true,proxy:{server:'http://127.0.0.1:7890',bypass:'localhost,127.0.0.1,[::1]'},args:['--disable-quic']});
const page=await browser.newPage({ignoreHTTPSErrors:true,viewport:{width:1440,height:1000}});page.setDefaultTimeout(30000);
const apiFailures=[];let tokenResponse;
page.on('response',async r=>{
 if(r.url().startsWith(origin+'/identity/connect/token') && r.status()===200){try{tokenResponse=await r.json();writeFileSync(`.secrets/${namespace}-session.json`,JSON.stringify(tokenResponse),{mode:0o600});}catch{}}
 if(r.url().startsWith(origin+'/api/') && r.status()>=400)apiFailures.push({path:new URL(r.url()).pathname,status:r.status()});
});
page.on('pageerror',e=>console.log('Web Vault client error:',e.message.slice(0,250)));
try{
 await page.goto(origin,{waitUntil:'networkidle'});
 await page.getByRole('button',{name:'使用北极小站登录'}).click();
 await page.waitForURL('https://auth.hasbai.xyz/**',{timeout:30000});
 const username=page.locator('input[name=username]');
 if(await username.count()){await username.fill(email);if(!await page.locator('input[name=password]').count()) await page.locator('button[type=submit]:visible:not([aria-hidden=true])').first().click();}
 await page.locator('input[name=password]').fill(password);await page.locator('button[type=submit]:visible:not([aria-hidden=true])').first().click();
 await page.waitForURL(url=>url.origin===origin || url.pathname==='/u/consent',{timeout:45000});
 if(new URL(page.url()).pathname==='/u/consent'){await page.getByRole('button',{name:/接受|Accept/}).click();await page.waitForURL(url=>url.origin===origin,{timeout:45000});}
 await page.waitForURL(/#\/(set-initial-password|lock|vault|tabs)/,{timeout:45000});
 if(page.url().includes('set-initial-password')){
  const fields=page.locator('input[type=password]');await fields.nth(0).fill(vault.password);await fields.nth(1).fill(vault.password);
  const breach=page.locator('input[type=checkbox]');if(await breach.count())await breach.first().uncheck();
  await page.locator('button[type=submit]:visible:not([aria-hidden=true])').first().click();
 }else if(page.url().includes('/lock')){
  await page.locator('input[type=password]').first().fill(vault.password);await page.locator('button[type=submit]:visible:not([aria-hidden=true])').first().click();
 }
 await page.waitForURL(/#\/(vault|tabs)/,{timeout:30000});
 await page.waitForTimeout(1500);
 if(namespace==='production' && page.url().includes('set-initial-password'))throw new Error('Production initialization must be performed by the user');
 if(namespace==='local'){
  const data=await page.evaluate(async token=>{const r=await fetch('/api/sync',{headers:{Authorization:`Bearer ${token}`}});if(!r.ok)throw new Error('Sync failed');return r.json();},tokenResponse.access_token);
  if(data.ciphers.length){const search=page.locator('input[placeholder="搜索密码库"]');if(await search.count()){await search.fill('Test item');await page.getByText('Test item',{exact:true}).first().waitFor();}}
 }
 if(namespace==='local'){
  const itemName='Web UI acceptance '+crypto.randomUUID();
  await page.getByRole('button',{name:'新增',exact:true}).click();
  await page.getByRole('menuitem',{name:'登录',exact:true}).click();
  const dialog=page.getByRole('dialog');
  await dialog.locator('input[formcontrolname=name]').fill(itemName);
  await dialog.locator('input[formcontrolname=username]').fill('web-test-user');
  await dialog.locator('input[formcontrolname=password]').fill('web-test-secret');
  await dialog.locator('input[formcontrolname=uri]').fill('https://example.test');
  const [saved]=await Promise.all([page.waitForResponse(r=>r.request().method()==='POST' && /\/api\/ciphers(?:\/create)?$/.test(new URL(r.url()).pathname)),dialog.getByRole('button',{name:'保存',exact:true}).click()]);
  if(saved.status()!==200)throw new Error('Web item save rejected');
  const cipher=await saved.json();if(cipher.name===itemName||!cipher.name.includes('|'))throw new Error('Web item was not encrypted');
  await page.reload({waitUntil:'networkidle'});
  await page.waitForURL(/#\/(lock|vault|tabs)/);
  if(page.url().includes('/lock')){await page.locator('input[type=password]').first().fill(vault.password);await page.locator('button[type=submit]').first().click();await page.waitForURL(/#\/(vault|tabs)/);}
  const search=page.locator('input[placeholder="搜索密码库"]');if(await search.count())await search.fill('');
  await page.getByText(itemName,{exact:true}).first().waitFor();
  const removed=await page.evaluate(async ({token,id})=>{const r=await fetch('/api/ciphers/'+id,{method:'DELETE',headers:{Authorization:`Bearer ${token}`}});return r.status;},{token:tokenResponse.access_token,id:cipher.id});
  if(removed!==204)throw new Error('Web acceptance fixture cleanup failed');
 }

 await page.screenshot({path:'test-results/web-vault.png',fullPage:true});
 if(!tokenResponse) throw new Error('No SSO token response observed');
 if(apiFailures.length)throw new Error('Required Web Vault API failures: '+JSON.stringify(apiFailures));
 console.log('Real Auth0 SSO and Web Vault initialization/unlock passed.');
}catch(error){
 await page.screenshot({path:'test-results/web-vault-error.png',fullPage:true});
 console.log('Browser stopped on',new URL(page.url()).pathname,'fragment',new URL(page.url()).hash.split('?')[0]);
 console.log('Visible page:',(await page.locator('body').innerText()).replaceAll(email,'[test email]').slice(0,1500));
 throw error;
}finally{await browser.close();}
