import {chromium} from 'playwright';
import {readFileSync,writeFileSync,mkdirSync,existsSync} from 'node:fs';
import {randomBytes,pbkdf2Sync,createHmac,createCipheriv} from 'node:crypto';
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

  // Exercise password-protected JSON in the pinned client, including the
  // server's global error contract and a successful retry after rejection.
  const importName='Encrypted import UI '+crypto.randomUUID();
  const importFolderId=crypto.randomUUID();
  const importPassword=randomBytes(24).toString('base64url');
  const importSalt=randomBytes(16).toString('base64');
  const master=pbkdf2Sync(importPassword,importSalt,600000,32,'sha256');
  const exportKey=Buffer.concat(['enc','mac'].map(k=>createHmac('sha256',master).update(Buffer.from(k+'\x01')).digest()));
  const encryptExport=text=>{const iv=randomBytes(16);const c=createCipheriv('aes-256-cbc',exportKey.subarray(0,32),iv);const data=Buffer.concat([c.update(text),c.final()]);const mac=createHmac('sha256',exportKey.subarray(32)).update(Buffer.concat([iv,data])).digest();return '2.'+[iv,data,mac].map(v=>v.toString('base64')).join('|');};
  const file={encrypted:true,passwordProtected:true,salt:importSalt,kdfType:0,kdfIterations:600000,encKeyValidation_DO_NOT_EDIT:encryptExport('validation'),data:encryptExport(JSON.stringify({encrypted:false,folders:[{id:importFolderId,name:importName+' folder'}],items:[{type:1,name:importName,folderId:importFolderId,login:{username:'import-test-user',password:'import-test-password',uris:[{uri:'https://import.example.test'}]}}]}))};
  await page.goto(origin+'/#/tools/import',{waitUntil:'networkidle'});
  await page.getByRole('combobox',{name:/文件格式/}).fill('Bitwarden');
  await page.getByRole('option',{name:'Bitwarden (json)',exact:true}).click();
  await page.locator('input[type=file]').setInputFiles({name:'password-protected-regression.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(file))});
  const importUrl=origin+'/api/ciphers/import';
  // Obtain the real server response separately; Playwright route.fetch's
  // Node cookie jar rejects a Unicode cookie from this local SSO fixture.
  const previousTls=process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  let rejection;
  try {
   process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';
   const r=await fetch(importUrl,{method:'POST',headers:{Authorization:`Bearer ${tokenResponse.access_token}`,'Content-Type':'application/json'},body:JSON.stringify({folders:[],ciphers:Array(10001).fill({type:1}),folderRelationships:[]})});
   rejection={status:r.status,body:await r.text()};
   if(rejection.status!==413 || JSON.parse(rejection.body).validationErrors!=null)throw new Error('Global import error contract failed');
  } finally {if(previousTls===undefined)delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;else process.env.NODE_TLS_REJECT_UNAUTHORIZED=previousTls;}
  await page.route(importUrl,route=>route.fulfill({status:rejection.status,contentType:'application/json',body:rejection.body}));
  await page.getByRole('button',{name:'导入',exact:true}).click();
  let importDialog=page.getByRole('dialog');
  await importDialog.locator('input[type=password]').fill(importPassword);
  await importDialog.getByRole('button',{name:'导入',exact:true}).click();
  await page.getByRole('dialog').getByText('Import at most 10000 records per request',{exact:true}).waitFor();
  if(await page.getByText("Cannot read properties of null (reading '0')",{exact:true}).count())throw new Error('Import global error parser still crashes');
  await page.getByRole('dialog').getByRole('button',{name:'确定',exact:true}).click();
  await page.unroute(importUrl);
  await page.getByRole('button',{name:'导入',exact:true}).click();
  importDialog=page.getByRole('dialog');
  await importDialog.locator('input[type=password]').fill(importPassword);
  const [importedResponse]=await Promise.all([page.waitForResponse(r=>r.url()===importUrl && r.request().method()==='POST'),importDialog.getByRole('button',{name:'导入',exact:true}).click()]);
  if(importedResponse.status()!==204)throw new Error('Password-protected browser import failed');
  await page.waitForURL(/#\/(vault|tabs)/);
  const importedSearch=page.locator('input[placeholder="搜索密码库"]');if(await importedSearch.count())await importedSearch.fill(importName);
  await page.getByText(importName,{exact:true}).first().waitFor();
  const cleaned=await page.evaluate(async token=>{const r=await fetch('/api/sync',{headers:{Authorization:`Bearer ${token}`}});return {sync:await r.json()};},tokenResponse.access_token);
  // API names remain encrypted; match the encrypted request name.
  const importRequest=JSON.parse(importedResponse.request().postData());
  const importedCipher=cleaned.sync.ciphers.find(c=>c.name===importRequest.ciphers[0].name);
  if(!importedCipher?.folderId)throw new Error('Imported folder relationship missing');
  await page.evaluate(async ({token,id,folderId})=>{const headers={Authorization:`Bearer ${token}`};for(const path of ['/api/ciphers/'+id,'/api/folders/'+folderId]){const r=await fetch(path,{method:'DELETE',headers});if(r.status!==204)throw new Error('Import fixture cleanup failed');}},{token:tokenResponse.access_token,id:importedCipher.id,folderId:importedCipher.folderId});
  const expectedFailure=apiFailures.findIndex(f=>f.path==='/api/ciphers/import'&&f.status===413);if(expectedFailure>=0)apiFailures.splice(expectedFailure,1);
  console.log('Pinned Web Vault: password-protected import, readable server error, successful retry and decrypted item passed.');
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
