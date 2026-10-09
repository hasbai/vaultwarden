import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {readFileSync,existsSync,unlinkSync,mkdirSync} from 'node:fs';
import {chromium} from 'playwright';
const origin='https://localhost:8787';const vault=JSON.parse(readFileSync('.secrets/local-vault.json','utf8'));
const source=readFileSync(process.env.AUTH0_TEST_ENV_FILE??'/Users/yueshi/src/financial/.env','utf8');const value=k=>source.match(new RegExp(`^${k}=(.*)$`,'m'))?.[1].trim().replace(/^['"]|['"]$/g,'');
mkdirSync('test-results/cli',{recursive:true});
const env={...process.env,BITWARDENCLI_APPDATA_DIR:process.cwd()+'/test-results/cli',BW_PASSWORD:vault.password};
const run=(args,session)=>execFileSync(process.execPath,['node_modules/@bitwarden/cli/build/bw.js',...args],{env:{...env,...(session?{BW_SESSION:session}:{})},encoding:'utf8',stdio:['pipe','pipe','pipe']}).trim();
try{run(['logout']);}catch{}
run(['config','server',origin]);if(existsSync('.secrets/cli-sso-url.txt'))unlinkSync('.secrets/cli-sso-url.txt');
const child=spawn(process.execPath,['--require','./tests/cli-browser-hook.cjs','node_modules/@bitwarden/cli/build/bw.js','login','--sso','hasbai','--passwordenv','BW_PASSWORD','--raw'],{env,stdio:['pipe','pipe','pipe']});
let stdout='',stderr='';child.on('exit',code=>console.log('CLI child exit:',code));child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);
const completed=new Promise(resolve=>child.on('exit',code=>resolve(code)));
process.env.PLAYWRIGHT_DISABLE_FORCED_CHROMIUM_PROXIED_LOOPBACK='1';
const browser=await chromium.launch({executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true,proxy:{server:'http://127.0.0.1:7890',bypass:'localhost,127.0.0.1,[::1]'},args:['--disable-quic']});
try{
 for(let i=0;i<300 && !existsSync('.secrets/cli-sso-url.txt');i++)await new Promise(r=>setTimeout(r,100));
 if(!existsSync('.secrets/cli-sso-url.txt'))throw new Error('CLI did not launch the SSO flow; '+stderr.slice(-600));
 const page=await browser.newPage({ignoreHTTPSErrors:true});page.on('requestfailed',r=>console.log('Browser request failed:',new URL(r.url()).origin,new URL(r.url()).pathname,r.failure()?.errorText));await page.goto(readFileSync('.secrets/cli-sso-url.txt','utf8'));
 await page.waitForURL('https://auth.hasbai.xyz/**');
 await page.locator('input[name=username]').fill(value('AUTH0_TEST_EMAIL'));
 if(!await page.locator('input[name=password]').count())await page.locator('button[type=submit]:visible:not([aria-hidden=true])').first().click();
 await page.locator('input[name=password]').fill(value('AUTH0_TEST_PASSWORD'));await page.locator('button[type=submit]:visible:not([aria-hidden=true])').first().click();
 await page.waitForURL(url=>(url.hostname==='localhost'&&Number(url.port)>=8065)||url.pathname==='/u/consent',{timeout:45000});
 if(new URL(page.url()).pathname==='/u/consent'){await page.getByRole('button',{name:/接受|Accept/}).click();await page.waitForURL(url=>url.hostname==='localhost'&&Number(url.port)>=8065,{timeout:45000});}
 const code=await Promise.race([completed,new Promise(r=>setTimeout(()=>r(-1),30000))]);
 if(code!==0)throw new Error('CLI SSO did not complete; '+stderr.slice(-600));
 const session=run(['unlock','--passwordenv','BW_PASSWORD','--raw']);assert.ok(session.length>20);
 run(['sync'],session);
 const encoded=execFileSync(process.execPath,['node_modules/@bitwarden/cli/build/bw.js','encode'],{env,input:JSON.stringify({name:'CLI folder'}),encoding:'utf8'}).trim();
 const folder=JSON.parse(run(['create','folder',encoded],session));assert.equal(folder.name,'CLI folder');
 const template=JSON.parse(run(['get','template','item'],session));template.name='CLI encrypted item';template.login={username:'test-user',password:'test-secret',uris:[{uri:'https://example.test'}]};template.folderId=folder.id;
 const itemEncoded=execFileSync(process.execPath,['node_modules/@bitwarden/cli/build/bw.js','encode'],{env,input:JSON.stringify(template),encoding:'utf8'}).trim();
 const item=JSON.parse(run(['create','item',itemEncoded],session));assert.equal(item.name,template.name);
 run(['sync'],session);const read=JSON.parse(run(['get','item',item.id],session));assert.equal(read.login.password,'test-secret');
 run(['delete','item',item.id],session);run(['delete','folder',folder.id],session);run(['logout']);
 console.log('Official Bitwarden CLI 2026.7.0: real Auth0 SSO, unlock, create/sync/decrypt/delete item and folder passed.');
}catch(error){console.log('CLI diagnostic stderr:',stderr.slice(-600));throw error;}finally{child.kill();await browser.close();}
