// Test harness intercepts only opening the SSO browser; official CLI protocol/encryption is unchanged.
const cp=require('node:child_process');
const fs=require('node:fs');
const {EventEmitter}=require('node:events');
const original=cp.spawn;
cp.spawn=function(command,args,...rest){
 const url=args?.find(a=>typeof a==='string' && a.startsWith('https://localhost:8787/'));
 if(url && /(^|\/)open$/.test(command)){
  fs.writeFileSync('.secrets/cli-sso-url.txt',url,{mode:0o600});
  const child=new EventEmitter();child.unref=()=>child;child.stdin=null;
  process.nextTick(()=>child.emit('close',0));return child;
 }
 return original.call(this,command,args,...rest);
};
const http=require('node:http');const createServer=http.createServer;
http.createServer=function(listener,...rest){return createServer.call(this,(req,res)=>{
 const url=new URL('http://localhost'+req.url);
 let expected;
 if(fs.existsSync('.secrets/cli-sso-url.txt'))expected=new URLSearchParams(new URL(fs.readFileSync('.secrets/cli-sso-url.txt','utf8')).hash.split('?')[1]).get('state');
 if(url.searchParams.has('code'))fs.writeFileSync('test-results/cli-callback.json',JSON.stringify({method:req.method,keys:[...url.searchParams.keys()],stateMatches:url.searchParams.get('state')?.split('_identifier=')[0]===expected,codePresent:!!url.searchParams.get('code')}));
 return listener(req,res);
},...rest);};
