import {generateKeyPairSync,randomBytes} from 'node:crypto';
import {mkdirSync,writeFileSync,existsSync,readFileSync} from 'node:fs';
mkdirSync('.secrets',{recursive:true,mode:0o700});
for (const name of ['local','production']) {
  const path = `.secrets/${name}.json`;
  let secrets;
  if (existsSync(path)) secrets=JSON.parse(readFileSync(path,'utf8'));
  else {
    const {privateKey} = generateKeyPairSync('rsa',{modulusLength:2048});
    secrets = {JWT_JWK:JSON.stringify(privateKey.export({format:'jwk'}))};
  }
  delete secrets.BOOTSTRAP_TOKEN;
  secrets.TOKEN_ENCRYPTION_KEY ??= randomBytes(32).toString('base64url');
  writeFileSync(path,JSON.stringify(secrets),{mode:0o600});
  if(name==='local') writeFileSync('.dev.vars',Object.entries(secrets).map(([k,v])=>`${k}='${v}'`).join('\n')+'\n',{mode:0o600});
}
console.log('Local and production protocol/storage keys prepared (values not logged).');
