import assert from 'node:assert/strict';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {verifyAuth0} from '../src/auth0.js';
const {privateKey,publicKey}=await generateKeyPair('RS256');const jwk={...await exportJWK(publicKey),kid:'local-test'};
const original=globalThis.fetch;
globalThis.fetch=async url=>{assert.equal(String(url),'https://auth.hasbai.xyz/.well-known/jwks.json');return Response.json({keys:[jwk]});};
const c={domain:'auth.hasbai.xyz',audience:'https://financial.hasbai.xyz/api',clientId:'shared-client',organization:'org_local',permission:'vaultwarden.all:all'};
const sign=async(patch={},options={})=>new SignJWT({org_id:c.organization,azp:c.clientId,permissions:[c.permission],...patch}).setProtectedHeader({alg:'RS256',kid:jwk.kid}).setIssuer(options.issuer??'https://auth.hasbai.xyz/').setAudience(options.audience??c.audience).setSubject(options.sub??'auth0|local').setIssuedAt().setExpirationTime(options.exp??'1h').sign(privateKey);
try{
 assert.equal(JSON.parse(await verifyAuth0(await sign(),JSON.stringify(c))).sub,'auth0|local');
 for(const [patch,options] of [[{permissions:[]},{}],[{permissions:['access:vaultwarden']},{}],[{org_id:'org_other'},{}],[{azp:'other-client'},{}],[{}, {issuer:'https://wrong.test/'}],[{}, {audience:c.clientId}],[{}, {sub:'machine@clients'}],[{}, {exp:'-1h'}]]) await assert.rejects(async()=>verifyAuth0(await sign(patch,options),JSON.stringify(c)));
 const forged=await sign();await assert.rejects(()=>verifyAuth0(forged.slice(0,-12)+'invalid',JSON.stringify(c)));
 console.log('Auth0 signed-token authorization: valid, missing permission, wrong org/client/audience/issuer, machine, expired and forged cases passed.');
}finally{globalThis.fetch=original;}
