import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {randomBytes, createCipheriv, createHmac, createDecipheriv, pbkdf2Sync} from 'node:crypto';

// Local D1 only. The SSO browser fixture supplies an isolated test vault.
const origin = 'https://localhost:8787';
const token = JSON.parse(readFileSync('.secrets/local-session.json')).access_token;
const run = promisify(execFile);
async function api(path, body) {
  const r = await fetch(origin + path, {method: body ? 'POST' : 'GET', headers: {Authorization: `Bearer ${token}`, 'Content-Type': 'application/json'}, body: body ? JSON.stringify(body) : undefined});
  const raw = await r.text();
  return {status: r.status, data: raw ? JSON.parse(raw) : null};
}
const profile = await api('/api/accounts/profile');
assert.equal(profile.status, 200);
const password = JSON.parse(readFileSync('.secrets/local-vault.json')).password;
const master = pbkdf2Sync(password, profile.data.email, 600000, 32, 'sha256');
const wrappingKey = Buffer.concat(['enc', 'mac'].map(k => createHmac('sha256', master).update(Buffer.from(k + '\x01')).digest()));
const [iv, data, mac] = profile.data.key.slice(2).split('|').map(s => Buffer.from(s, 'base64'));
assert.deepEqual(createHmac('sha256', wrappingKey.subarray(32)).update(Buffer.concat([iv, data])).digest(), mac);
const decipher = createDecipheriv('aes-256-cbc', wrappingKey.subarray(0, 32), iv);
const key = Buffer.concat([decipher.update(data), decipher.final()]);
function encrypt(text) {
  const iv = randomBytes(16), cipher = createCipheriv('aes-256-cbc', key.subarray(0, 32), iv);
  const data = Buffer.concat([cipher.update(text), cipher.final()]);
  const mac = createHmac('sha256', key.subarray(32)).update(Buffer.concat([iv, data])).digest();
  return '2.' + [iv, data, mac].map(b => b.toString('base64')).join('|');
}
const testRun = crypto.randomUUID();
const base = {type: 2, name: encrypt('Import regression'), notes: encrypt('x'.repeat(1024)), secureNote: {type: 0}, folderId: null, encryptedFor: profile.data.id, testRun};
const payload = {folders: [{name: encrypt('Import folder A')}, {name: encrypt('Import folder B')}], ciphers: Array.from({length: 1501}, (_, importIndex) => ({...base, importIndex})), folderRelationships: [{key: 0, value: 0}, {key: 750, value: 1}, {key: 1500, value: 0}]};
for (const relation of payload.folderRelationships) payload.ciphers[relation.key].folderId = crypto.randomUUID();
assert.ok(Buffer.byteLength(JSON.stringify(payload)) > 2 * 1024 * 1024);
async function snapshot() {
  const sync = await api('/api/sync'), revision = await api('/api/accounts/revision-date');
  assert.equal(sync.status, 200);
  return {items: sync.data.ciphers.length, folders: sync.data.folders.length, revision: revision.data};
}
async function localSql(sql) {
  writeFileSync('.secrets/import-regression.sql', sql, {mode: 0o600});
  await run(process.execPath, ['node_modules/wrangler/bin/wrangler.js', 'd1', 'execute', 'vaultwarden', '--local', '--persist-to', 'test-results/d1-live', '--file', '.secrets/import-regression.sql']);
}
const before = await snapshot();
const invalid = structuredClone(payload); invalid.ciphers.at(-1).type = 100;
assert.equal((await api('/api/ciphers/import', invalid)).status, 400);
assert.deepEqual(await snapshot(), before);
const badMapping = structuredClone(payload); badMapping.folderRelationships.push({key: 1501, value: 0});
assert.equal((await api('/api/ciphers/import', badMapping)).status, 400);
assert.deepEqual(await snapshot(), before);
const overCount = await api('/api/ciphers/import', {folders: [], ciphers: Array(10001).fill({type: 2}), folderRelationships: []});
assert.equal(overCount.status, 413); assert.match(overCount.data.message, /10000/); assert.equal(overCount.data.validationErrors, undefined);
assert.deepEqual(await snapshot(), before);
const overBody = await api('/api/ciphers/import', {padding: 'x'.repeat(8 * 1024 * 1024)});
assert.equal(overBody.status, 413); assert.match(overBody.data.message, /8 MiB/);
assert.deepEqual(await snapshot(), before);
await localSql("CREATE TRIGGER import_regression_fail BEFORE INSERT ON ciphers WHEN json_extract(NEW.payload,'$.importIndex')=1500 BEGIN SELECT RAISE(ABORT,'late import failure'); END;");
try {
  assert.equal((await api('/api/ciphers/import', payload)).status, 409);
  assert.deepEqual(await snapshot(), before);
} finally { await localSql('DROP TRIGGER import_regression_fail;'); }
try {
  assert.equal((await api('/api/ciphers/import', payload)).status, 204);
  const sync = (await api('/api/sync')).data;
  const imported = sync.ciphers.filter(c => c.testRun === testRun);
  assert.equal(imported.length, 1501);
  assert.equal(sync.folders.length, before.folders + 2);
  const item = index => imported.find(c => c.importIndex === index);
  assert.equal(item(0).folderId, item(1500).folderId);
  assert.notEqual(item(0).folderId, item(750).folderId);
  assert.ok(sync.folders.some(f => f.id === item(750).folderId));
  assert.equal(item(1000).notes, base.notes);
  // JSON escaping makes this single valid item exceed the normal chunk target.
  const large = {...base, importIndex: 2000, notes: null, quoteHeavy: '"'.repeat(250000)};
  assert.ok(Buffer.byteLength(JSON.stringify(large)) < 512 * 1024);
  assert.equal((await api('/api/ciphers/import', {folders: [], ciphers: [large], folderRelationships: []})).status, 204);
} finally {
  const sync = (await api('/api/sync')).data;
  const imported = sync.ciphers.filter(c => c.testRun === testRun);
  const folders = [...new Set(imported.map(c => c.folderId).filter(Boolean))];
  await localSql(`DELETE FROM ciphers WHERE json_extract(payload,'$.testRun')='${testRun}';${folders.map(id => `DELETE FROM folders WHERE id='${id}';`).join('')}`);
}
const after = await snapshot();
assert.equal(after.items, before.items); assert.equal(after.folders, before.folders);
console.log('Large encrypted import passed: 1501 items, >2 MiB, cross-chunk folders, late validation and DB rollback, readable limits, large escaped item.');
