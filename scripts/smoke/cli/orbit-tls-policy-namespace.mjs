// Credential-free Linux/KVM qualification. Usage (root):
// node <this-file> <candidate-msb> <rootfs> <firmware> <fuse-overlayfs> [loader-libs]
// This is a smoke test, not an installer. It never swaps production binaries.
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
import {existsSync, readFileSync, writeFileSync, readlinkSync, realpathSync,
  statSync, mkdirSync, mkdtempSync, chmodSync} from 'node:fs';
import {dirname, isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {DatabaseSync} from 'node:sqlite';
import net from 'node:net';
import tls from 'node:tls';

const execute = promisify(execFile);
const hash = path => createHash('sha256').update(readFileSync(path)).digest('hex');
const managed = '/etc/microsandbox/managed.json';

export function validateCandidateVersion(version) {
  assert.equal(version.trim(), 'msb 0.7.7');
}

export function fixtureFailureLabel(report) {
  if (report?.qualified !== false || typeof report.failure !== 'string')
    return 'namespace_fixture_failed';
  return /^(?:COMMAND_FAILED_(?:version|ca|leaf-request|leaf|mount|create|guest|stop|remove|unmount)|fixture_assertion|cleanup_failed|unmount_failed|qualification_failed)$/.test(report.failure)
    ? report.failure : 'namespace_fixture_failed';
}

export function validateIsolation(e) {
  assert.equal(e.pid, 1, 'fixture must own a private PID namespace');
  for (const [current, parent, prefix] of [[e.net, e.parentNet, 'net'], [e.mount, e.parentMount, 'mnt']]) {
    assert.match(current, new RegExp(`^${prefix}:\\[\\d+\\]$`));
    assert.match(parent, new RegExp(`^${prefix}:\\[\\d+\\]$`));
    assert.notEqual(current, parent, 'refuse the host namespace');
  }
  assert.equal(e.links.length, 1);
  assert.equal(e.links[0].ifname, 'lo');
  assert(e.links[0].flags.includes('UP'));
  assert.equal(e.addresses.length, 1);
  assert.equal(e.addresses[0].ifname, 'lo');
  const allowed = new Set(['127.0.0.1/8', '8.8.8.8/32', '::1/128']);
  for (const address of e.addresses[0].addr_info)
    assert(allowed.has(`${address.local}/${address.prefixlen}`), 'unexpected address');
  assert(e.addresses[0].addr_info.some(a => a.local === '8.8.8.8' && a.prefixlen === 32));
  for (const route of e.routes) {
    assert.equal(route.dev, 'lo', 'no external route');
    assert(!route.gateway && !route.via && !route.nexthops, 'no gateway');
    assert(route.dst && !['default', '0.0.0.0/0', '::/0'].includes(route.dst), 'no default route');
  }
  // The runtime selects guest IPv4 only if its UDP route lookup to
  // TEST-NET-1 succeeds. This loopback-only route enables that lookup without
  // a default route or access to any external network device.
  assert(e.routes.some(route => ['192.0.2.1', '192.0.2.1/32'].includes(route.dst)
    && route.dev === 'lo' && (!route.type || route.type === 'unicast')),
  'fixture needs the local IPv4 family-detection route');
}

export function validateEvidence(e) {
  validateIsolation(e.isolationBefore);
  validateIsolation(e.isolationAfter);
  assert.equal(e.isolationBefore.net, e.isolationAfter.net);
  assert.equal(e.isolationBefore.mount, e.isolationAfter.mount);
  assert.equal(e.profile, 'multi_tenant');
  assert.equal(e.candidateMatchesRuntime, true);
  assert.equal(e.runtimeInsideIsolation, true);
  for (const key of ['verified', 'control', 'http1_blocked', 'http2_blocked',
    'connect_blocked', 'malformed_connect_blocked']) assert.equal(e.guest[key], true, key);
  assert.equal(e.upstreamValidRequests, 1);
  assert.equal(e.upstreamBadBytes, false);
  assert.equal(e.connectHeaders, 2);
  assert.equal(e.connectPayloadBytes, 0);
  assert.equal(e.retainedBadBytes, false);
  assert.equal(e.remainingSandboxes, 0);
  assert.equal(e.remainingCpuAllocations, 0);
  assert.equal(e.cleanupComplete, true);
  for (const ip of ['10.1.2.3', '169.254.169.254'])
    assert(e.events.some(row => row.ip === ip && row.policy_origin === 'platform'
      && row.reason === 'egress_policy'));
  for (const [host, source, reason] of [
    ['evil.example', 'http_host', 'http_authority_mismatch'],
    ['evil.example', 'http_authority', 'http_authority_mismatch'],
    ['evil.example', 'sni', 'connect_sni_mismatch'],
    ['', 'sni', 'connect_sni_mismatch'],
  ]) assert.equal(e.events.filter(row => row.host === host && row.source === source
    && row.policy_origin === 'platform' && row.reason === reason).length, 1);
}

async function observeIsolation(parentNet, parentMount) {
  const json = async args => JSON.parse((await execute('/usr/sbin/ip', ['-j', ...args])).stdout);
  return {pid: process.pid, parentNet, parentMount,
    net: readlinkSync('/proc/self/ns/net'), mount: readlinkSync('/proc/self/ns/mnt'),
    links: await json(['link', 'show']), addresses: await json(['addr', 'show']),
    routes: [...await json(['-4', 'route', 'show', 'table', 'all']),
      ...await json(['-6', 'route', 'show', 'table', 'all'])]};
}

function validateInputs(args) {
  assert(args.length === 4 || args.length === 5, 'expected msb, rootfs, firmware, fuse-overlayfs, optional loader-libs');
  for (const path of args.slice(0, 4)) {
    assert(isAbsolute(path));
    assert(existsSync(path));
  }
  assert(statSync(args[0]).isFile() && (statSync(args[0]).mode & 0o111));
  assert(statSync(args[1]).isDirectory());
  assert(statSync(args[2]).isFile());
  assert(statSync(args[3]).isFile() && (statSync(args[3]).mode & 0o111));
  for (const path of (args[4] ?? dirname(args[2])).split(':')) {
    assert(isAbsolute(path) && statSync(path).isDirectory());
  }
  assert.equal(statSync(managed).uid, 0);
  assert.equal(statSync(managed).mode & 0o777, 0o644);
  assert.equal(statSync(dirname(managed)).uid, 0);
  assert.equal(statSync(dirname(managed)).mode & 0o022, 0);
  assert.equal(JSON.parse(readFileSync(managed)).overrides.deployment_profile, 'multi-tenant');
}

async function runInside(root, parentNet, parentMount, args) {
  assert.equal(process.getuid(), 0);
  assert.equal(process.pid, 1);
  assert.match(root, /^\/tmp\/msb-orbit-tls-netns\.[A-Za-z0-9]+$/);
  validateInputs(args);
  assert.notEqual(readlinkSync('/proc/self/ns/net'), parentNet);
  assert.notEqual(readlinkSync('/proc/self/ns/mnt'), parentMount);
  // All network mutations occur inside this new namespace, never on the host.
  await execute('/usr/sbin/ip', ['link', 'set', 'lo', 'up']);
  await execute('/usr/sbin/ip', ['addr', 'add', '8.8.8.8/32', 'dev', 'lo']);
  await execute('/usr/sbin/ip', ['route', 'add', '192.0.2.1/32', 'dev', 'lo']);
  const isolationBefore = await observeIsolation(parentNet, parentMount);
  validateIsolation(isolationBefore);
  const [binary, lower, firmware, fuse] = args;
  const binaryHash = hash(binary), policyHash = hash(managed);
  for (const dir of ['home', 'upper', 'work', 'merged']) mkdirSync(`${root}/${dir}`, {mode: 0o700});
  writeFileSync(`${root}/home/config.json`, JSON.stringify({version: 1, deployment_profile: 'single_tenant'}), {mode: 0o600});
  const env = {PATH: '/usr/bin:/usr/sbin:/bin', HOME: `${root}/home`, LANG: 'C.UTF-8',
    MSB_HOME: `${root}/home`, MSB_CONFIG_PATH: `${root}/home/config.json`, MSB_PATH: binary,
    MSB_LIBKRUNFW_PATH: firmware, LD_LIBRARY_PATH: args[4] ?? dirname(firmware)};
  async function command(file, argv, label, extra = {}) {
    try {
      const result = await execute(file, argv, {env: {...env, ...extra}, timeout: 60000, maxBuffer: 4 * 1024 * 1024});
      writeFileSync(`${root}/${label}.stdout`, result.stdout, {mode: 0o600});
      writeFileSync(`${root}/${label}.stderr`, result.stderr, {mode: 0o600});
      return result.stdout;
    } catch (error) {
      writeFileSync(`${root}/${label}.stdout`, error.stdout ?? '', {mode: 0o600});
      writeFileSync(`${root}/${label}.stderr`, error.stderr ?? '', {mode: 0o600});
      throw new Error(`COMMAND_FAILED_${label}`);
    }
  }
  validateCandidateVersion(await command(binary, ['--version'], 'version'));
  await command('/usr/bin/openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=Orbit smoke CA', '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', `${root}/ca.key`, '-out', `${root}/ca.crt`], 'ca');
  await command('/usr/bin/openssl', ['req', '-new', '-newkey', 'rsa:2048', '-nodes',
    '-subj', '/CN=allowed.example', '-keyout', `${root}/leaf.key`, '-out', `${root}/leaf.csr`], 'leaf-request');
  writeFileSync(`${root}/leaf.ext`, 'basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:allowed.example\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n', {mode: 0o600});
  await command('/usr/bin/openssl', ['x509', '-req', '-days', '1', '-in', `${root}/leaf.csr`,
    '-CA', `${root}/ca.crt`, '-CAkey', `${root}/ca.key`, '-CAcreateserial', '-extfile', `${root}/leaf.ext`, '-out', `${root}/leaf.crt`], 'leaf');
  const peers = new Set();
  const track = socket => {peers.add(socket); socket.on('close', () => peers.delete(socket)); socket.on('error', () => {});};
  let upstreamValidRequests = 0, upstreamBadBytes = false, connectHeaders = 0, connectPayloadBytes = 0;
  const tlsServer = tls.createServer({key: readFileSync(`${root}/leaf.key`), cert: readFileSync(`${root}/leaf.crt`)}, socket => {
    track(socket); let data = Buffer.alloc(0), answered = false;
    socket.on('data', chunk => {
      data = Buffer.concat([data, chunk]);
      if (data.length > 16384) {upstreamBadBytes = true; socket.destroy(); return;}
      const text = data.toString('utf8');
      if (text.includes('evil.example') || text.includes('fixture-private-marker')) upstreamBadBytes = true;
      if (!answered && text.includes('\r\n\r\n')) {
        answered = true;
        if (text.startsWith('GET /control HTTP/1.1\r\nHost: allowed.example\r\n')) upstreamValidRequests++;
        else upstreamBadBytes = true;
        socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK');
      }
    });
  });
  tlsServer.on('tlsClientError', () => {});
  const connectServer = net.createServer(socket => {
    track(socket); let data = Buffer.alloc(0), ready = false;
    socket.on('data', chunk => {
      if (ready) {connectPayloadBytes += chunk.length; return;}
      data = Buffer.concat([data, chunk]);
      if (data.length > 8192) {socket.destroy(); return;}
      const end = data.indexOf('\r\n\r\n'); if (end < 0) return;
      connectHeaders++;
      if (!data.toString('ascii').startsWith('CONNECT allowed.example:443 HTTP/1.1\r\n')) {socket.destroy(); return;}
      ready = true; connectPayloadBytes += data.length - end - 4;
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    });
  });
  const listen = (server, port) => new Promise((resolve, reject) => {
    server.once('error', reject); server.listen(port, '8.8.8.8', resolve);
  });
  let mounted = false, attempted = false, guest = null, runtime = null, profile = null, failure = null;
  const name = 'orbit-tls-smoke';
  try {
    await listen(tlsServer, 443); await listen(connectServer, 8443);
    validateIsolation(await observeIsolation(parentNet, parentMount));
    for (const dir of ['upper', 'work', 'merged']) chmodSync(`${root}/${dir}`, 0o777);
    await command(fuse, ['-o', `lowerdir=${lower},upperdir=${root}/upper,workdir=${root}/work`, `${root}/merged`], 'mount');
    mounted = true; attempted = true;
    await command(binary, ['create', '--name', name, '--memory', '512M', '--cpus', '1', '--max-duration', '3m',
      '--deployment-profile', 'single-tenant', '--net', 'all', '--net-strict=false', '--tls-intercept',
      '--tls-upstream-ca-cert', `${root}/ca.crt`, '--entrypoint', '/bin/bash', `${root}/merged`], 'create',
    {MSB_DENY_LOG_PATH: `${root}/deny.jsonl`});
    const db = new DatabaseSync(`${root}/home/db/msb.db`, {readOnly: true});
    try {
      const row = db.prepare('SELECT id, config FROM sandbox WHERE name=?').get(name);
      const run = db.prepare('SELECT pid FROM run WHERE sandbox_id=? ORDER BY id DESC LIMIT 1').get(row.id);
      const config = JSON.parse(row.config); profile = config.deployment_profile ?? config.spec?.deployment_profile;
      const path = realpathSync(`/proc/${run.pid}/exe`);
      runtime = {pid: run.pid, sha256: hash(path),
        net: readlinkSync(`/proc/${run.pid}/ns/net`), mount: readlinkSync(`/proc/${run.pid}/ns/mnt`)};
    } finally {db.close();}
    assert.equal(runtime.sha256, binaryHash);
    assert.equal(runtime.net, isolationBefore.net);
    assert.equal(runtime.mount, isolationBefore.mount);
    const out = await command(binary, ['exec', '--no-tty', '--timeout', '45s', name, '--', '/env/bin/python3', '-c', guestCode], 'guest');
    const result = out.split('\n').find(line => line.startsWith('FIXTURE_RESULT='));
    assert(result); guest = JSON.parse(result.slice('FIXTURE_RESULT='.length));
  } catch (error) {failure = error.message.startsWith('COMMAND_FAILED_') ? error.message : 'fixture_assertion';}
  finally {
    if (attempted) {
      try {await command(binary, ['stop', '--timeout', '20', name], 'stop');
        await command(binary, ['remove', name], 'remove'); attempted = false;}
      catch {failure ??= 'cleanup_failed';}
    }
    if (mounted && !attempted) {
      try {await command('/usr/bin/fusermount3', ['-u', `${root}/merged`], 'unmount'); mounted = false;}
      catch {failure ??= 'unmount_failed';}
    }
    for (const peer of peers) peer.destroy();
    for (const server of [connectServer, tlsServer]) server.close();
  }
  let remainingSandboxes = null, remainingCpuAllocations = null;
  if (existsSync(`${root}/home/db/msb.db`)) {
    const db = new DatabaseSync(`${root}/home/db/msb.db`, {readOnly: true});
    try {
      remainingSandboxes = db.prepare('SELECT COUNT(*) AS n FROM sandbox').get().n;
      remainingCpuAllocations = db.prepare('SELECT COUNT(*) AS n FROM cpu_allocation').get().n;
    } finally {db.close();}
  }
  const raw = existsSync(`${root}/deny.jsonl`) ? readFileSync(`${root}/deny.jsonl`, 'utf8') : '';
  const events = raw.trim().split('\n').filter(Boolean).map(line => JSON.parse(line).fields);
  const isolationAfter = await observeIsolation(parentNet, parentMount);
  const report = {observedAt: new Date().toISOString(), candidateSha256: binaryHash, firmwareSha256: hash(firmware),
    isolationBefore, isolationAfter, profile, runtime, candidateMatchesRuntime: runtime?.sha256 === binaryHash,
    runtimeInsideIsolation: runtime?.net === isolationBefore.net && runtime?.mount === isolationBefore.mount,
    guest, events, failure, upstreamValidRequests, upstreamBadBytes, connectHeaders, connectPayloadBytes,
    retainedBadBytes: ['fixture-private-marker', 'Authorization', '/invalid', 'private/secret!'].some(s => raw.includes(s)),
    remainingSandboxes, remainingCpuAllocations, cleanupComplete: !attempted && !mounted,
    actualAIExecution: false, productionBinaryReplaced: false,
    scope: 'private VM and retained host events; not Orbit delivery/UI, SDK skew or Codex refresh/concurrency'};
  let qualified = false;
  try {assert.equal(hash(binary), binaryHash); assert.equal(hash(managed), policyHash);
    assert.equal(failure, null); validateEvidence(report); qualified = true;}
  catch {report.failure ??= 'qualification_failed';}
  writeFileSync(`${root}/result.json`, JSON.stringify({...report, qualified}, null, 2), {mode: 0o644});
  chmodSync(root, 0o755); // Only the synthetic, metadata-only report is public.
  console.log(JSON.stringify({result: `${root}/result.json`, qualified, failure: report.failure}));
  if (!qualified) process.exitCode = 1;
}

const guestCode = String.raw`import socket,ssl,json,struct
context=ssl.create_default_context(cafile='/.msb/tls/ca.pem')
r={'verified':context.check_hostname and context.verify_mode==ssl.CERT_REQUIRED}
for ip in ['10.1.2.3','169.254.169.254']:
 s=socket.socket();s.settimeout(2)
 try:s.connect((ip,80))
 except OSError:pass
 finally:s.close()
def connection():
 return context.wrap_socket(socket.create_connection(('8.8.8.8',443),timeout=4),server_hostname='allowed.example')
def blocked(s):
 try:return not s.recv(4096)
 except TimeoutError:return False
 except OSError:return True
s=connection();s.sendall(b'GET /control HTTP/1.1\r\nHost: allowed.example\r\nConnection: close\r\n\r\n');r['control']=s.recv(4096).startswith(b'HTTP/1.1 200');s.close()
s=connection();s.sendall(b'GET /invalid HTTP/1.1\r\nHost: evil.example\r\nAuthorization: fixture-private-marker\r\n\r\n');r['http1_blocked']=blocked(s);s.close()
def literal(n,v):return bytes([0,len(n)])+n+bytes([len(v)])+v
block=b''.join(literal(n,v) for n,v in [(b':method',b'GET'),(b':scheme',b'https'),(b':authority',b'evil.example'),(b':path',b'/invalid'),(b'authorization',b'fixture-private-marker')])
frame=len(block).to_bytes(3,'big')+bytes([1,5])+struct.pack('>I',1)+block
s=connection();s.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'+bytes([0,0,0,4,0,0,0,0,0])+frame);r['http2_blocked']=blocked(s);s.close()
def tunnel():
 s=socket.create_connection(('8.8.8.8',8443),timeout=4)
 s.sendall(b'CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\n\r\n');data=b''
 while b'\r\n\r\n' not in data:
  chunk=s.recv(1024)
  if not chunk or len(data)>8192:raise RuntimeError('fixture_connect_header')
  data+=chunk
 assert data.startswith(b'HTTP/1.1 200')
 return s
s=tunnel()
try:context.wrap_socket(s,server_hostname='evil.example');r['connect_blocked']=False
except TimeoutError:r['connect_blocked']=False
except OSError:r['connect_blocked']=True
s.close()
incoming=ssl.MemoryBIO();outgoing=ssl.MemoryBIO();obj=context.wrap_bio(incoming,outgoing,server_hostname='allowed.example')
try:obj.do_handshake()
except ssl.SSLWantReadError:pass
hello=outgoing.read();assert hello.count(b'allowed.example')==1
hello=hello.replace(b'allowed.example',b'private/secret!')
s=tunnel();s.sendall(hello);r['malformed_connect_blocked']=blocked(s);s.close()
print('FIXTURE_RESULT='+json.dumps(r))
`;

async function main(args) {
  if (args[0] === '--inside') return runInside(args[1], args[2], args[3], args.slice(4));
  assert.equal(process.platform, 'linux');
  assert.equal(process.getuid(), 0, 'root is required only to create isolated Linux namespaces');
  validateInputs(args);
  const root = mkdtempSync('/tmp/msb-orbit-tls-netns.');
  const parentNet = readlinkSync('/proc/self/ns/net'), parentMount = readlinkSync('/proc/self/ns/mnt');
  const script = fileURLToPath(import.meta.url);
  // PID namespace teardown kills only fixture descendants; mount propagation
  // is private and no network device/route can lead back to the real host.
  try {
    const result = await execute('/usr/bin/unshare', ['--net', '--mount', '--pid', '--fork', '--kill-child',
      '--mount-proc', '--propagation', 'private', '--', process.execPath, script, '--inside', root,
      parentNet, parentMount, ...args], {env: {PATH: '/usr/bin:/usr/sbin:/bin', LANG: 'C.UTF-8', NODE_NO_WARNINGS: '1'},
      timeout: 180000, maxBuffer: 1024 * 1024});
    process.stdout.write(result.stdout);
  } catch {
    let failure = 'namespace_fixture_failed';
    // A completed, unsuccessful child is not necessarily an unshare failure.
    // Publish only its fixed reason label, never stderr or arbitrary text.
    try {failure = fixtureFailureLabel(JSON.parse(readFileSync(`${root}/result.json`, 'utf8')));} catch {}
    console.log(JSON.stringify({result: `${root}/result.json`, qualified: false, failure}));
    process.exitCode = 1;
  }
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(() => {
    console.error('Fixture preflight failed; no qualification claimed. Check root, arguments and managed configuration.');
    process.exitCode = 1;
  });
}
