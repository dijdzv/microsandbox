import assert from 'node:assert/strict';
import test from 'node:test';
import {validateIsolation, validateEvidence, fixtureFailureLabel} from './orbit-tls-policy-namespace.mjs';

const isolation = () => ({
  pid: 1, net: 'net:[2]', parentNet: 'net:[1]',
  mount: 'mnt:[4]', parentMount: 'mnt:[3]',
  links: [{ifname: 'lo', flags: ['LOOPBACK', 'UP']}],
  addresses: [{ifname: 'lo', addr_info: [
    {local: '127.0.0.1', prefixlen: 8}, {local: '8.8.8.8', prefixlen: 32},
    {local: '::1', prefixlen: 128},
  ]}],
  routes: [{type: 'local', dst: '8.8.8.8', dev: 'lo'},
    {dst: '192.0.2.1', dev: 'lo', scope: 'link'}],
});
const evidence = () => ({
  isolationBefore: isolation(), isolationAfter: isolation(),
  profile: 'multi_tenant', candidateMatchesRuntime: true, runtimeInsideIsolation: true,
  guest: {verified: true, control: true, http1_blocked: true,
    http2_blocked: true, connect_blocked: true, malformed_connect_blocked: true},
  upstreamValidRequests: 1, upstreamBadBytes: false, connectHeaders: 2,
  connectPayloadBytes: 0, retainedBadBytes: false,
  remainingSandboxes: 0, remainingCpuAllocations: 0, cleanupComplete: true,
  events: [
    ...['10.1.2.3', '169.254.169.254'].map(ip => ({ip, policy_origin: 'platform', reason: 'egress_policy'})),
    ...['http_host', 'http_authority'].map(source => ({host: 'evil.example', source,
      policy_origin: 'platform', reason: 'http_authority_mismatch'})),
    {host: 'evil.example', source: 'sni', policy_origin: 'platform', reason: 'connect_sni_mismatch'},
    {host: '', source: 'sni', policy_origin: 'platform', reason: 'connect_sni_mismatch'},
  ],
});

test('accepts a private namespace with only logical loopback fixture addresses', () => {
  validateIsolation(isolation());
  validateEvidence(evidence());
});
test('refuses the host namespaces and a non-init process', () => {
  for (const patch of [{net: 'net:[1]'}, {mount: 'mnt:[3]'}, {pid: 2}])
    assert.throws(() => validateIsolation({...isolation(), ...patch}));
});
test('requires the local IPv4 family-detection route without an external gateway', () => {
  const missing = isolation();
  missing.routes = missing.routes.filter(route => route.dst !== '192.0.2.1');
  assert.throws(() => validateIsolation(missing));
  const explicitPrefix = isolation();
  explicitPrefix.routes[1].dst = '192.0.2.1/32';
  validateIsolation(explicitPrefix);
  for (const patch of [{dev: 'eth0'}, {gateway: '10.0.0.1'}, {dst: '192.0.2.0/24'}]) {
    const wrong = isolation();
    wrong.routes[1] = {...wrong.routes[1], ...patch};
    assert.throws(() => validateIsolation(wrong));
  }
});
test('refuses external interfaces, addresses, gateways and default routes', () => {
  for (const patch of [
    {links: [...isolation().links, {ifname: 'eth0', flags: ['UP']}]},
    {addresses: [{ifname: 'lo', addr_info: [{local: '1.1.1.1', prefixlen: 32}]}]},
    {routes: [{dst: 'default', dev: 'lo'}]},
    {routes: [{dst: '::/0', dev: 'lo'}]},
    {routes: [{dst: '8.8.8.8', dev: 'eth0'}]},
    {routes: [{dst: '8.8.8.8', dev: 'lo', gateway: '10.0.0.1'}]},
  ]) assert.throws(() => validateIsolation({...isolation(), ...patch}));
});
test('failed connections without the exact retained events cannot pass', () => {
  assert.throws(() => validateEvidence({...evidence(), events: []}));
  const wrong = evidence(); wrong.events.at(-1).host = 'private/secret!';
  assert.throws(() => validateEvidence(wrong));
  const duplicate = evidence(); duplicate.events.push({...duplicate.events.at(-1)});
  assert.throws(() => validateEvidence(duplicate));
});
test('requires verified TLS, positive control, unchanged isolation and complete cleanup', () => {
  for (const patch of [{profile: 'single_tenant'}, {candidateMatchesRuntime: false}, {runtimeInsideIsolation: false},
    {upstreamValidRequests: 0}, {upstreamBadBytes: true}, {connectPayloadBytes: 1},
    {retainedBadBytes: true}, {remainingSandboxes: 1}, {remainingCpuAllocations: 1},
    {cleanupComplete: false}]) assert.throws(() => validateEvidence({...evidence(), ...patch}));
  for (const key of Object.keys(evidence().guest)) {
    const wrong = evidence(); wrong.guest[key] = false;
    assert.throws(() => validateEvidence(wrong));
  }
  const escaped = evidence(); escaped.isolationAfter.links.push({ifname: 'eth0', flags: ['UP']});
  assert.throws(() => validateEvidence(escaped));
});
test('preserves a known child failure label without publishing raw errors or claiming success', () => {
  assert.equal(fixtureFailureLabel({qualified: false, failure: 'COMMAND_FAILED_guest',
    stderr: 'fixture-private-marker'}), 'COMMAND_FAILED_guest');
  assert.equal(fixtureFailureLabel({qualified: false, failure: 'fixture_assertion'}), 'fixture_assertion');
  for (const report of [null, {}, {qualified: true, failure: null},
    {qualified: true, failure: 'COMMAND_FAILED_guest'},
    {qualified: false, failure: 'fixture-private-marker'},
    {qualified: false, failure: 'COMMAND_FAILED_guest\nfixture-private-marker'}])
    assert.equal(fixtureFailureLabel(report), 'namespace_fixture_failed');
});
