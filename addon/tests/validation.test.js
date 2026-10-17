// Tests for addon/Validation.gs. Run from the repo root: node addon/tests/validation.test.js
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const sandbox = {};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'Validation.gs'), 'utf8'), sandbox);
const { validateEntry, isValidAddress, isValidRuleId, cleanPreferences } = sandbox;

let passed = 0;
function test(name, fn) {
  try { fn(); passed++; } catch (err) { console.error('FAIL', name, '\n ', err.message); process.exitCode = 1; }
}
const U = (code) => String.fromCharCode(code);  // build invisible characters without literal escapes

test('valid addresses and domains are accepted and normalized', () => {
  assert.strictEqual(validateEntry(' Dana.Cohen+x@Acme.co.il ', false).entry, 'dana.cohen+x@acme.co.il');
  assert.strictEqual(validateEntry('mycompany.com', false).entry, 'mycompany.com');
  assert.strictEqual(validateEntry('friend@gmail.com', false).entry, 'friend@gmail.com');
});

test('hostile or malformed entries are refused', () => {
  const hostile = [
    '"john smith"@company.com', '<script>@x.com', 'a<b@x.com', "o'brien@x.com", 'x@y', '@x.com', 'x@-bad.com',
    'x@bad-.com', 'x@x..com', '../etc/passwd', 'javascript:alert(1)', 'a'.repeat(65) + '@x.com',
    'x@' + 'a'.repeat(64) + '.com', 'x@' + ('a'.repeat(60) + '.').repeat(5) + 'com', 'x@x.c', 'x@x.c0m',
    'ab' + U(0x202e) + 'cd@x.com', 'a' + U(0x200b) + '@x.com', 'a@x.com' + U(0x0000), 'a' + U(0x0a) + 'b@x.com',
    U(0xfeff) + 'x.com', 'x' + U(0x2066) + '.com', 'xn--a.com ' + U(0x00ad),
  ];
  for (const raw of hostile) {
    assert.strictEqual(validateEntry(raw, true).entry, '', 'accepted: ' + JSON.stringify(raw));
  }
});

test('invisible characters are reported as such', () => {
  assert.strictEqual(validateEntry('a' + U(0x202e) + '@x.com', true).reason, 'contains control or invisible characters');
});

test('free-mail domains only as whole addresses in the trusted list', () => {
  assert.strictEqual(validateEntry('gmail.com', false).entry, '');
  assert.strictEqual(validateEntry('gmail.com', true).entry, 'gmail.com');  // blocking a whole domain is fine
});

test('non-strings are refused', () => {
  for (const raw of [null, undefined, 42, {}, ['a@b.com']]) assert.strictEqual(validateEntry(raw, true).entry, '');
});

test('isValidAddress: plain addresses only', () => {
  assert.ok(isValidAddress('a.b@c.com'));
  for (const raw of ['c.com', 'A@B.COM', '"a"@b.com', 'a b@c.com', 'a@b.com OR from:*', 'a@b.com' + U(0x200b)]) {
    assert.ok(!isValidAddress(raw), raw);
  }
});

test('rule ids: lowercase identifiers only', () => {
  assert.ok(isValidRuleId('virustotal_domain'));
  for (const raw of ['', 'Rule', '1rule', 'a-b', 'a b', 'a'.repeat(65), '__proto__x'.toUpperCase(), 'a.b', null, 7]) {
    assert.ok(!isValidRuleId(raw), String(raw));
  }
});

test('cleanPreferences drops everything invalid, dedupes and caps', () => {
  const dirty = {
    disabledRules: ['spf_fail', 'spf_fail', 'BAD', '<x>', 42, 'url_shortener'],
    trustedSenders: ['gmail.com', 'Friend@Gmail.com', 'friend@gmail.com', '"x"@y.com', 'ok.com', null],
    blockedSenders: Array.from({ length: 250 }, (_, i) => 'spam' + i + '.com').concat(['gmail.com']),
  };
  const clean = cleanPreferences(dirty);
  assert.deepStrictEqual(Array.from(clean.disabledRules), ['spf_fail', 'url_shortener']);
  assert.deepStrictEqual(Array.from(clean.trustedSenders), ['friend@gmail.com', 'ok.com']);
  assert.strictEqual(clean.blockedSenders.length, 200);
  assert.deepStrictEqual(Array.from(cleanPreferences(null).trustedSenders), []);
  assert.deepStrictEqual(Array.from(cleanPreferences({ trustedSenders: 'a@b.com' }).trustedSenders), []);  // not a list
});

console.log(`${passed} passed${process.exitCode ? ', some FAILED' : ''}`);

// --- trusted file types -----------------------------------------------------------------
const { validateExtension } = sandbox;
let passed2 = 0;
function test2(name, fn) {
  try { fn(); passed2++; } catch (err) { console.error('FAIL', name, '\n ', err.message); process.exitCode = 1; }
}
test2('file types are normalized', () => {
  for (const [raw, want] of [['html', 'html'], ['.HTML', 'html'], [' docm ', 'docm'], ['7z', '7z']]) {
    assert.strictEqual(validateExtension(raw).entry, want, raw);
  }
});
test2('malformed file types are refused', () => {
  for (const raw of ['', '.', 'ht ml', 'a'.repeat(11), '<b>', 'tar.gz', 'pdf.exe', 'ht' + U(0x202e) + 'ml', null, 5]) {
    assert.strictEqual(validateExtension(raw).entry, '', String(raw));
  }
});
test2('cleanPreferences keeps valid, unique file types, at most 50', () => {
  const clean = cleanPreferences({ trustedExtensions: ['html', '.HTML', 'bad type', 'docm'].concat(Array.from({ length: 60 }, (_, i) => 'x' + i)) });
  assert.deepStrictEqual(Array.from(clean.trustedExtensions).slice(0, 3), ['html', 'docm', 'x0']);
  assert.strictEqual(clean.trustedExtensions.length, 50);
});
console.log(`${passed2} more passed (file types)`);
