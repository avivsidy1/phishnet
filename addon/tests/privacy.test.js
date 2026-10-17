// Tests for addon/Privacy.gs. Run from the repo root: node addon/tests/privacy.test.js
// Apps Script files aren't modules, so the file is loaded into a sandbox like Apps Script does.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const sandbox = {};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'Privacy.gs'), 'utf8'), sandbox);
const { maskSensitive, sanitizeUrl, sanitizeReport, maskUrl, privacySummary } = sandbox;

let passed = 0;
function test(name, fn) {
  try { fn(); passed++; } catch (err) { console.error('FAIL', name, '\n ', err.message); process.exitCode = 1; }
}
const masks = (input, expected) => assert.strictEqual(maskSensitive(input), expected);

test('credit cards (Luhn-valid, any common grouping) are masked', () => {
  masks('card 4111 1111 1111 1111 ok', 'card [credit card] ok');
  masks('5500-0000-0000-0004', '[credit card]');
  masks('amex 378282246310005', 'amex [credit card]');
});
test('numbers failing Luhn stay', () => masks('ref 4111 1111 1111 1112', 'ref 4111 1111 1111 1112'));

test('Israeli ID with a valid check digit is masked, invalid stays', () => {
  masks('ID: 123456782', 'ID: [israeli id]');
  masks('ID: 123456789', 'ID: 123456789');
});

test('US SSN masked; impossible ones stay', () => {
  masks('SSN 123-45-6789', 'SSN [ssn]');
  masks('000-12-3456 666-12-3456 900-12-3456 123-00-4567', '000-12-3456 666-12-3456 900-12-3456 123-00-4567');
});

test('IBAN (mod-97 valid) masked, wrong check stays', () => {
  masks('GB82 WEST 1234 5698 7654 32', '[iban]');
  masks('pay to DE89370400440532013000.', 'pay to [iban].');
  masks('GB82 WEST 1234 5698 7654 33', 'GB82 WEST 1234 5698 7654 33');
});

test('bank account numbers after an account keyword are masked', () => {
  masks('Account number: 12-345-678901', 'Account number: [bank account]');
  masks('acct #4433221 please', 'acct #[bank account] please');
  masks('מספר חשבון 778899', 'מספר חשבון [bank account]');
});

test('known secret formats are masked', () => {
  masks('AKIAIOSFODNN7EXAMPLE', '[secret]');
  masks('ghp_' + 'a'.repeat(36), '[secret]');
  masks('xoxb-1234567890-abcdefghij', '[secret]');
  masks('sk_live_' + '4'.repeat(24), '[secret]');
  masks('AIza' + 'B'.repeat(35), '[secret]');
  masks('key sk-ant-api03-' + 'x'.repeat(40), 'key [secret]');
  masks('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXBhcnQ', '[secret]');
  masks('-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----', '[secret]');
});

test('ordinary numbers and text stay', () => {
  const text = 'Order 12345, call 03-1234567, on 2026-10-17, total $1,234.56, zip 90210, version 1.2.3';
  masks(text, text);
});

test('URLs with a sensitive parameter name are reduced to the domain', () => {
  assert.strictEqual(sanitizeUrl('https://bank.com/reset?token=abc123'), 'https://bank.com/');
  assert.strictEqual(sanitizeUrl('https://app.example.com/cb#access_token=xyz&x=1'), 'https://app.example.com/');
  assert.strictEqual(sanitizeUrl('https://x.com/p?a=1&Session_ID=9'), 'https://x.com/');
  assert.strictEqual(sanitizeUrl('https://login.example.com/?code=abc'), 'https://login.example.com/');
  assert.strictEqual(sanitizeUrl('https://x.com/go?a=1&amp;password=hunter2'), 'https://x.com/');  // inside HTML
});
test('URLs without sensitive parameters are kept as they are', () => {
  for (const url of ['https://shop.com/item?id=5', 'https://example.com/?keyword=shoes&monkey=1', 'https://a.com/path', 'mailto:x@y.com']) {
    assert.strictEqual(sanitizeUrl(url), url);
  }
});
test('masking a link never touches its host', () => {
  assert.strictEqual(maskUrl('https://4111111111111111.example.com/pay/4111111111111111'),
    'https://4111111111111111.example.com/pay/[credit card]');
});

test('sanitizeReport cleans every text field and links, and counts what it did', () => {
  const report = {
    message: { subject: 'Your card 4111 1111 1111 1111' },
    body: {
      text: 'Reset: https://bank.com/reset?token=abc and ID 123456782',
      html: '<a href="https://bank.com/reset?x=1&amp;token=abc">reset</a> SSN 123-45-6789',
    },
    links: [{ url: 'https://bank.com/reset?token=abc', text: 'https://bank.com/reset?token=abc', source: 'html' }],
  };
  sanitizeReport(report);
  assert.strictEqual(report.message.subject, 'Your card [credit card]');
  assert.strictEqual(report.body.text, 'Reset: https://bank.com/ and ID [israeli id]');
  assert.strictEqual(report.body.html, '<a href="https://bank.com/">reset</a> SSN [ssn]');
  assert.deepStrictEqual(report.links[0], { url: 'https://bank.com/', text: 'https://bank.com/', source: 'html' });
  assert.deepStrictEqual(JSON.parse(JSON.stringify(report.privacy)),
    { urlsReduced: 4, masked: { 'credit card': 1, 'israeli id': 1, ssn: 1 } });
  assert.strictEqual(privacySummary(report.privacy),
    'Masked before sending: 1 credit card, 1 israeli id, 1 ssn; 4 link(s) with sensitive parameters reduced to their domain');
});

test('hostile input stays fast (no catastrophic backtracking)', () => {
  const inputs = ['1'.repeat(100000), '1 '.repeat(50000), 'a'.repeat(100000), 'https://x'.repeat(10000),
    'eyJ' + 'a'.repeat(100000), '-----BEGIN PRIVATE KEY-----' + 'a'.repeat(100000), 'account ' + '1 '.repeat(50000)];
  for (const input of inputs) {
    const t = Date.now();
    maskSensitive(input);
    const report = { message: { subject: '' }, body: { text: input, html: input }, links: [] };
    sanitizeReport(report);
    assert.ok(Date.now() - t < 1500, `took ${Date.now() - t} ms on ${input.slice(0, 12)}…`);
  }
});

console.log(`${passed} passed${process.exitCode ? ', some FAILED' : ''}`);
