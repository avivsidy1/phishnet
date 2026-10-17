/**
 * Privacy: clean the report before it leaves Google.
 *
 * Layer 1: a URL whose query or fragment has a parameter with a sensitive name (token, password,
 * session, ...) is reduced to its domain ("https://bank.com/"); other URLs are kept as they are.
 * The rules only need the host, so detection is unaffected. Applied to links and to URLs inside text.
 *
 * Layer 2: sensitive values in the subject, bodies and link text/URLs are replaced with a typed
 * placeholder: [credit card], [israeli id], [ssn], [iban], [bank account], [secret]. Checksums (Luhn,
 * mod-97) keep false hits low; a false hit only masks a harmless number.
 *
 * Every pattern has bounded repetition so attacker-controlled text can't make it slow.
 */

// Parameter names that usually carry credentials or one-time links.
var SENSITIVE_PARAM_RE = /token|passw|pwd|session|secret|auth|apikey|api_key|signature|credential|bearer|jwt|otp|ticket|magic|reset|^(sig|sid|key|code|pass|hash|nonce)$/i;
var URL_IN_TEXT_RE = /https?:\/\/[^\s<>"'`]{1,2000}/gi;
var URL_PARTS_RE = /^([a-z][a-z0-9+.-]{0,20}:\/\/[^\/?#\s]{1,300})([^?#\s]*)(\?[^#\s]*)?(#\S*)?$/i;

var SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----[\s\S]{0,10000}?-----END [A-Z ]{0,30}PRIVATE KEY-----/g,
  /\beyJ[A-Za-z0-9_-]{10,2000}\.[A-Za-z0-9_-]{10,4000}\.[A-Za-z0-9_-]{10,2000}/g,  // JWT
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,                                              // AWS access key
  /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g, /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g,  // GitHub
  /\bxox[abprs]-[A-Za-z0-9-]{10,255}/g,                                          // Slack
  /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255}\b/g,                            // Stripe
  /\bAIza[0-9A-Za-z_-]{35}\b/g,                                                  // Google API key
  /\bsk-[A-Za-z0-9_-]{20,255}/g,                                                 // OpenAI / Anthropic style
];
var IBAN_RE = /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g;
// How cards are written: 13-19 digits together, 4-digit groups with one consistent separator, or
// Amex 4-6-5. (A looser pattern joined neighbouring numbers, e.g. two SSNs, into a false "card".)
var CARD_RE = /\b(?:\d{13,19}|\d{4}([ -])\d{4}\1\d{4}\1\d{1,7}|\d{4}([ -])\d{6}\2\d{5})\b/g;
var SSN_RE = /\b(\d{3})[- ](\d{2})[- ](\d{4})\b/g;
var ISRAELI_ID_RE = /\b\d{9}\b/g;
var BANK_ACCOUNT_RE = /((?:bank\s{0,3})?(?:account|acct|a\/c|חשבון)(?:\s{0,3}(?:no\.?|number|num|#|מספר))?\s{0,3}[:#]?\s{0,3})(\d[\d -]{4,18}\d)/gi;

/** Cleans the report in place and records what was changed in report.privacy (counts only). */
function sanitizeReport(report) {
  var stats = { urlsReduced: 0, masked: {} };
  var clean = function (text) { return maskSensitive(reduceUrlsInText(text, stats), stats); };

  report.message.subject = clean(report.message.subject);
  report.body.text = clean(report.body.text);
  report.body.html = clean(report.body.html);
  report.links.forEach(function (link) {
    link.url = maskUrl(sanitizeUrl(link.url, stats), stats);
    link.text = clean(link.text);
  });
  report.privacy = stats;  // counts only; shown in the card's Details section
  return report;
}

/** Layer 1: domain only if a query/fragment parameter has a sensitive name, else unchanged. */
function sanitizeUrl(url, stats) {
  var m = URL_PARTS_RE.exec(String(url || ''));
  if (!m) return url;
  var names = [];
  [m[3], m[4]].forEach(function (part) {
    if (!part) return;
    part.slice(1).split('&').forEach(function (pair) {
      names.push(safeDecode(pair.split('=')[0]).replace(/^amp;/i, ''));  // "&amp;" inside HTML
    });
  });
  var sensitive = names.some(function (name) { return name && SENSITIVE_PARAM_RE.test(name); });
  if (!sensitive) return url;
  if (stats) stats.urlsReduced++;
  return m[1] + '/';
}

/** Masks values in a URL's path/query, never in its scheme and host (the rules need the host intact). */
function maskUrl(url, stats) {
  var m = URL_PARTS_RE.exec(String(url || ''));
  if (!m) return maskSensitive(url, stats);
  return m[1] + maskSensitive(url.slice(m[1].length), stats);
}

function reduceUrlsInText(text, stats) {
  return String(text || '').replace(URL_IN_TEXT_RE, function (url) { return sanitizeUrl(url, stats); });
}

/** Layer 2: typed placeholders for sensitive values. Order matters: longer formats first. */
function maskSensitive(text, stats) {
  var out = String(text || '');
  var count = function (kind) { if (stats) stats.masked[kind] = (stats.masked[kind] || 0) + 1; };

  SECRET_PATTERNS.forEach(function (re) {
    out = out.replace(re, function () { count('secret'); return '[secret]'; });
  });
  out = out.replace(IBAN_RE, function (match) {
    if (!validIban(match)) return match;
    count('iban'); return '[iban]';
  });
  out = out.replace(CARD_RE, function (match) {
    var digits = match.replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19 || !luhn(digits)) return match;
    count('credit card'); return '[credit card]';
  });
  out = out.replace(SSN_RE, function (match, area, group, serial) {
    if (area === '000' || area === '666' || area[0] === '9' || group === '00' || serial === '0000') return match;
    count('ssn'); return '[ssn]';
  });
  out = out.replace(ISRAELI_ID_RE, function (match) {
    if (!luhn(match)) return match;  // the Israeli ID check digit is the Luhn algorithm on 9 digits
    count('israeli id'); return '[israeli id]';
  });
  out = out.replace(BANK_ACCOUNT_RE, function (match, prefix) {
    count('bank account'); return prefix + '[bank account]';
  });
  return out;
}

function luhn(digits) {
  var sum = 0;
  for (var i = 0; i < digits.length; i++) {
    var d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return digits.length > 0 && sum % 10 === 0;
}

function validIban(candidate) {
  var iban = candidate.replace(/ /g, '');
  if (iban.length < 15 || iban.length > 34) return false;
  var rearranged = iban.slice(4) + iban.slice(0, 4);
  var remainder = 0;
  for (var i = 0; i < rearranged.length; i++) {
    var c = rearranged.charCodeAt(i);
    var value = c >= 65 ? String(c - 55) : rearranged[i];  // A=10 ... Z=35
    for (var j = 0; j < value.length; j++) remainder = (remainder * 10 + Number(value[j])) % 97;
  }
  return remainder === 1;
}

function safeDecode(s) {
  try { return decodeURIComponent(s); } catch (err) { return s; }
}

/** One line for the card's Details section, e.g. "Masked before sending: 2 credit card, 1 secret; 1 link reduced to its domain". */
function privacySummary(privacy) {
  if (!privacy) return '';
  var parts = Object.keys(privacy.masked || {}).map(function (k) { return privacy.masked[k] + ' ' + k; });
  var text = parts.length ? 'Masked before sending: ' + parts.join(', ') : '';
  if (privacy.urlsReduced) {
    text += (text ? '; ' : 'Before sending: ') + privacy.urlsReduced + ' link(s) with sensitive parameters reduced to their domain';
  }
  return text;
}
