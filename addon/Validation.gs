/**
 * One definition of "valid" for everything the add-on stores or sends that came from outside.
 *
 * All client-side data is untrusted: what the user types, what comes back from a card click, what is
 * read back from storage, and addresses taken from an email's (attacker-written) From header. Every one
 * of those passes through these functions. The backend applies the same rules (engine/sender_lists.py,
 * models.py) and never relies on this side having done it.
 */

var MAX_LIST_ENTRIES = 200;
var MAX_DISABLED_RULES = 100;
var MAX_TRUSTED_EXTENSIONS = 50;
// Local part: letters, digits and ._%+- only (no quotes, brackets, spaces, control or invisible characters).
var ADDRESS_RE = /^[a-z0-9._%+-]{1,64}@((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})$/;
var DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
var RULE_ID_RE = /^[a-z][a-z0-9_]{0,63}$/;
var EXTENSION_RE = /^[a-z0-9]{1,10}$/;  // a file type without the dot: html, docm
// Control characters, zero-width characters, bidi overrides/isolates and the BOM: never valid in an entry.
var INVISIBLE_RE = /[\u0000-\u001f\u007f-\u009f\u00ad\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/;
// Same list as the backend (engine/sender_lists.py): trusting one of these whole domains would
// trust every account on it, so only full addresses are accepted for them.
var FREE_MAIL_DOMAINS = [
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
  'yahoo.com', 'ymail.com', 'aol.com', 'icloud.com', 'me.com', 'mac.com', 'proton.me',
  'protonmail.com', 'gmx.com', 'gmx.net', 'mail.com', 'yandex.com', 'yandex.ru', 'mail.ru',
  'zoho.com', 'web.de', 'qq.com', '163.com',
];

/**
 * Checks one trusted/blocked entry (an address, or a domain covering its subdomains).
 * Returns { entry: normalized value or '', reason: why it was refused or '' }.
 */
function validateEntry(raw, allowFreeMailDomains) {
  if (typeof raw !== 'string') return { entry: '', reason: 'not text' };
  if (INVISIBLE_RE.test(raw)) return { entry: '', reason: 'contains control or invisible characters' };
  var entry = raw.trim().toLowerCase();
  if (!entry) return { entry: '', reason: 'empty' };
  if (entry.length > 254) return { entry: '', reason: 'too long' };
  if (ADDRESS_RE.test(entry)) return { entry: entry, reason: '' };
  if (DOMAIN_RE.test(entry) && entry.length <= 253) {
    if (!allowFreeMailDomains && FREE_MAIL_DOMAINS.indexOf(entry) !== -1) {
      return { entry: '', reason: 'a whole free-mail domain can\'t be trusted: add full addresses' };
    }
    return { entry: entry, reason: '' };
  }
  return { entry: '', reason: 'not a valid email address or domain' };
}

/** A plain email address only (Trust/Block buttons, mailbox search). */
function isValidAddress(raw) {
  return typeof raw === 'string' && !INVISIBLE_RE.test(raw) && raw.length <= 254 && ADDRESS_RE.test(raw);
}

function isValidRuleId(raw) {
  return typeof raw === 'string' && RULE_ID_RE.test(raw);
}

/** Cleans a list from storage or elsewhere: keeps valid, normalized, unique entries, at most `max`. */
function cleanEntries(list, allowFreeMailDomains, max) {
  var out = [];
  (Array.isArray(list) ? list : []).forEach(function (raw) {
    var checked = validateEntry(raw, allowFreeMailDomains);
    if (checked.entry && out.indexOf(checked.entry) === -1 && out.length < max) out.push(checked.entry);
  });
  return out;
}

/** One trusted file type: "html", ".HTML" or " docm " become "html" / "docm". Returns { entry, reason }. */
function validateExtension(raw) {
  if (typeof raw !== 'string') return { entry: '', reason: 'not text' };
  if (INVISIBLE_RE.test(raw)) return { entry: '', reason: 'contains control or invisible characters' };
  var ext = raw.trim().toLowerCase().replace(/^\./, '');
  if (!ext) return { entry: '', reason: 'empty' };
  if (!EXTENSION_RE.test(ext)) return { entry: '', reason: 'a file type is 1-10 letters or digits, like html or docm' };
  return { entry: ext, reason: '' };
}

function cleanExtensions(list) {
  var out = [];
  (Array.isArray(list) ? list : []).forEach(function (raw) {
    var ext = validateExtension(raw).entry;
    if (ext && out.indexOf(ext) === -1 && out.length < MAX_TRUSTED_EXTENSIONS) out.push(ext);
  });
  return out;
}

function cleanRuleIds(list) {
  var out = [];
  (Array.isArray(list) ? list : []).forEach(function (id) {
    if (isValidRuleId(id) && out.indexOf(id) === -1 && out.length < MAX_DISABLED_RULES) out.push(id);
  });
  return out;
}

/** Whole preferences object, as read from storage: everything re-validated. */
function cleanPreferences(prefs) {
  prefs = prefs || {};
  return {
    disabledRules: cleanRuleIds(prefs.disabledRules),
    trustedSenders: cleanEntries(prefs.trustedSenders, false, MAX_LIST_ENTRIES),
    blockedSenders: cleanEntries(prefs.blockedSenders, true, MAX_LIST_ENTRIES),
    trustedExtensions: cleanExtensions(prefs.trustedExtensions),
  };
}
