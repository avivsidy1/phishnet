/**
 * Builds the JSON report sent to the backend.
 *
 * The add-on only collects facts. It does not judge. All interpretation lives in the backend.
 */

var SCHEMA_VERSION = '1.3';  // 1.1 preferences; 1.2 mailbox context; 1.3 masked by Privacy.gs

// Limits keep the payload bounded. Email content is attacker-controlled and can be huge.
var MAX_TEXT_BODY_CHARS = 50000;
var MAX_HTML_BODY_CHARS = 100000;
var MAX_LINKS = 200;
var MAX_URL_CHARS = 2000;
var MAX_LINK_TEXT_CHARS = 300;
var MAX_HEADERS = 200;
var MAX_HEADER_VALUE_CHARS = 2000;
var MAX_HASH_BYTES = 25 * 1024 * 1024;

function buildReport(message, threadId) {
  var raw = message.getRawContent();
  var htmlBody = message.getBody() || '';
  var textBody = message.getPlainBody() || '';
  var headers = parseHeaders(raw);
  var from = parseAddress(message.getFrom());
  var prefs = loadPreferences();

  var report = {
    schemaVersion: SCHEMA_VERSION,
    generatedAt: new Date().toISOString(),
    message: {
      id: message.getId(),
      threadId: threadId,
      date: message.getDate().toISOString(),
      subject: message.getSubject() || '',
      rawSizeBytes: raw.length,
    },
    sender: {
      from: from,
      replyTo: parseAddressList(message.getReplyTo()),
      returnPath: firstHeader(headers, 'Return-Path'),
    },
    recipients: {
      to: parseAddressList(message.getTo()),
      cc: parseAddressList(message.getCc()),
    },
    headers: headers,
    body: {
      text: limitString(textBody, MAX_TEXT_BODY_CHARS),
      textLength: textBody.length,
      textTruncated: textBody.length > MAX_TEXT_BODY_CHARS,
      html: limitString(htmlBody, MAX_HTML_BODY_CHARS),
      htmlLength: htmlBody.length,
      htmlTruncated: htmlBody.length > MAX_HTML_BODY_CHARS,
    },
    links: extractLinks(htmlBody, textBody),
    attachments: extractAttachments(message),
    // The user's own settings (Settings.gs). The backend validates them; they only affect this user.
    preferences: prefs,
  };
  // Derived mailbox facts (Mailbox.gs): only "new" / "established" / "unknown", never content.
  var mailbox = mailboxContext(message, from ? from.address : '', prefs);
  if (mailbox) report.mailbox = mailbox;
  // Privacy (Privacy.gs): reduce links with sensitive parameters, mask sensitive values. Last step,
  // so nothing above sends or keeps unmasked text.
  return sanitizeReport(report);
}

/**
 * Parses the header block of the raw RFC 822 message into an ordered list.
 * Order matters (e.g. the Received chain), and names can repeat, so this is a list, not a map.
 */
function parseHeaders(raw) {
  var end = raw.search(/\r?\n\r?\n/);
  var block = end === -1 ? raw : raw.substring(0, end);
  // Unfold continuation lines (lines starting with whitespace belong to the previous header).
  var unfolded = block.replace(/\r?\n[ \t]+/g, ' ');

  var headers = [];
  unfolded.split(/\r?\n/).forEach(function (line) {
    var idx = line.indexOf(':');
    if (idx <= 0 || headers.length >= MAX_HEADERS) return;
    headers.push({
      name: line.substring(0, idx).trim(),
      value: limitString(line.substring(idx + 1).trim(), MAX_HEADER_VALUE_CHARS),
    });
  });
  return headers;
}

function firstHeader(headers, name) {
  var lower = name.toLowerCase();
  for (var i = 0; i < headers.length; i++) {
    if (headers[i].name.toLowerCase() === lower) return headers[i].value;
  }
  return null;
}

/** "Display Name <user@example.com>" -> { name, address, domain }. */
function parseAddress(value) {
  value = (value || '').trim();
  if (!value) return null;

  var name = '';
  var address = value;
  var angle = value.match(/^(.*)<([^>]*)>\s*$/);
  if (angle) {
    name = angle[1].trim().replace(/^"(.*)"$/, '$1');
    address = angle[2].trim();
  }
  var at = address.lastIndexOf('@');
  return {
    raw: value,
    name: name,
    address: address,
    domain: at === -1 ? null : address.substring(at + 1).toLowerCase(),
  };
}

/** Splits an address list on commas that are not inside quotes or angle brackets. */
function parseAddressList(value) {
  var parts = [];
  var current = '';
  var inQuotes = false;
  var inAngle = false;
  for (var i = 0; i < (value || '').length; i++) {
    var c = value.charAt(i);
    if (c === '"') inQuotes = !inQuotes;
    else if (c === '<' && !inQuotes) inAngle = true;
    else if (c === '>' && !inQuotes) inAngle = false;

    if (c === ',' && !inQuotes && !inAngle) {
      parts.push(current);
      current = '';
    } else {
      current += c;
    }
  }
  parts.push(current);

  return parts
    .map(parseAddress)
    .filter(function (a) { return a !== null; });
}

/**
 * Collects links from <a href> tags (with their visible text, needed to detect
 * text/target mismatch) and bare URLs from the plain-text body.
 * Regex extraction is good enough for collection; the backend does the real URL parsing.
 */
function extractLinks(html, text) {
  var links = [];
  var seen = {};

  function add(url, linkText, source) {
    url = limitString(url, MAX_URL_CHARS);
    linkText = limitString(linkText, MAX_LINK_TEXT_CHARS);
    var key = source + '|' + url + '|' + linkText;
    if (seen[key] || links.length >= MAX_LINKS) return;
    seen[key] = true;
    links.push({ url: url, text: linkText, source: source });
  }

  var anchorRe = /<a\b[^>]*?href\s*=\s*(["'])(.*?)\1[^>]*>([\s\S]*?)<\/a>/gi;
  var m;
  while ((m = anchorRe.exec(html)) !== null) {
    var visible = decodeEntities(m[3].replace(/<[^>]+>/g, '')).replace(/\s+/g, ' ').trim();
    add(decodeEntities(m[2]).trim(), visible, 'html');
  }

  var urlRe = /\bhttps?:\/\/[^\s<>"')\]]+/gi;
  while ((m = urlRe.exec(text)) !== null) {
    add(m[0], '', 'text');
  }
  return links;
}

/** Metadata + SHA-256 only. File contents are never sent; the hash is enough for reputation lookups. */
function extractAttachments(message) {
  return message.getAttachments({ includeInlineImages: false }).map(function (att) {
    var size = att.getSize();
    return {
      filename: att.getName(),
      contentType: att.getContentType(),
      sizeBytes: size,
      sha256: size <= MAX_HASH_BYTES ? sha256Hex(att.getBytes()) : null,
    };
  });
}

function sha256Hex(bytes) {
  return Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes)
    .map(function (b) { return ('0' + (b & 0xff).toString(16)).slice(-2); })
    .join('');
}

function decodeEntities(s) {
  return s
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&amp;/gi, '&');
}
