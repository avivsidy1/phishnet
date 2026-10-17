/**
 * Facts derived from the user's mailbox, for the new_sender rule.
 *
 * Runs two Gmail searches (Gmail API, metadata of at most one message each) and sends the backend
 * only the conclusion: "new", "established" or "unknown". No mailbox content leaves Google.
 *
 * Established = the user has EVER sent mail to the sender (no date limit), OR received mail from
 * them before (this email's date - HISTORY_DAYS). One-way senders such as a bank stop being
 * "new" after 30 days. Accepted trade-offs: an attacker who sent a harmless email more than 30 days
 * earlier (still in the inbox), or whom the user has replied to, is no longer "new" (10 points).
 */

var HISTORY_DAYS = 30;
var HISTORY_CACHE_SECONDS = 6 * 3600;

/** { senderHistory, historyDays } for the report, or null if the user switched new_sender off. */
function mailboxContext(message, address, prefs) {
  if (prefs.disabledRules.indexOf('new_sender') !== -1) {
    return null;  // switched off: don't search the mailbox at all
  }
  return { senderHistory: senderHistory(address, message.getDate()), historyDays: HISTORY_DAYS };
}

function senderHistory(address, messageDate) {
  address = String(address || '').toLowerCase();
  // Strict on purpose (isValidAddress, Validation.gs): the address comes from the attacker-controlled From
  // header and goes into a Gmail search. Spaces, quotes, braces or "OR" could otherwise rewrite the query.
  if (!isValidAddress(address)) return 'unknown';
  if (address === String(Session.getEffectiveUser().getEmail() || '').toLowerCase()) return 'established';

  // Relative to this email's date, so an old email is judged by what came before it,
  // and the email itself never counts as its own history.
  var cutoff = Math.floor(messageDate.getTime() / 1000) - HISTORY_DAYS * 86400;
  var cache = CacheService.getUserCache();
  // v3: ignores answers cached under earlier definitions. Cutoff day: stable for a day.
  var key = 'history3|' + Math.floor(cutoff / 86400) + '|' + address;
  var cached = cache.get(key);
  if (cached) return cached;

  var result;
  try {
    var known = hasMessage('in:sent to:' + address) ||              // ever written to them: no date limit
      hasMessage('from:' + address + ' before:' + cutoff);          // only searched if the first finds nothing
    result = known ? 'established' : 'new';
  } catch (err) {
    console.error('Mailbox search failed: ' + err.message);
    return 'unknown';  // never cached: try again next time
  }
  cache.put(key, result, HISTORY_CACHE_SECONDS);
  return result;
}

/** True if at least one message matches. Spam and Trash are excluded (the API default). */
function hasMessage(query) {
  var response = Gmail.Users.Messages.list('me', { q: query, maxResults: 1, includeSpamTrash: false });
  return Boolean(response.messages && response.messages.length);
}
