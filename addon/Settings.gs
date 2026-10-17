/**
 * The user's own settings: rules turned off, trusted senders, blocked senders.
 *
 * Stored per user by Google (Apps Script user properties) and sent with every report. Everything
 * here is untrusted (typed input, click values, storage): it all goes through Validation.gs,
 * and the backend validates it again.
 */

// Settings layout: 'compact' = no header, rules without points, an (i) per rule that opens a
// description screen; 'classic' = the previous layout (header, "+N points" under each rule). Set to
// 'classic' to revert; nothing else needs to change.
var SETTINGS_STYLE = 'compact';
var INFO_ICON_URL = 'https://www.gstatic.com/images/icons/material/system/2x/info_outline_grey600_24dp.png';
var REMOVE_ICON_URL = 'https://www.gstatic.com/images/icons/material/system/2x/close_grey600_24dp.png';

/** Section heading: bold and dark in the compact layout, plain in the classic one. */
function sectionHeader(text) {
  return SETTINGS_STYLE === 'compact' ? '<font color="#202124"><b>' + escapeHtml(text) + '</b></font>' : escapeHtml(text);
}
var CATEGORY_ORDER = ['authentication', 'sender', 'domain', 'links', 'attachments', 'content'];
var CATEGORY_LABELS = {
  authentication: 'Authentication',
  sender: 'Sender',
  domain: 'Domains',
  links: 'Links',
  attachments: 'Attachments',
  content: 'Content',
};
// Rule ids and titles from the last GET /rules, so a click can only toggle a rule the server listed.
var KNOWN_RULES_CACHE_KEY = 'knownRules';

// --- Storage -------------------------------------------------------------------------------

/** Settings from storage, re-validated every time (storage is input too: old versions, manual edits). */
function loadPreferences() {
  var props = PropertiesService.getUserProperties();
  var stored = {
    disabledRules: readList(props, 'disabledRules'),
    trustedSenders: readList(props, 'trustedSenders'),
    blockedSenders: readList(props, 'blockedSenders'),
    trustedExtensions: readList(props, 'trustedExtensions'),
  };
  var clean = cleanPreferences(stored);
  if (JSON.stringify(clean) !== JSON.stringify(stored)) savePreferences(clean);  // drop what didn't pass
  return clean;
}

function savePreferences(prefs) {
  prefs = cleanPreferences(prefs);  // never store anything that didn't pass validation
  PropertiesService.getUserProperties().setProperties({
    disabledRules: JSON.stringify(prefs.disabledRules),
    trustedSenders: JSON.stringify(prefs.trustedSenders.slice(0, MAX_LIST_ENTRIES)),
    blockedSenders: JSON.stringify(prefs.blockedSenders.slice(0, MAX_LIST_ENTRIES)),
    trustedExtensions: JSON.stringify(prefs.trustedExtensions),
  });
}

function readList(props, key) {
  try {
    var value = JSON.parse(props.getProperty(key) || '[]');
    return Array.isArray(value) ? value : [];
  } catch (err) {
    return [];
  }
}

/** Splits user input into valid entries; returns { entries, rejected: [human-readable reasons] }. */
function parseEntries(text, allowFreeMailDomains) {
  var entries = [];
  var rejected = [];
  String(text || '').slice(0, 20000).split(/[\s,;]+/).forEach(function (raw) {
    if (!raw) return;
    var checked = validateEntry(raw, allowFreeMailDomains);
    if (!checked.entry) {
      if (checked.reason !== 'empty') rejected.push(raw.slice(0, 60).replace(INVISIBLE_RE, '?') + ' (' + checked.reason + ')');
    } else if (entries.indexOf(checked.entry) === -1) {
      entries.push(checked.entry);
    }
  });
  if (entries.length > MAX_LIST_ENTRIES) {
    rejected.push((entries.length - MAX_LIST_ENTRIES) + ' entries over the limit of ' + MAX_LIST_ENTRIES);
    entries = entries.slice(0, MAX_LIST_ENTRIES);
  }
  return { entries: entries, rejected: rejected };
}

// --- Settings card -------------------------------------------------------------------------

function settingsCard(message, expandedRuleId) {
  var prefs = loadPreferences();
  var rules = null;
  try {
    rules = callBackend('get', '/rules');
  } catch (err) {
    console.error('Could not load rules: ' + err.message);
  }
  if (!Array.isArray(rules)) rules = null;
  if (rules) rules = rules.filter(function (r) { return r && isValidRuleId(r.id); });  // server data: checked too
  rememberKnownRules(rules);

  var compact = SETTINGS_STYLE === 'compact';
  var card = CardService.newCardBuilder();
  if (!compact) {
    card.setHeader(CardService.newCardHeader().setTitle('PhishNet settings').setSubtitle('Only affect your own results'));
  }
  if (message) {
    card.addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(escapeHtml(message))));
  }

  if (rules) {
    CATEGORY_ORDER.concat(otherCategories(rules)).forEach(function (category) {
      var inCategory = rules.filter(function (r) { return r && r.category === category; });
      if (inCategory.length === 0) return;
      var section = CardService.newCardSection().setHeader(sectionHeader(CATEGORY_LABELS[category] || category));
      inCategory.forEach(function (rule) {
        var row = CardService.newDecoratedText()
          .setText(escapeHtml(rule.title))
          .setWrapText(true);  // show the full rule name, not "Domain flagged as mali…"
        if (compact) {
          // (i): tapping the rule shows its description right under it, tapping again hides it.
          // Cards have no tooltips, so this is the closest equivalent. The switch still toggles the rule.
          row.setStartIcon(CardService.newIconImage().setIconUrl(INFO_ICON_URL).setAltText('About this rule'))
            .setOnClickAction(CardService.newAction().setFunctionName('onRuleInfo').setParameters({
              ruleId: String(rule.id),
              open: expandedRuleId === rule.id ? 'yes' : '',
            }));
        } else {
          row.setBottomLabel('+' + Number(rule.score) + ' points' +
            (rule.id === 'new_sender' ? ' · searches your mailbox in Google; only "new or not" is sent' : ''));
        }
        if (rule.canDisable) {
          row.setSwitchControl(
            CardService.newSwitch()
              .setFieldName('rule_' + rule.id)
              .setValue('on')
              .setSelected(prefs.disabledRules.indexOf(rule.id) === -1)
              .setOnChangeAction(CardService.newAction().setFunctionName('onToggleRule')
                .setParameters({ ruleId: String(rule.id), title: String(rule.title) }))
          );
        } else {
          row.setBottomLabel(compact ? 'Always on' : '+' + Number(rule.score) + ' points · always on (uses your blocklist)');
        }
        section.addWidget(row);
        if (compact && expandedRuleId === rule.id) section.addWidget(ruleDetails(rule));
      });
      card.addSection(section);
    });
  } else {
    card.addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(
      'Couldn\'t load the rule list from the server, so rule switches are unavailable right now. ' +
      'Your trusted and blocked senders can still be edited.'
    )));
  }

  card.addSection(listSection(
    'trusted', 'Trusted senders', prefs.trustedSenders,
    'Always score 0, but only when Gmail confirms the sender (DMARC). A domain covers its subdomains. ' +
    'Free-mail domains such as gmail.com need full addresses.'
  ));
  card.addSection(listSection(
    'blocked', 'Blocked senders', prefs.blockedSenders,
    'Always score 100 (malicious). Wins over the trusted list.'
  ));
  card.addSection(listSection(
    'extensions', 'Trusted file types', prefs.trustedExtensions,
    'Attachments of these types are not flagged for their type. A disguised name (invoice.pdf.html) is ' +
    'still flagged, and so is known malware (VirusTotal).'
  ));

  card.addSection(
    CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(
        '<font color="' + MUTED + '">Changes are saved immediately and apply to the next email you open.</font>'
      ))
      .addWidget(CardService.newTextButton().setText('Reset to defaults')
        .setOnClickAction(CardService.newAction().setFunctionName('onResetSettings')))
  );
  return card.build();
}

/** One list: its entries, each with a remove (✕) button, then a field and an Add button. */
function listSection(list, title, entries, help) {
  var compact = SETTINGS_STYLE === 'compact';
  var section = CardService.newCardSection()
    .setHeader(sectionHeader(title + ' (' + entries.length + ')'))
    .addWidget(CardService.newTextParagraph().setText('<font color="' + MUTED + '">' + escapeHtml(help) + '</font>'));

  var input = [
    CardService.newTextInput().setFieldName('new_' + list).setTitle(list === 'extensions' ? 'File type' : 'Address or domain')
      .setHint(list === 'trusted' ? 'e.g. friend@gmail.com or mycompany.com'
        : list === 'blocked' ? 'e.g. scam@shop.com or scam-shop.com' : 'e.g. html or docm'),
    CardService.newTextButton().setText('Add')
      .setOnClickAction(CardService.newAction().setFunctionName('onAddEntry').setParameters({ list: list })),
  ];
  // Compact: description, then the input, then the entries. Classic: entries before the input.
  if (compact) {
    input.forEach(function (w) { section.addWidget(w); });
    section.addWidget(CardService.newTextParagraph().setText(' '));  // a little space before the list
  }

  if (entries.length === 0) {
    section.addWidget(CardService.newTextParagraph().setText('<font color="' + MUTED + '"><i>None yet.</i></font>'));
  }
  entries.forEach(function (entry) {
    var removeAction = CardService.newAction().setFunctionName('onRemoveEntry').setParameters({ list: list, entry: entry });
    // Compact: a borderless icon button and the entry in bold. Classic: bordered text "✕".
    var remove = compact
      ? CardService.newImageButton().setIconUrl(REMOVE_ICON_URL).setAltText('Remove ' + entry).setOnClickAction(removeAction)
      : CardService.newTextButton().setText('✕').setOnClickAction(removeAction);
    var label = compact ? '<b>' + escapeHtml(entry) + '</b>' : escapeHtml(entry);
    section.addWidget(CardService.newDecoratedText().setText(label).setWrapText(true).setButton(remove));
  });

  if (!compact) input.forEach(function (w) { section.addWidget(w); });
  return section;
}

/** The description shown under an expanded rule: what it detects and how many points it adds. */
function ruleDetails(rule) {
  var lines = [
    escapeHtml(rule.description || 'No description available.'),
    '<b>Adds +' + Number(rule.score) + ' points</b> to the risk score when it fires.',
  ];
  if (!rule.canDisable) lines.push('Always on: it is controlled by your blocked senders list.');
  return CardService.newTextParagraph().setText('<font color="' + MUTED + '">' + lines.join('<br>') + '</font>');
}

/** Tap on a rule: show its details inline, or hide them if they are already shown. */
function onRuleInfo(e) {
  var params = (e.commonEventObject || {}).parameters || {};
  var ruleId = isValidRuleId(params.ruleId) && !params.open ? params.ruleId : '';  // click values are input too
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(settingsCard(null, ruleId)))
    .build();
}

/** Remembers which rule ids the server listed (and their titles), for validating switch clicks. */
function rememberKnownRules(rules) {
  if (!rules) return;
  var map = {};
  rules.forEach(function (r) { map[r.id] = String(r.title || r.id).slice(0, 200); });
  try { CacheService.getUserCache().put(KNOWN_RULES_CACHE_KEY, JSON.stringify(map), 6 * 3600); } catch (err) {}
}

function knownRules() {
  try { return JSON.parse(CacheService.getUserCache().get(KNOWN_RULES_CACHE_KEY) || 'null'); } catch (err) { return null; }
}

function otherCategories(rules) {
  var seen = [];
  rules.forEach(function (r) {
    if (r && CATEGORY_ORDER.indexOf(r.category) === -1 && seen.indexOf(r.category) === -1) seen.push(r.category);
  });
  return seen;
}

// --- Actions -------------------------------------------------------------------------------

/** "Settings" in the add-on's menu (universal action). */
function onSettingsUniversal() {
  return CardService.newUniversalActionResponseBuilder().displayAddOnCards([settingsCard()]).build();
}

/** "Settings" button on the result and home cards. */
function onOpenSettings() {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(settingsCard()))
    .build();
}

var LIST_KEYS = { trusted: 'trustedSenders', blocked: 'blockedSenders', extensions: 'trustedExtensions' };
var LIST_NAMES = { trusted: 'trusted senders', blocked: 'blocked senders', extensions: 'trusted file types' };

/** A rule switch was flipped: save it right away. */
function onToggleRule(e) {
  var event = e.commonEventObject || {};
  var ruleId = (event.parameters || {}).ruleId;
  var known = knownRules();
  // Only a well-formed id that the server actually returned. If the remembered list expired, refuse:
  // reopening Settings fetches it again (no "probably fine" fallback for client data).
  if (!isValidRuleId(ruleId) || !known || !Object.prototype.hasOwnProperty.call(known, ruleId)) {
    return notify('Unknown rule; reopen Settings.');
  }
  var on = inputValue((event.formInputs || {})['rule_' + ruleId]) === 'on';
  var prefs = loadPreferences();
  prefs.disabledRules = without(prefs.disabledRules, ruleId);
  if (!on) prefs.disabledRules.push(ruleId);
  savePreferences(prefs);
  var title = known[ruleId];  // our own copy, not the click's parameter
  return notify((on ? 'Turned on: ' : 'Turned off: ') + title);
}

/** "Add" under a list. Invalid entries are refused with the reason; the typed text stays. */
function onAddEntry(e) {
  var event = e.commonEventObject || {};
  var list = (event.parameters || {}).list;
  if (!Object.prototype.hasOwnProperty.call(LIST_KEYS, list)) return notify('Unknown list.');
  var typed = inputValue((event.formInputs || {})['new_' + list]);
  if (list === 'extensions') return addExtensions(typed);
  var parsed = parseEntries(typed, list === 'blocked');
  if (parsed.rejected.length) return notify('Not added: ' + parsed.rejected[0]);
  if (parsed.entries.length === 0) return notify('Type an email address or a domain first.');

  var prefs = loadPreferences();
  var other = list === 'trusted' ? 'blocked' : 'trusted';
  var added = [];
  parsed.entries.forEach(function (entry) {
    prefs[LIST_KEYS[other]] = without(prefs[LIST_KEYS[other]], entry);  // an entry is in one list only
    if (prefs[LIST_KEYS[list]].indexOf(entry) === -1) {
      prefs[LIST_KEYS[list]].push(entry);
      added.push(entry);
    }
  });
  if (added.length === 0) return notify('Already in your ' + LIST_NAMES[list] + '.');
  if (prefs[LIST_KEYS[list]].length > MAX_LIST_ENTRIES) {
    return notify('Your ' + LIST_NAMES[list] + ' list is full (' + MAX_LIST_ENTRIES + ' entries).');
  }
  savePreferences(prefs);
  return notifyAndRefresh('Added ' + added.join(', ') + ' to your ' + LIST_NAMES[list]);
}

/** "✕" next to an entry. */
/** "Add" under Trusted file types: each typed type validated (Validation.gs). */
function addExtensions(typed) {
  var prefs = loadPreferences();
  var added = [];
  var parts = String(typed || '').slice(0, 2000).split(/[\s,;]+/).filter(function (p) { return p; });
  if (parts.length === 0) return notify('Type a file type first, like html.');
  for (var i = 0; i < parts.length; i++) {
    var checked = validateExtension(parts[i]);
    if (!checked.entry) return notify('Not added: ' + parts[i].slice(0, 20).replace(INVISIBLE_RE, '?') + ' (' + checked.reason + ')');
    if (prefs.trustedExtensions.indexOf(checked.entry) === -1) {
      prefs.trustedExtensions.push(checked.entry);
      added.push(checked.entry);
    }
  }
  if (added.length === 0) return notify('Already in your trusted file types.');
  if (prefs.trustedExtensions.length > MAX_TRUSTED_EXTENSIONS) {
    return notify('Your trusted file types list is full (' + MAX_TRUSTED_EXTENSIONS + ').');
  }
  savePreferences(prefs);
  return notifyAndRefresh('Added ' + added.map(function (x) { return '.' + x; }).join(', ') + ' to your trusted file types');
}

function onRemoveEntry(e) {
  var params = (e.commonEventObject || {}).parameters || {};
  if (!Object.prototype.hasOwnProperty.call(LIST_KEYS, params.list)) return notify('Unknown list.');
  var entry = params.list === 'extensions'  // click values are input too
    ? validateExtension(params.entry).entry
    : validateEntry(params.entry, true).entry;
  if (!entry) return notify('Nothing to remove.');
  var prefs = loadPreferences();
  prefs[LIST_KEYS[params.list]] = without(prefs[LIST_KEYS[params.list]], entry);
  savePreferences(prefs);
  return notifyAndRefresh('Removed ' + entry + ' from your ' + LIST_NAMES[params.list]);
}

function notify(text) {
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(text))
    .build();
}

function notifyAndRefresh(text) {
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(text))
    .setNavigation(CardService.newNavigation().updateCard(settingsCard()))
    .build();
}

function onResetSettings() {
  savePreferences({ disabledRules: [], trustedSenders: [], blockedSenders: [], trustedExtensions: [] });
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText('Settings reset to defaults'))
    .setNavigation(CardService.newNavigation().updateCard(settingsCard('All rules on, all lists empty.')))
    .build();
}

/** Result-card buttons: trust, block, or remove the sender's address, then re-check the email. */
function onTrustSender(e) { return updateSenderLists(e, 'trust'); }
function onBlockSender(e) { return updateSenderLists(e, 'block'); }
function onUntrustSender(e) { return updateSenderLists(e, 'untrust'); }
function onUnblockSender(e) { return updateSenderLists(e, 'unblock'); }

function updateSenderLists(e, change) {
  // The address comes from the email's From header (attacker-written) via a click value: validate it.
  var address = String(((e.commonEventObject || {}).parameters || {}).address || '').trim().toLowerCase();
  if (!isValidAddress(address) || ['trust', 'block', 'untrust', 'unblock'].indexOf(change) === -1) {
    return notify("This sender's address has unusual characters and can't be added. You can add its domain in Settings.");
  }
  var prefs = loadPreferences();
  prefs.trustedSenders = without(prefs.trustedSenders, address);
  prefs.blockedSenders = without(prefs.blockedSenders, address);
  if (change === 'trust') prefs.trustedSenders.push(address);
  if (change === 'block') prefs.blockedSenders.push(address);
  savePreferences(prefs);

  var texts = {
    trust: 'Trusted ' + address,
    block: 'Blocked ' + address,
    untrust: 'Removed ' + address + ' from trusted senders',
    unblock: 'Removed ' + address + ' from blocked senders',
  };
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(texts[change]))
    .setNavigation(CardService.newNavigation().updateCard(onGmailMessageOpen(e)))
    .build();
}

function without(list, value) {
  return list.filter(function (item) { return item !== value; });
}

/** First value of a card form input (switch or text field). */
function inputValue(input) {
  var values = input && input.stringInputs && input.stringInputs.value;
  return values && values.length ? values[0] : '';
}
