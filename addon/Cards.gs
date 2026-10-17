/**
 * Card UI. Everything shown comes from the email or the backend, so all text is
 * HTML-escaped before it is placed in a card.
 */

var VERDICT_STYLES = {
  safe: { label: 'SAFE', icon: '✅', color: '#188038' },
  suspicious: { label: 'SUSPICIOUS', icon: '⚠️', color: '#e37400' },
  malicious: { label: 'MALICIOUS', icon: '⛔', color: '#d93025' },
};
var SEVERITY_COLORS = { high: '#d93025', medium: '#e37400', low: '#5f6368' };
var MUTED = '#5f6368';
// How the score is shown: 'gauge' = animated ring image from the backend (GET /gauge/<score>.gif);
// 'bar' = the original text bar (■■■■□□□). Set to 'bar' to revert; nothing else needs to change.
var SCORE_DISPLAY = 'gauge';
var GAUGE_VERSION = 3;
// "Your settings" section (notes on how the user's settings changed the result). Hidden at the user's
// request; the backend still sends `notes`. Set to true to show it again.
var SHOW_SETTINGS_NOTES = false;
// "Show what was sent" button in Details: the exact report sent, after masking. The copy lives only in the
// user's own Apps Script cache for 10 minutes. Set to false to hide the button.
var SHOW_SENT_REPORT = true;
var SENT_REPORT_CACHE_KEY = 'lastSentReport';
var SENT_REPORT_CACHE_SECONDS = 600;
var SENT_REPORT_MAX_SHOWN_CHARS = 1500;  // per long field (bodies), so the screen stays readable  // bump if the gauge's look changes, so Gmail's image cache fetches the new one

function resultCard(result, report) {
  var style = VERDICT_STYLES[result.verdict];
  var gauge = SCORE_DISPLAY === 'gauge';
  var card = CardService.newCardBuilder();
  if (!gauge) {
    // Original layout (SCORE_DISPLAY = 'bar'): title, subject and "Verdict" label.
    card.setHeader(
      CardService.newCardHeader()
        .setTitle('PhishNet')
        .setSubtitle(limitString(report.message.subject || '(no subject)', 80))
    );
  }

  var verdictSection = CardService.newCardSection();
  if (gauge) {
    // Gauge layout: one image carries the verdict (icon + large word), its range and the
    // animated score; card text can't be enlarged, so the verdict lives in the image. No header.
    verdictSection.addWidget(scoreGauge(result));
  } else {
    verdictSection
      .addWidget(
        CardService.newDecoratedText()
          .setTopLabel('Verdict')
          .setText(style.icon + ' <font color="' + style.color + '"><b>' + style.label + '</b></font>')
          .setBottomLabel('Risk score ' + result.score + ' / 100')
      )
      .addWidget(CardService.newTextParagraph().setText(scoreBar(result.score, style.color)));
  }
  card.addSection(verdictSection.addWidget(CardService.newTextParagraph().setText(escapeHtml(result.summary))));

  // How the user's own settings affected this result (trusted sender, rules turned off, ...).
  var notes = Array.isArray(result.notes) ? result.notes : [];
  if (SHOW_SETTINGS_NOTES && notes.length > 0) {
    card.addSection(
      CardService.newCardSection()
        .setHeader('Your settings')
        .addWidget(CardService.newTextParagraph().setText(
          '<font color="' + MUTED + '">' + notes.map(function (n) { return '• ' + escapeHtml(n); }).join('<br>') + '</font>'
        ))
    );
  }

  if (result.findings.length > 0) {
    // Collapsed by default: the verdict and summary come first; the user expands the reasons
    // with our own button text instead of the generic "Show more".
    var count = result.findings.length;
    var reasons = CardService.newCardSection()
      .setCollapsible(true)
      .setNumUncollapsibleWidgets(0)
      .setCollapseControl(
        CardService.newCollapseControl()
          .setExpandButton(CardService.newTextButton().setText('Show why (' + count + ')'))
          .setCollapseButton(CardService.newTextButton().setText('Hide why'))
      );
    result.findings.forEach(function (finding) {
      reasons.addWidget(CardService.newTextParagraph().setText(findingHtml(finding)));
    });
    card.addSection(reasons);
  }

  card.addSection(senderActionsSection(report));
  card.addSection(detailsSection(result, report));
  return card.build();
}

/** Trust / block the sender's address (or undo), and open the settings. */
function senderActionsSection(report) {
  var from = report.sender && report.sender.from;
  var address = from && from.address ? String(from.address).toLowerCase() : '';
  var buttons = CardService.newButtonSet();

  if (isValidAddress(address)) {  // no Trust/Block for addresses the lists would refuse anyway
    var prefs = loadPreferences();
    var trusted = prefs.trustedSenders.indexOf(address) !== -1;
    var blocked = prefs.blockedSenders.indexOf(address) !== -1;
    buttons.addButton(senderButton(trusted ? 'Remove from trusted' : 'Trust sender', trusted ? 'onUntrustSender' : 'onTrustSender', address));
    buttons.addButton(senderButton(blocked ? 'Remove from blocked' : 'Block sender', blocked ? 'onUnblockSender' : 'onBlockSender', address));
  }
  buttons.addButton(
    CardService.newTextButton().setText('Settings').setOnClickAction(CardService.newAction().setFunctionName('onOpenSettings'))
  );
  return CardService.newCardSection().addWidget(buttons);
}

function senderButton(text, functionName, address) {
  return CardService.newTextButton()
    .setText(text)
    .setOnClickAction(CardService.newAction().setFunctionName(functionName).setParameters({ address: address }));
}

/** The score range of the shown verdict, from the server's thresholds (30 / 70 by default). */
function verdictRange(result) {
  var suspicious = Number(result.suspiciousThreshold) || 30;
  var malicious = Number(result.maliciousThreshold) || 70;
  if (result.verdict === 'malicious') return 'Score ' + malicious + ' or higher';  // same wording as the image
  if (result.verdict === 'suspicious') return 'Score between ' + suspicious + ' and ' + (malicious - 1);
  return 'Score below ' + suspicious;
}

/** Verdict + animated score ring (an image: cards can't run code or enlarge text). Score is 0-100 from a validated result. */
function scoreGauge(result) {
  var safeScore = Math.max(0, Math.min(100, Math.round(Number(result.score))));
  return CardService.newImage()
    .setImageUrl(BACKEND_URL + '/gauge/' + safeScore + '.gif?v=' + GAUGE_VERSION)
    .setAltText(VERDICT_STYLES[result.verdict].label + ', risk score ' + safeScore + ' of 100 (' + verdictRange(result) + ')');
}

/** The original display (SCORE_DISPLAY = 'bar'): a 20-block bar, e.g. ■■■■■■□□□□□□□□□□□□□□ for 30/100. */
function scoreBar(score, color) {
  var filled = Math.round(score / 5);
  return (
    '<font color="' + color + '">' + repeat('■', filled) + '</font>' +
    '<font color="#dadce0">' + repeat('■', 20 - filled) + '</font>'
  );
}

function findingHtml(finding) {
  var color = SEVERITY_COLORS[finding.severity] || MUTED;
  var html =
    '<font color="' + color + '"><b>' + escapeHtml(finding.title) + '</b></font>' +
    ' <font color="' + MUTED + '">+' + Number(finding.score) + '</font><br>' +
    escapeHtml(finding.explanation);

  var evidence = Array.isArray(finding.evidence) ? finding.evidence : [];
  if (evidence.length > 0) {
    html += '<br><font color="' + MUTED + '">' +
      evidence.map(function (e) { return '• ' + escapeHtml(e); }).join('<br>') +
      '</font>';
  }
  return html;
}

function detailsSection(result, report) {
  var lines = ['Rules checked: ' + Number(result.rulesEvaluated)];
  var privacy = privacySummary(report && report.privacy);  // what Privacy.gs masked before sending
  if (privacy) lines.push(escapeHtml(privacy));
  if (Array.isArray(result.rulesFailed) && result.rulesFailed.length > 0) {
    lines.push('Rules that failed to run: ' + escapeHtml(result.rulesFailed.join(', ')));
  }
  lines.push('Score: sum of matched rule points, capped at 100. 30+ is suspicious, 70+ is malicious. ' +
    'Blocked senders always score 100; trusted senders score 0 when Gmail confirms them.');

  var section = CardService.newCardSection()
    .setHeader('Details')
    .setCollapsible(true)
    .addWidget(CardService.newTextParagraph().setText(
      '<font color="' + MUTED + '">' + lines.join('<br>') + '</font>'
    ));
  if (SHOW_SENT_REPORT) {
    section.addWidget(CardService.newTextButton().setText('Show what was sent')
      .setOnClickAction(CardService.newAction().setFunctionName('onShowSentReport')));
  }
  return section;
}

/** Keeps the exact JSON that was sent (already masked) for 10 minutes, in the user's own cache. */
function rememberSentReport(payload) {
  if (!SHOW_SENT_REPORT) return;
  try {
    CacheService.getUserCache().put(SENT_REPORT_CACHE_KEY, payload, SENT_REPORT_CACHE_SECONDS);
  } catch (err) {
    console.error('Could not keep the sent report: ' + err.message);  // e.g. over the 100 KB cache limit
  }
}

/** The sent report, field by field. Long bodies are shortened for display (and say so). */
function sentReportCard() {
  var raw = CacheService.getUserCache().get(SENT_REPORT_CACHE_KEY);
  var report = null;
  try { report = raw ? JSON.parse(raw) : null; } catch (err) { report = null; }

  var section = CardService.newCardSection();
  if (!report) {
    section.addWidget(CardService.newTextParagraph().setText(
      'Nothing to show: the copy is kept for 10 minutes only. Reopen the email and try again.'));
  } else {
    var shown = JSON.parse(JSON.stringify(report));
    var shortened = [];
    [['body', 'text'], ['body', 'html']].forEach(function (key) {
      var value = shown[key[0]] && shown[key[0]][key[1]];
      if (typeof value === 'string' && value.length > SENT_REPORT_MAX_SHOWN_CHARS) {
        shown[key[0]][key[1]] = value.slice(0, SENT_REPORT_MAX_SHOWN_CHARS) + ' …';
        shortened.push(key.join('.') + ' (' + value.length + ' chars)');
      }
    });
    if (Array.isArray(shown.headers) && shown.headers.length > 12) {
      shortened.push('headers (' + shown.headers.length + ', first 12 shown)');
      shown.headers = shown.headers.slice(0, 12);
    }
    section.addWidget(CardService.newTextParagraph().setText(
      '<b>Exactly what was sent to the analysis server</b>, after masking (' + escapeHtml(privacySummary(report.privacy) || 'nothing needed masking') + ').' +
      (shortened.length ? '<br><font color="' + MUTED + '">Shortened here for display only: ' + escapeHtml(shortened.join(', ')) + '</font>' : '')));
    section.addWidget(CardService.newTextParagraph().setText(
      escapeHtml(JSON.stringify(shown, null, 2)).replace(/\n/g, '<br>').replace(/  /g, '&nbsp;&nbsp;')));
  }
  section.addWidget(CardService.newTextButton().setText('Back')
    .setOnClickAction(CardService.newAction().setFunctionName('onBackToResult')));
  return CardService.newCardBuilder().addSection(section).build();
}

function onShowSentReport() {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(sentReportCard()))
    .build();
}

function onBackToResult() {
  return CardService.newActionResponseBuilder().setNavigation(CardService.newNavigation().popCard()).build();
}

function errorCard(message) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('PhishNet'))
    .addSection(
      CardService.newCardSection()
        .addWidget(CardService.newTextParagraph().setText(
          '<b>Couldn\'t analyze this email</b><br>' + escapeHtml(message)
        ))
        .addWidget(
          CardService.newTextButton()
            .setText('Try again')
            .setOnClickAction(CardService.newAction().setFunctionName('onRetry'))
        )
    )
    .build();
}

function homepageCard() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('PhishNet'))
    .addSection(
      CardService.newCardSection()
        .addWidget(CardService.newTextParagraph().setText('Open an email to check it for phishing.'))
        .addWidget(
          CardService.newTextButton().setText('Settings')
            .setOnClickAction(CardService.newAction().setFunctionName('onOpenSettings'))
        )
    )
    .build();
}

function messageCard(title, text) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle(title))
    .addSection(
      CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(escapeHtml(text)))
    )
    .build();
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function limitString(s, n) {
  s = String(s == null ? '' : s);
  return s.length > n ? s.substring(0, n) + '…' : s;
}

function repeat(s, n) {
  return new Array(Math.max(0, n) + 1).join(s);
}
