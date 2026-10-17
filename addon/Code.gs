/**
 * PhishNet: Gmail add-on.
 *
 * Flow: user opens email -> buildReport() (Report.gs) -> POST /analyze with a Google identity
 * token -> backend scores it -> resultCard() (Cards.gs).
 */

// The backend's address. Must also be listed in appsscript.json -> urlFetchWhitelist.
var BACKEND_URL = 'https://18-209-193-119.sslip.io';

// Backend rejects bodies over 1 MB; leave headroom for JSON escaping.
var MAX_PAYLOAD_BYTES = 900 * 1024;

/** Shown when the add-on is opened with no email selected. */
function onHomepage() {
  return homepageCard();
}

/** Contextual trigger: runs when the user opens an email. */
function onGmailMessageOpen(e) {
  var report;
  try {
    // The per-message access token grants read access to this one message only.
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    var message = GmailApp.getMessageById(e.gmail.messageId);
    report = buildReport(message, e.gmail.threadId);
  } catch (err) {
    console.error('Failed to read message: ' + err);
    return errorCard('Could not read this email.');
  }

  try {
    return resultCard(analyzeReport(report), report);
  } catch (err) {
    console.error('Analysis failed: ' + err.message);
    return errorCard(err.message);
  }
}

/** "Try again" button on the error card. */
function onRetry(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(onGmailMessageOpen(e)))
    .build();
}

/**
 * Sends the report to the backend and returns the validated result.
 * Authenticates with a Google-signed OpenID Connect token for the current user:
 * no shared secret is stored anywhere in the add-on.
 */
function analyzeReport(report) {
  var payload = JSON.stringify(report);
  if (Utilities.newBlob(payload).getBytes().length > MAX_PAYLOAD_BYTES) {
    // Very large emails: drop the HTML body (the plain-text body and links are kept).
    report.body.html = '';
    report.body.htmlTruncated = true;
    payload = JSON.stringify(report);
  }

  // The response is external input too: validate its shape before rendering it.
  rememberSentReport(payload);  // for "Show what was sent" (Cards.gs); stays in the user's own cache
  var result = callBackend('post', '/analyze', payload);
  if (!isValidResult(result)) {
    throw new Error('The analysis server returned an unexpected response.');
  }
  return result;
}

/** Authenticated request to the backend; returns the parsed JSON body (or null if it isn't JSON). */
function callBackend(method, path, payload) {
  var token = ScriptApp.getIdentityToken();
  if (!token) {
    throw new Error('Could not get your Google identity. Try re-authorizing the add-on.');
  }
  var options = {
    method: method,
    headers: { Authorization: 'Bearer ' + token },
    muteHttpExceptions: true,
    followRedirects: false,
  };
  if (payload !== undefined) {
    options.contentType = 'application/json';
    options.payload = payload;
  }

  var response;
  try {
    response = UrlFetchApp.fetch(BACKEND_URL + path, options);
  } catch (err) {
    throw new Error('The analysis server is unreachable. Try again in a moment.');
  }
  var status = response.getResponseCode();
  if (status !== 200) {
    throw new Error(describeHttpError(status));
  }
  try {
    return JSON.parse(response.getContentText());
  } catch (err) {
    return null;
  }
}

function describeHttpError(status) {
  switch (status) {
    case 401: return 'The analysis server could not verify your identity.';
    case 403: return 'Your Google account is not authorized to use PhishNet.';
    case 413: return 'This email is too large to analyze.';
    case 422: return 'The analysis server rejected the email report.';
    default: return 'The analysis server had a problem (HTTP ' + status + '). Try again in a moment.';
  }
}

function isValidResult(r) {
  return (
    r !== null &&
    typeof r === 'object' &&
    ['safe', 'suspicious', 'malicious'].indexOf(r.verdict) !== -1 &&
    typeof r.score === 'number' &&
    r.score >= 0 &&
    r.score <= 100 &&
    typeof r.summary === 'string' &&
    Array.isArray(r.findings) &&
    (r.notes === undefined || Array.isArray(r.notes))
  );
}

/**
 * Setup helper: run from the Apps Script editor (select it, click Run, open the log).
 * Prints the values the backend needs in ALLOWED_AUDIENCES and ALLOWED_EMAILS.
 * Prints only the token's claims, never the token itself.
 */
function debugIdentityToken() {
  var token = ScriptApp.getIdentityToken();
  if (!token) {
    console.log('No identity token. Check that appsscript.json includes the "openid" scope.');
    return;
  }
  var segment = token.split('.')[1];
  while (segment.length % 4) segment += '=';
  var claims = JSON.parse(Utilities.newBlob(Utilities.base64DecodeWebSafe(segment)).getDataAsString());
  console.log('ALLOWED_AUDIENCES=' + claims.aud);
  console.log('ALLOWED_EMAILS=' + claims.email + '   (email_verified: ' + claims.email_verified + ')');
}
