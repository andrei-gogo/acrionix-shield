// Secrets must never reach CLI output, JSON output or CI logs.
// Keep a short prefix so the finding can still be located, plus the length.
function redactSecret(value) {
  const str = String(value);
  const keep = Math.min(4, Math.floor(str.length / 4));
  return `${str.slice(0, keep)}…[redacted ${str.length} chars]`;
}

// Strips credentials from a URL while keeping the scheme, host and path needed to investigate.
// Userinfo is masked and the whole query string and fragment are dropped: tokens can hide
// under any parameter name, so no allow-list of "sensitive" keys is trusted.
function redactUrl(value) {
  const str = String(value);
  let url;
  try {
    url = new URL(str);
  } catch {
    // Not parseable: strip anything that looks like userinfo, a query string or a fragment
    return str.replace(/\/\/[^/@\s]*@/, '//***@').replace(/[?#].*$/, '');
  }
  if (url.username || url.password) {
    url.username = '***';
    url.password = '';
  }
  url.search = '';
  url.hash = '';
  return url.toString();
}

module.exports = { redactSecret, redactUrl };
