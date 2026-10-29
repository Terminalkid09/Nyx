'use strict';

const page        = document.getElementById('page');
const urlInput    = document.getElementById('url-input');
const backBtn     = document.getElementById('back-btn');
const forwardBtn  = document.getElementById('forward-btn');
const refreshBtn  = document.getElementById('refresh-btn');
const loadingBar  = document.getElementById('loading-bar');
const statusText  = document.getElementById('status-text');
const errOverlay  = document.getElementById('error-overlay');
const errTitle    = document.getElementById('err-title');
const errDesc     = document.getElementById('err-desc');
const errCode     = document.getElementById('err-code');
const errTips     = document.getElementById('err-tips');
const lockIcon    = document.getElementById('lock-icon');
const btnRetry    = document.getElementById('btn-retry');
const captureBadge = document.getElementById('capture-badge');
const proxyIndicator = document.getElementById('proxy-indicator');
const proxyDot = document.getElementById('proxy-dot');
const proxyPortText = document.getElementById('proxy-port-text');

// ─── Error codes ───────────────────────────────────────────────────────────
const ERROR_MAP = {
  '-2':   { title: 'Connection Failed',        desc: 'The server refused the connection. It may be offline or blocking requests.' },
  '-3':   { title: 'DNS Lookup Failed',         desc: 'The domain name could not be resolved. Check your connection or DNS settings.' },
  '-6':   { title: 'Connection Timed Out',      desc: 'The server took too long to respond.' },
  '-7':   { title: 'Proxy Connection Error',    desc: 'Nyx proxy (127.0.0.1:8080) could not be reached. Make sure the backend is running.' },
  '-105': { title: 'Name Not Resolved',         desc: 'Could not resolve the hostname. Check your spelling or network connection.' },
  '-106': { title: 'No Internet Connection',    desc: 'Your machine appears to be offline.' },
  '-109': { title: 'Address Unreachable',       desc: 'The IP address of the server could not be reached.' },
  '-201': { title: 'SSL Certificate Error',     desc: 'The site\'s certificate is invalid or untrusted. The Nyx CA may not be installed.' },
  '-202': { title: 'SSL Certificate Revoked',   desc: 'The site\'s SSL certificate has been revoked.' },
  '-200': { title: 'SSL Connection Error',      desc: 'A secure connection could not be established.' },
  '-300': { title: 'Invalid URL',               desc: 'The URL you entered is not valid.' },
  '-310': { title: 'Too Many Redirects',        desc: 'This page redirected too many times.' },
  '-21':  { title: 'Network Changed',           desc: 'Your network connection changed while loading the page.' },
};

const PROXY_TIPS = `<p><strong>Tip:</strong> For HTTP sites (non-HTTPS) traffic is fully intercepted and visible in Proxy Log.</p>
<p><strong>Tip:</strong> For HTTPS, install the Nyx CA certificate on the target device to decrypt content.</p>`;

// ─── Proxy state ───────────────────────────────────────────────────────────
// The badge used to claim "PROXIED" unconditionally. A pentester who forgot
// to enable capture (or whose TLS MITM was off) saw traffic labelled as
// intercepted while the browser was going direct — a wrong mental model of
// what ends up in the Proxy Log.
function applyProxyState(state) {
  if (!state) return;
  const capture = state.capture === true;
  const tls = state.tlsMitm !== false;
  // The proxy port is not fixed: the shell moves it when 8080 is busy.
  const proxyAddr = `127.0.0.1:${state.proxyPort || 8080}`;
  if (proxyPortText) proxyPortText.textContent = proxyAddr;
  if (capture) {
    captureBadge.textContent = tls ? '⬤ PROXIED + TLS' : '⬤ PROXIED (HTTP only)';
    captureBadge.title = tls
      ? `HTTP and HTTPS traffic go through Nyx on ${proxyAddr} and is decrypted`
      : 'Only HTTP is proxied: the Nyx CA is not trusted, so HTTPS goes direct';
    captureBadge.style.color = '#a855f7';
    captureBadge.style.opacity = '1';
    proxyDot.style.background = '#a855f7';
    proxyDot.style.boxShadow = '0 0 6px #a855f7';
  } else {
    captureBadge.textContent = '○ NOT CAPTURED';
    captureBadge.title = 'Capture is off: this window browses directly, nothing reaches the Proxy Log';
    captureBadge.style.color = '#64748b';
    captureBadge.style.opacity = '.9';
    proxyDot.style.background = '#475569';
    proxyDot.style.boxShadow = 'none';
  }
  proxyIndicator.title = capture ? 'Nyx proxy active' : 'Nyx proxy bypassed (direct connection)';
}

function refreshProxyState() {
  if (window.nyxBrowser && window.nyxBrowser.getProxyState) {
    window.nyxBrowser.getProxyState().then(applyProxyState).catch(() => {});
  }
}

if (window.nyxBrowser && window.nyxBrowser.onProxyState) {
  window.nyxBrowser.onProxyState(applyProxyState);
}

// ─── Helpers ───────────────────────────────────────────────────────────────
let currentUrl = '';

function flash(el) {
  el.classList.add('flash');
  setTimeout(() => el.classList.remove('flash'), 180);
}

function setLoading(active) {
  if (active) loadingBar.classList.add('active');
  else        loadingBar.classList.remove('active');
}

function updateNavButtons() {
  try {
    backBtn.disabled    = !page.canGoBack();
    forwardBtn.disabled = !page.canGoForward();
  } catch {}
}

function hideError() {
  errOverlay.classList.remove('visible');
}

function showError(code, description, failedUrl) {
  setLoading(false);
  const info = ERROR_MAP[String(code)] || { title: 'Page Load Error', desc: description || 'An unknown error occurred.' };

  errTitle.textContent = info.title;
  errDesc.textContent  = info.desc;
  errCode.textContent  = `Error ${code}: ${description || 'ERR_UNKNOWN'}`;

  // Proxy-specific advice
  const isProxyErr = ['-7', '-105', '-106'].includes(String(code));
  const isSSLErr   = ['-200', '-201', '-202'].includes(String(code));

  let tips = '';
  if (isProxyErr || isSSLErr) tips = PROXY_TIPS;
  if (isSSLErr) tips += `<p style="margin-top:6px;color:#f59e0b">⚠ Install the Nyx CA cert from Dashboard → CA Certificate to decrypt HTTPS.</p>`;

  errTips.innerHTML = tips;

  btnRetry._failedUrl = failedUrl || currentUrl;
  errOverlay.classList.add('visible');
  statusText.textContent = `⚠ ${info.title}`;
  lockIcon.textContent = '⚠';
  lockIcon.className   = 'error';
}

// A host (optionally with port or path) that should be navigated to rather
// than searched: domain names and IPv4/IPv6, including "192.168.1.1:8080".
const HOST_LIKE = /^(?:\[[0-9a-f:]+\]|localhost|(?:\d{1,3}\.){3}\d{1,3}|[\w-]+(?:\.[\w-]+)+)(?::\d{1,5})?(?:[\/?#].*)?$/i;

function navigate(url) {
  let finalUrl = url.trim();
  if (!finalUrl) return;
  if (!/^https?:\/\//i.test(finalUrl)) {
    if (HOST_LIKE.test(finalUrl)) {
      // Loopback/LAN targets are usually HTTP-only test apps; anything else
      // is better reached over HTTPS first.
      const isLocal = /^(?:localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|\[::1\])/i.test(finalUrl);
      finalUrl = (isLocal ? 'http://' : 'https://') + finalUrl;
    } else {
      finalUrl = 'https://www.google.com/search?q=' + encodeURIComponent(finalUrl);
    }
  }
  hideError();
  statusText.textContent = 'Navigating…';
  setLoading(true);
  currentUrl = finalUrl;
  urlInput.value = finalUrl;
  try { page.loadURL(finalUrl); } catch(e) { showError(0, e.message, finalUrl); }
}

// ─── Retry button ──────────────────────────────────────────────────────────
btnRetry.addEventListener('click', () => {
  const url = btnRetry._failedUrl || urlInput.value;
  if (url) navigate(url);
});

// ─── URL bar ───────────────────────────────────────────────────────────────
urlInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    navigate(urlInput.value);
  }
  if (e.key === 'Escape') urlInput.blur();
});

urlInput.addEventListener('focus', () => urlInput.select());

// ─── Nav buttons ───────────────────────────────────────────────────────────
backBtn.addEventListener('click', () => {
  flash(backBtn); hideError(); setLoading(true);
  statusText.textContent = 'Going back…';
  try { page.goBack(); } catch {}
});

forwardBtn.addEventListener('click', () => {
  flash(forwardBtn); hideError(); setLoading(true);
  statusText.textContent = 'Going forward…';
  try { page.goForward(); } catch {}
});

refreshBtn.addEventListener('click', () => {
  flash(refreshBtn); hideError(); setLoading(true);
  statusText.textContent = 'Refreshing…';
  try { page.reload(); } catch {}
});

// ─── Webview events ────────────────────────────────────────────────────────
page.addEventListener('did-start-loading', () => {
  hideError();
  setLoading(true);
  statusText.textContent = 'Loading…';
  lockIcon.textContent = '🔒';
  lockIcon.className   = '';
});

page.addEventListener('did-stop-loading', () => {
  setLoading(false);
  statusText.textContent = 'Done';
  updateNavButtons();
});

page.addEventListener('did-navigate', (e) => {
  currentUrl = e.url;
  urlInput.value = e.url;
  statusText.textContent = e.url;
  hideError();
  setLoading(false);
  updateNavButtons();

  // Update lock icon based on protocol
  const isSecure = e.url.startsWith('https://');
  if (isSecure) {
    lockIcon.textContent = '🔒'; lockIcon.className = 'secure'; lockIcon.title = 'Secure (HTTPS)';
  } else {
    lockIcon.textContent = '⚠'; lockIcon.className = 'insecure'; lockIcon.title = 'Not secure (HTTP)';
  }
});

page.addEventListener('did-navigate-in-page', (e) => {
  currentUrl = e.url;
  urlInput.value = e.url;
  updateNavButtons();
});

page.addEventListener('page-title-updated', (e) => {
  if (e.title) document.title = e.title + ' — Nyx Browser';
});

// ── Core fix: show a proper error page instead of a black screen ──
page.addEventListener('did-fail-load', (e) => {
  // Ignore -3 on about:blank or empty urls (initial state), and aborted loads (-3 = ERR_ABORTED is actually -3 in some versions)
  // ERR_ABORTED = -3 happens on navigation cancels, not real errors
  if (e.errorCode === -3 && (!e.validatedURL || e.validatedURL === 'about:blank')) return;
  // Ignore intentional aborts (user navigated away before page finished)
  if (e.errorCode === -3) return;

  showError(e.errorCode, e.errorDescription, e.validatedURL);
});

page.addEventListener('page-favicon-updated', (e) => {
  if (e.favicons && e.favicons.length) {
    // Could set app icon here in future
  }
});

// Handle new-window requests (target="_blank" etc.)
page.addEventListener('new-window', (e) => {
  // Load in same webview instead of spawning a new window
  e.preventDefault();
  navigate(e.url);
});

// ─── Keyboard shortcuts ────────────────────────────────────────────────────
document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
    e.preventDefault(); urlInput.select(); urlInput.focus();
  }
  if (e.key === 'F5' || ((e.ctrlKey || e.metaKey) && e.key === 'r')) {
    e.preventDefault(); flash(refreshBtn); hideError(); setLoading(true);
    try { page.reload(); } catch {}
  }
  if (e.altKey && e.key === 'ArrowLeft')  { e.preventDefault(); backBtn.click(); }
  if (e.altKey && e.key === 'ArrowRight') { e.preventDefault(); forwardBtn.click(); }
  if (e.key === 'Escape') {
    try { page.stop(); } catch {}
    setLoading(false); statusText.textContent = 'Stopped.';
  }
});

// ─── Initial state ────────────────────────────────────────────────────────
backBtn.disabled    = true;
forwardBtn.disabled = true;
lockIcon.textContent = '🔍';
lockIcon.className   = '';
refreshProxyState();
