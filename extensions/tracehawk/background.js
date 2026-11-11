const BASE = 'http://127.0.0.1:4000/api/extension';
let active = null;
let lastSession = null;
let lastError = '';
let queue = Promise.resolve();
let queued = 0;
const requests = new Map();

async function api(path, body, headers = {}) {
  const response = await fetch(BASE + path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-TraceHawk-Control': '1',
      ...headers
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(15000)
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

async function stop(reason = '', notifyServer = false) {
  const recording = active;
  if (!recording) return;
  active = null;
  requests.clear();
  lastError = reason;

  await chrome.debugger.detach({ tabId: recording.tabId }).catch(() => {});
  await queue.catch(() => {});

  if (notifyServer && (recording.code || recording.sessionId)) {
    const token = recording.code || recording.sessionId;
    await api('/bridge/stop', {}, { Authorization: `Bearer ${token}` }).catch(() => {});
  }

  await chrome.storage.session.remove('recording').catch(() => {});
  await chrome.action.setBadgeText({ text: '' }).catch(() => {});
  console.log('[TraceHawk] Stopped recording.', reason);
}

async function attachAndRecordTab(tabId, url, sessionId, code, origins = []) {
  if (active) {
    if (active.tabId === tabId && active.sessionId === sessionId) {
      console.log('[TraceHawk] Already attached to this tab for session:', sessionId);
      return;
    }
    await stop('Switched recording tab', true);
  }

  if (!url || !/^https?:\/\//i.test(url)) {
    throw new Error('Please select an HTTP or HTTPS application tab.');
  }

  const effectiveToken = code || sessionId;

  try {
    await chrome.debugger.attach({ tabId }, '1.3');
  } catch (err) {
    await api('/bridge/stop', {}, {Authorization:`Bearer ${effectiveToken}`}).catch(()=>{});
    throw new Error(`Failed to attach to tab: ${err.message}. Close DevTools on this tab and try again.`);
  }

  try {
    await chrome.debugger.sendCommand({ tabId }, 'Network.enable', {
      maxTotalBufferSize: 16 * 1024 * 1024,
      maxResourceBufferSize: 1024 * 1024
    });

    active = {
      sessionId,
      tabId,
      url,
      code: effectiveToken,
      origins: origins || [],
      paused: false
    };
    lastSession = sessionId;
    lastError = '';

    await chrome.storage.session.set({ recording: { tabId, sessionId, url } }).catch(() => {});
    await chrome.action.setBadgeBackgroundColor({ color: '#b91c1c' });
    await chrome.action.setBadgeText({ text: 'REC' });
    console.log('[TraceHawk] Successfully attached & recording tab:', tabId, url, 'Session:', sessionId);
  } catch (err) {
    active = null;
    await chrome.debugger.detach({ tabId }).catch(() => {});
    await api('/bridge/stop', {}, {Authorization:`Bearer ${effectiveToken}`}).catch(()=>{});
    throw err;
  }
}

// A bound session is the only source of recording control.
async function pollBackend(){if(!active)return;try{const state=await api('/bridge/status',undefined,{Authorization:`Bearer ${active.code}`});if(!active)return;if(!['RECORDING','PAUSED'].includes(state.status)){await stop('Session stopped',false);return;}if(state.focus){const tab=await chrome.tabs.update(active.tabId,{active:true});await chrome.windows.update(tab.windowId,{focused:true});}active.paused=state.status==='PAUSED';if(active.paused)requests.clear();await chrome.action.setBadgeText({text:active.paused?'PAUSE':'REC'});}catch(e){await stop(e.message,true);}}
setInterval(pollBackend,1500);
function inScope(url){try{return active?.origins.includes(new URL(url).origin);}catch{return false;}}
function plainHeaders(headers) {
  return Object.fromEntries(
    Object.entries(headers || {})
      .slice(0, 200)
      .map(([k, v]) => [k, String(v).slice(0, 20000)])
  );
}

function body(text) {
  return typeof text === 'string' ? (text.length <= 65536 ? text : '[OMITTED: body exceeds 64 KiB]') : null;
}

function upload(recording, exchange) {
  if (++queued > 200) {
    queued--;
    void stop('Upload queue full', true);
    return;
  }
  queue = queue
    .then(async () => {
      try {
        const token = recording.code || recording.sessionId;
        const res = await api('/bridge/exchange', exchange, { Authorization: `Bearer ${token}` });
        if (res && res.accepted) {
          console.log('[TraceHawk] Exchange saved:', exchange.method, exchange.url, exchange.statusCode);
        } else if (res && res.accepted === false) {
          console.warn('[TraceHawk] Exchange not accepted:', res.status);
        }
      } catch (err) {
        lastError=err.message;setTimeout(()=>void stop(err.message,true),0);
      }
    })
    .finally(() => queued--);
}

async function onEvent(source, method, p) {
  const recording = active;
  if (!recording || source.tabId !== recording.tabId || recording.paused) return;

  if (method === 'Network.requestWillBeSent') {
    if(!inScope(p.request?.url)||!inScope(recording.url))return;
    if (requests.size >= 500){void stop('Too many pending requests',true);return;}
    // Filter out non-HTTP/HTTPS URLs (e.g. data:, blob:, chrome-extension:)
    if (!p.request || !p.request.url || !/^https?:\/\//i.test(p.request.url)) return;

    if (p.redirectResponse && requests.has(p.requestId)) {
      const old = requests.get(p.requestId);
      const rawDur = (p.timestamp - (old.started || p.timestamp)) * 1000;
      upload(recording, {
        ...old,
        statusCode: p.redirectResponse.status,
        responseHeaders: plainHeaders(p.redirectResponse.headers),
        responseBody: null,
        contentType: p.redirectResponse.mimeType || '',
        duration: Number.isFinite(rawDur) && rawDur >= 0 ? Math.round(rawDur) : 0,
        started: undefined
      });
    }

    requests.set(p.requestId, {
      url: p.request.url,
      pageUrl: recording.url,
      method: p.request.method || 'GET',
      statusCode: null,
      requestHeaders: plainHeaders(p.request.headers),
      responseHeaders: {},
      requestBody: body(p.request.postData),
      responseBody: null,
      contentType: '',
      duration: 0,
      resourceType: (p.type || 'other').toLowerCase(),
      failureReason: null,
      started: p.timestamp
    });
  } else if (method === 'Network.responseReceived' && requests.has(p.requestId)) {
    const e = requests.get(p.requestId);
    e.statusCode = p.response.status;
    e.responseHeaders = plainHeaders(p.response.headers);
    e.contentType = p.response.mimeType || '';
  } else if ((method === 'Network.loadingFinished' || method === 'Network.loadingFailed') && requests.has(p.requestId)) {
    const e = requests.get(p.requestId);
    requests.delete(p.requestId);

    const rawDur = (p.timestamp - (e.started || p.timestamp)) * 1000;
    e.duration = Number.isFinite(rawDur) && rawDur >= 0 ? Math.round(rawDur) : 0;
    delete e.started;

    if (method === 'Network.loadingFailed') {
      e.failureReason = p.errorText || 'Request failed';
    } else if ((p.encodedDataLength || 0) <= 65536 && /json|text|javascript|xml|html/.test(e.contentType)) {
      try {
        const result = await chrome.debugger.sendCommand({ tabId: recording.tabId }, 'Network.getResponseBody', {
          requestId: p.requestId
        });
        e.responseBody = result.base64Encoded ? '[OMITTED: encoded body]' : body(result.body);
      } catch {
        e.responseBody = null;
      }
    }

    if (active === recording && !recording.paused) {
      upload(recording, e);
    }
  }
}

chrome.debugger.onEvent.addListener((s, m, p) => {
  void onEvent(s, m, p).catch(e=>void stop(e.message,true));
});

chrome.debugger.onDetach.addListener((source) => {
  if (active?.tabId === source.tabId) {
    // Only detach locally; do not kill the server session
    void stop('Debugger detached by user or browser', true);
  }
});

chrome.tabs.onUpdated.addListener((tabId,change)=>{if(active?.tabId===tabId&&change.url){if(!inScope(change.url)){void stop('Tab left project scope',true);return;}active.url=change.url;}});
chrome.tabs.onRemoved.addListener((tabId) => {
  if (active?.tabId === tabId) {
    void stop('Tab closed', true);
  }
});

chrome.runtime.onMessage.addListener((message, _sender, reply) => {
  if(_sender.id!==chrome.runtime.id)return;
  (async () => {
    if (message.action === 'status') {
      return {
        active: !!active,
        sessionId: active?.sessionId || lastSession,
        recordingUrl: active?.url,
        tabId: active?.tabId,
        error: lastError
      };
    } else if (message.action === 'start_current_tab') {
      const res = await api('/start-session', { url: message.url, projectId: message.projectId });
      await attachAndRecordTab(message.tabId, message.url, res.sessionId, res.code || res.sessionId, res.origins);
      return { success: true, sessionId: res.sessionId };
    } else if (message.action === 'open_and_record') {
      const expectedOrigin = new URL(message.url).origin.toLowerCase();
      const tabs = await chrome.tabs.query({});
      let targetTab = tabs.find(t => {
        if (!t.url) return false;
        try {
          return t.url === message.url;
        } catch { return false; }
      });

      if (targetTab && targetTab.id) {
        await chrome.tabs.update(targetTab.id, { active: true });
      } else {
        targetTab = await chrome.tabs.create({ url: 'about:blank', active: true });
      }

      const res = await api('/start-session', { url: message.url, projectId: message.projectId });
      await attachAndRecordTab(targetTab.id, message.url, res.sessionId, res.code, res.origins);
      await chrome.tabs.update(targetTab.id,{url:message.url,active:true});
      return { success: true, sessionId: res.sessionId, tabId: targetTab.id };
    } else if (message.action === 'start_legacy') {
      const claim = await api('/bridge/claim', { url: message.url }, { Authorization: `Bearer ${message.code}` });
      await attachAndRecordTab(message.tabId, message.url, claim.sessionId, message.code, claim.origins);
      return { success: true, sessionId: claim.sessionId };
    } else if (message.action === 'stop') {
      await stop('Stopped from popup', true);
      return { success: true };
    }
    return { error: 'Unknown action' };
  })()
    .then(reply)
    .catch((err) => reply({ error: err.message }));
  return true;
});

// Cleanup on restart
chrome.storage.session.get('recording').then(async ({ recording }) => {
  if (recording && !active) {
    await chrome.debugger.detach({ tabId: recording.tabId }).catch(() => {});
    await chrome.storage.session.remove('recording').catch(() => {});
  }
});

