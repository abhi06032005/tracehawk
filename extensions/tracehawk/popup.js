const $ = (id) => document.getElementById(id);

let currentTab = null;
let projectList = [];

async function init() {
  // 1. Get active tab in current window
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTab = tabs[0] || null;
  } catch (err) {
    console.error('Failed to query active tab:', err);
  }

  // Display tab URL
  if (currentTab && currentTab.url && /^https?:\/\//i.test(currentTab.url)) {
    $('current-tab-url').textContent = currentTab.url;
    $('btn-record-current').disabled = false;
  } else {
    $('current-tab-url').textContent = currentTab?.url || 'No HTTP/HTTPS page open in this tab';
    $('btn-record-current').disabled = true;
  }

  // 2. Fetch projects from TraceHawk backend
  try {
    const res = await fetch('http://127.0.0.1:4000/api/extension/projects', {
      signal: AbortSignal.timeout(3000)
    });
    if (res.ok) {
      const data = await res.json();
      projectList = data.projects || [];
      $('conn-status').textContent = '● Connected';
      $('conn-status').className = 'badge badge-online';
      renderProjects();
    } else {
      throw new Error(`Server returned ${res.status}`);
    }
  } catch {
    $('conn-status').textContent = '● Server Offline';
    $('conn-status').className = 'badge badge-offline';
    $('project-select').innerHTML = '<option value="">TraceHawk server offline</option>';
  }

  // 3. Get background recording status
  await refreshStatus();
}

function renderProjects() {
  const select = $('project-select');
  select.innerHTML = '';
  if (projectList.length === 0) {
    select.innerHTML = '<option value="">No saved projects yet</option>';
    $('btn-open-record').disabled = true;
    return;
  }
  $('btn-open-record').disabled = false;
  for (const p of projectList) {
    const opt = document.createElement('option');
    opt.value = p.id;
    opt.textContent = `${p.name} — ${p.targetUrl}`;
    opt.dataset.targetUrl = p.targetUrl;
    select.appendChild(opt);
  }
}

async function refreshStatus() {
  try {
    const state = await chrome.runtime.sendMessage({ action: 'status' });
    if (state.active) {
      $('idle-view').hidden = true;
      $('recording-view').hidden = false;
      $('recording-url').textContent = state.recordingUrl || 'Active tab';
      if (state.sessionId) {
        $('btn-view-live').href = `http://localhost:3001/sessions/${state.sessionId}`;
      }
    } else {
      $('idle-view').hidden = false;
      $('recording-view').hidden = true;
    }
    if (state.error) {
      $('status-msg').textContent = state.error;
    }
  } catch (err) {
    console.error(err);
  }
}

// Button: Record Current Tab
$('btn-record-current').onclick = async () => {
  if (!currentTab || !currentTab.url || !/^https?:\/\//i.test(currentTab.url)) {
    $('status-msg').textContent = 'Open an HTTP or HTTPS page in this tab first.';
    return;
  }
  $('btn-record-current').disabled = true;
  $('status-msg').textContent = 'Starting recording…';

  try {
    const result = await chrome.runtime.sendMessage({
      action: 'start_current_tab',
      tabId: currentTab.id,
      url: currentTab.url,
      projectId: $('project-select').value || undefined
    });

    if (result.error) throw new Error(result.error);
    await refreshStatus();

    // Open the live dashboard tab in background so traffic is visible
    if (result.sessionId) {
      await chrome.tabs.create({
        url: `http://localhost:3001/sessions/${result.sessionId}`,
        active: false
      }).catch(() => {});
    }

    window.close(); // Close popup so user continues using their tab seamlessly
  } catch (err) {
    $('status-msg').textContent = err.message;
    $('btn-record-current').disabled = false;
  }
};

// Button: Open in New Tab & Record
$('btn-open-record').onclick = async () => {
  const select = $('project-select');
  const selectedOpt = select.options[select.selectedIndex];
  const targetUrl = selectedOpt?.dataset?.targetUrl;
  const projectId = select.value;

  if (!targetUrl) {
    $('status-msg').textContent = 'Please choose a saved project.';
    return;
  }

  $('btn-open-record').disabled = true;
  $('status-msg').textContent = 'Opening tab & starting recording…';

  try {
    const result = await chrome.runtime.sendMessage({
      action: 'open_and_record',
      url: targetUrl,
      projectId
    });

    if (result.error) throw new Error(result.error);
    await refreshStatus();
    window.close();
  } catch (err) {
    $('status-msg').textContent = err.message;
    $('btn-open-record').disabled = false;
  }
};

// Button: Stop Recording
$('btn-stop').onclick = async () => {
  $('btn-stop').disabled = true;
  $('status-msg').textContent = 'Stopping and saving session…';
  try {
    await chrome.runtime.sendMessage({ action: 'stop' });
    await refreshStatus();
  } catch (err) {
    $('status-msg').textContent = err.message;
  } finally {
    $('btn-stop').disabled = false;
  }
};

init();
