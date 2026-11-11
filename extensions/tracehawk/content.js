// Content script running on http://localhost:3001
// Bridges TraceHawk Web Dashboard with Everyday Chrome Extension directly

window.postMessage({ type: 'TRACEHAWK_EXTENSION_READY' }, '*');
if(document.documentElement)document.documentElement.dataset.tracehawkExtension = 'installed';

window.addEventListener('message', async (event) => {
  if (event.source !== window || !event.data) return;

  if (event.data.type === 'TRACEHAWK_START_RECORD') {
    const { url, projectId } = event.data;
    try {
      const resp = await chrome.runtime.sendMessage({
        action: 'open_and_record',
        url,
        projectId
      });
      window.postMessage({
        type: 'TRACEHAWK_RECORD_STARTED',
        sessionId: resp.sessionId,
        success: !resp.error,
        error: resp.error
      }, '*');
    } catch (err) {
      window.postMessage({
        type: 'TRACEHAWK_RECORD_STARTED',
        success: false,
        error: err.message
      }, '*');
    }
  } else if (event.data.type === 'TRACEHAWK_CHECK_EXTENSION') {
    window.postMessage({ type: 'TRACEHAWK_EXTENSION_READY' }, '*');
  }
});

