'use strict';

/**
 * Bridge module for the nearby.html WKWebView flow.
 * Re-exports the keytap native bridge detection used by nearby.js.
 */

export function detectBridge() {
  const handler = window.webkit?.messageHandlers?.keytap;
  if (handler && typeof handler.postMessage === 'function') {
    return { kind: 'native', handler };
  }
  return { kind: 'missing' };
}

export function postToKeytap(bridge, payload) {
  if (bridge.kind === 'native') {
    bridge.handler.postMessage(JSON.stringify(payload));
    return true;
  }
  return false;
}
