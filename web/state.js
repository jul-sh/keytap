'use strict';

/**
 * @typedef {'register'} RegisterFlow
 * @typedef {{ kind: 'derive', keyName: string, format: string }} DeriveFlow
 * @typedef {{ kind: 'public-key', keyName: string, format: string }} PublicKeyFlow
 * @typedef {RegisterFlow | DeriveFlow | PublicKeyFlow} Flow
 *
 * @typedef {{ kind: 'unsupported', reason: string }} UnsupportedState
 * @typedef {{ kind: 'ready', flow: Flow }} ReadyState
 * @typedef {{ kind: 'running', flow: Flow }} RunningState
 * @typedef {{ kind: 'succeeded', result: SuccessResult }} SucceededState
 * @typedef {{ kind: 'failed', flow: Flow, message: string }} FailedState
 * @typedef {UnsupportedState | ReadyState | RunningState | SucceededState | FailedState} PageState
 */

export const PRIVATE_FORMATS = ['hex', 'base64', 'age', 'ssh'];
export const PUBLIC_FORMATS = ['hex', 'base64', 'age', 'ssh'];

export function initialState() {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    return { kind: 'unsupported', reason: 'WebAuthn is not available in this browser.' };
  }
  return { kind: 'ready', flow: { kind: 'register' } };
}
