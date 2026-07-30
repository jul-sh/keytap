'use strict';

// Passkey ceremonies for the web terminal: WebAuthn create/get with the PRF
// extension, configured by the wasm build of keytap-core so the relying
// party, salts, and user identity can never drift from the CLI's.

import { registrationConfig, assertionConfig } from './pkg/keytap_web.js';

const CRED_STORAGE_KEY = 'keytap:credentialId';

function encodeBase64URL(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeBase64URL(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function loadCredentialId() {
  try {
    return localStorage.getItem(CRED_STORAGE_KEY);
  } catch {
    return null;
  }
}

function saveCredentialId(rawId) {
  try {
    localStorage.setItem(CRED_STORAGE_KEY, encodeBase64URL(new Uint8Array(rawId)));
  } catch {
    // Ignore storage errors
  }
}

export function webAuthnAvailable() {
  return Boolean(window.PublicKeyCredential && navigator.credentials);
}

/// Whether a credential ID from an earlier ceremony is stored here. Its
/// absence says nothing about passkeys available through sync or a security
/// key; it only means this browser has no preferred credential ID to send.
export function hasStoredCredentialId() {
  return loadCredentialId() !== null;
}

/// WebAuthn only honors an RP ID that is a registrable suffix of (or equal
/// to) the page's host. Anywhere else; localhost checkouts, mirrors; the
/// ceremony is doomed, and browsers report it with an unhelpful (or, in
/// Safari's case, deliberately vague) error. Fail first, naming the fix.
function guardOrigin(rpId) {
  const host = location.hostname;
  if (host === rpId || host.endsWith('.' + rpId)) return;
  throw new Error(
    `passkeys are bound to ${rpId}, but this page is served from ${host}; ` +
      `ceremonies only work on https://${rpId}`
  );
}

/// The user closed or rejected the passkey prompt; keytap calls that
/// "cancelled", matching the native CLI's message.
function normalizeError(error) {
  if (error && (error.name === 'NotAllowedError' || error.name === 'AbortError')) {
    return new Error('cancelled');
  }
  return error;
}

export async function register(signal) {
  const config = registrationConfig();
  guardOrigin(config.rp_id);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const prfSalt = new Uint8Array(config.default_prf_salt);

  let credential;
  try {
    credential = await navigator.credentials.create({
      signal,
      publicKey: {
        challenge,
        rp: { id: config.rp_id, name: 'keytap' },
        user: {
          id: new Uint8Array(config.user_id),
          name: config.user_name,
          displayName: config.user_name,
        },
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 },
        ],
        authenticatorSelection: {
          residentKey: 'required',
          userVerification: 'required',
        },
        attestation: 'none',
        timeout: 120000,
        extensions: { prf: { eval: { first: prfSalt } } },
      },
    });
  } catch (error) {
    throw normalizeError(error);
  }
  if (!credential) throw new Error('Passkey creation returned no credential.');

  const extResults = credential.getClientExtensionResults?.() || {};
  if (!extResults.prf?.enabled) {
    throw new Error('The passkey was created, but this authenticator does not support WebAuthn PRF.');
  }

  saveCredentialId(credential.rawId);
  return { credentialId: encodeBase64URL(new Uint8Array(credential.rawId)) };
}

/// Run an assertion ceremony for `keyName` and return the raw PRF output.
export async function assertPrf(keyName, signal) {
  const credIdB64 = loadCredentialId();
  const preferredCredId = credIdB64 ? Array.from(decodeBase64URL(credIdB64)) : null;
  const config = assertionConfig(keyName, preferredCredId);
  guardOrigin(config.rp_id);

  const request = {
    signal,
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: config.rp_id,
      userVerification: 'required',
      timeout: 120000,
      extensions: { prf: { eval: { first: new Uint8Array(config.prf_salt) } } },
    },
  };
  if (config.preferred_credential_id) {
    request.publicKey.allowCredentials = [
      { type: 'public-key', id: new Uint8Array(config.preferred_credential_id) },
    ];
  }

  let credential;
  try {
    credential = await navigator.credentials.get(request);
  } catch (error) {
    throw normalizeError(error);
  }
  if (!credential) throw new Error('Passkey approval returned no credential.');

  const extResults = credential.getClientExtensionResults?.() || {};
  const prfFirst = extResults.prf?.results?.first;
  if (!prfFirst) {
    throw new Error('PRF output was not returned by this passkey flow.');
  }

  saveCredentialId(credential.rawId);
  return new Uint8Array(prfFirst);
}
