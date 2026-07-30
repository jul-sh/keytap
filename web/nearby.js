import {
  IdentityProofUnavailableError,
  InitialIndeterminateError,
  InitialRejectionError,
  PairingRejectedError,
  ProtocolError,
  createApproverCipher,
  createNearbyIdentityProof,
  createRegistrationIdentityProof,
  createSasCommitment,
  createSasContext,
  createSasDigest,
  decodeBase64URL,
  encodeBase64URL,
  isCompletedElsewhereMessage,
  parseCliMessage,
  parseInitialRequest,
  parseSasWordList,
  relayRoomId,
  sasPhrase,
  verifySasCommitment,
} from './nearby-protocol.js';

const RELAY_ORIGIN = 'https://keytap-relay.julsh.workers.dev';
const OPEN_TIMEOUT_MS = 30_000;
const RELAY_MESSAGE_TIMEOUT_MS = 150_000;
const WEBAUTHN_TIMEOUT_MS = 120_000;
const MAX_RELAY_FRAME_BYTES = 16 * 1024;
const MAX_WORD_LIST_BYTES = 32 * 1024;
const RP_ID = 'keytap.jul.sh';

let identityWasmPromise;
let sasWordsPromise;

/**
 * @typedef {
 *   {kind: 'boot'} |
 *   {kind: 'connecting'} |
 *   {kind: 'sas', session: RelaySession, request: Request, digest: Uint8Array} |
 *   {kind: 'choice', session: RelaySession, request: AssertRequest, binding: ProofBinding} |
 *   {kind: 'ceremony', session: RelaySession, operation: CeremonyOperation} |
 *   {kind: 'registration-created', session: RelaySession, credential: CreatedCredential} |
 *   {kind: 'sent', session: RelaySession, result: SentResult} |
 *   {kind: 'suspended', work: SuspendedWork} |
 *   {kind: 'terminal', outcome: TerminalOutcome} |
 *   {kind: 'expired'}
 * } Phase
 * @typedef {RegisterRequest | AssertRequest} Request
 * @typedef {{kind: 'assert', challenge: Uint8Array, prfSalt: Uint8Array, identitySalt: Uint8Array, identity: IdentityMode, keyName: string, storage: 'choose'|'remember'}} AssertRequest
 * @typedef {{kind: 'pairing-any'} | {kind: 'pairing-credential', credentialId: Uint8Array} | {kind: 'pinned', credentialId: Uint8Array}} IdentityMode
 * @typedef {
 *   {kind: 'first-pair-sas', digest: Uint8Array} |
 *   {kind: 'pinned-identity', sessionBinding: Uint8Array, requestFrameBytes: Uint8Array}
 * } ProofBinding
 * @typedef {'once'|'remember'} Disposition
 * @typedef {{kind: 'registration', request: RegisterRequest} | {kind: 'assertion', request: AssertRequest, binding: ProofBinding, disposition: Disposition}} CeremonyOperation
 * @typedef {{kind: 'register', challenge: Uint8Array, identitySalt: Uint8Array, userId: Uint8Array, userName: string}} RegisterRequest
 * @typedef {{kind: 'identified', credentialId: Uint8Array} | {kind: 'malformed'}} CreatedCredential
 * @typedef {{kind: 'registration'} | {kind: 'assertion', keyName: string, disposition: Disposition}} SentResult
 * @typedef {{kind: 'pre-result'} | {kind: 'registration-created'} | {kind: 'registration-sent'} | {kind: 'assertion-sent'} | {kind: 'terminal', outcome: TerminalOutcome}} SuspendedWork
 * @typedef {{kind: 'registered'|'once'|'stored'|'storage-unavailable'|'completed-elsewhere'|'pairing-rejected'|'identity-store-unavailable'|'identity-rejected'|'identity-indeterminate'|'capability-unavailable'|'registration-created-unsaved'|'registration-indeterminate'|'assertion-indeterminate'|'failed'|'expired', title: string, message: string}} TerminalOutcome
 */

/** @type {Phase} */
let phase = { kind: 'boot' };
let pageLifetime;
let activeSession;

export function isTopLevelContext(context) {
  try {
    return context.top === context.self;
  } catch {
    return false;
  }
}

export function revealTopLevelPage(context, root) {
  if (!isTopLevelContext(context)) return false;
  root.classList.add('approval-top-level');
  return true;
}

export class CompletedElsewhereError extends ProtocolError {
  constructor() {
    super('approval completed on the Mac');
    this.name = 'CompletedElsewhereError';
  }
}

export class LocalPairingRejectionError extends ProtocolError {
  constructor() {
    super('the pairing words were rejected on this device');
    this.name = 'LocalPairingRejectionError';
  }
}

export class PasskeyPrfUnavailableError extends Error {
  constructor() {
    super('this browser and passkey did not return the required PRF outputs');
    this.name = 'PasskeyPrfUnavailableError';
  }
}

class AsyncQueue {
  constructor() {
    this.items = [];
    this.waiters = [];
    this.failure = null;
  }

  push(value) {
    if (this.failure) return;
    const waiter = this.waiters.shift();
    if (waiter) {
      clearTimeout(waiter.timer);
      waiter.resolve(value);
    } else {
      this.items.push(value);
    }
  }

  fail(error) {
    if (this.failure) return;
    this.failure = error instanceof Error ? error : new Error(String(error));
    for (const waiter of this.waiters.splice(0)) {
      clearTimeout(waiter.timer);
      waiter.reject(this.failure);
    }
  }

  next(timeoutMs = RELAY_MESSAGE_TIMEOUT_MS) {
    if (this.items.length > 0) return Promise.resolve(this.items.shift());
    if (this.failure) return Promise.reject(this.failure);
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject, timer: 0 };
      waiter.timer = setTimeout(() => {
        const index = this.waiters.indexOf(waiter);
        if (index !== -1) this.waiters.splice(index, 1);
        reject(new ProtocolError('timed out waiting for the CLI'));
      }, timeoutMs);
      this.waiters.push(waiter);
    });
  }
}

function abortReason(signal) {
  return signal.reason instanceof Error
    ? signal.reason
    : new DOMException('The operation was aborted.', 'AbortError');
}

function throwIfAborted(signal) {
  if (signal?.aborted) throw abortReason(signal);
}

function abortable(promise, signal) {
  if (!signal) return promise;
  try {
    throwIfAborted(signal);
  } catch (error) {
    return Promise.reject(error);
  }
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(abortReason(signal));
    signal.addEventListener('abort', onAbort, { once: true });
    Promise.resolve(promise).then(
      value => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      error => {
        signal.removeEventListener('abort', onAbort);
        reject(error);
      },
    );
  });
}

export function exactCliPublicKeyFromFragment() {
  const fragment = location.hash.startsWith('#') ? location.hash.slice(1) : '';
  history.replaceState(null, '', location.pathname + location.search);
  const matched = /^key=([A-Za-z0-9_-]{87})$/.exec(fragment);
  if (!matched) {
    throw new ProtocolError('No unambiguous nearby CLI key in the approval link.');
  }
  let publicKey;
  try {
    publicKey = decodeBase64URL(matched[1]);
  } catch {
    throw new ProtocolError('Invalid nearby CLI key in the approval link.');
  }
  if (publicKey.length !== 65 || publicKey[0] !== 0x04) {
    throw new ProtocolError('Invalid nearby CLI key in the approval link.');
  }
  return publicKey;
}

export async function relayUrl(cliPublicKey) {
  const url = new URL(RELAY_ORIGIN);
  url.protocol = 'wss:';
  url.pathname = `/room/${await relayRoomId(cliPublicKey)}`;
  url.search = 'role=approver';
  return url.href;
}

async function binaryMessage(data) {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (typeof Blob === 'function' && data instanceof Blob) {
    if (data.size > MAX_RELAY_FRAME_BYTES) throw new ProtocolError('relay frame is too large');
    return new Uint8Array(await data.arrayBuffer());
  }
  throw new ProtocolError('relay sent a non-binary frame');
}

export class RelaySession {
  constructor(socket, cipher, controller) {
    this.socket = socket;
    this.cipher = cipher;
    this.controller = controller;
    this.incoming = new AsyncQueue();
    this.intentionalClose = false;
    this.deferredSocketFailure = false;
    this.decodeChain = Promise.resolve();

    socket.addEventListener('message', event => {
      this.decodeChain = this.decodeChain.then(async () => {
        const frame = await binaryMessage(event.data);
        if (frame.length > MAX_RELAY_FRAME_BYTES) throw new ProtocolError('relay frame is too large');
        const opened = await cipher.open(frame);
        if (isCompletedElsewhereMessage(opened.value)) {
          throw new CompletedElsewhereError();
        }
        this.incoming.push(opened);
      }).catch(error => this.fail(error));
    });
    socket.addEventListener('close', () => {
      this.deferSocketFailure(new ProtocolError('the encrypted relay closed'));
    });
    socket.addEventListener('error', () => {
      this.deferSocketFailure(new ProtocolError('the encrypted relay failed'));
    });
  }

  deferSocketFailure(error) {
    if (this.intentionalClose || this.deferredSocketFailure) return;
    this.deferredSocketFailure = true;
    this.decodeChain = this.decodeChain.then(() => this.fail(error));
  }

  fail(error) {
    const failure = error instanceof Error ? error : new ProtocolError('the encrypted relay failed');
    this.incoming.fail(failure);
    if (!this.controller.signal.aborted) this.controller.abort(failure);
  }

  async send(message) {
    throwIfAborted(this.controller.signal);
    const frame = await this.cipher.seal(message);
    throwIfAborted(this.controller.signal);
    if (this.socket.readyState !== WebSocket.OPEN) {
      throw new ProtocolError('the encrypted relay closed');
    }
    this.socket.send(frame);
  }

  async nextRaw(timeoutMs) {
    return this.incoming.next(timeoutMs);
  }

  async next(timeoutMs) {
    return (await this.nextRaw(timeoutMs)).value;
  }

  close() {
    if (this.intentionalClose) return;
    this.intentionalClose = true;
    this.incoming.fail(this.controller.signal.aborted
      ? abortReason(this.controller.signal)
      : new ProtocolError('the encrypted relay closed'));
    if (this.socket.readyState === WebSocket.OPEN
        || this.socket.readyState === WebSocket.CONNECTING) {
      this.socket.close(1000, 'done');
    }
  }
}

export async function openRelay(cliPublicKey, controller) {
  const cipher = await createApproverCipher(cliPublicKey);
  throwIfAborted(controller.signal);
  const socket = new WebSocket(await relayUrl(cliPublicKey));
  socket.binaryType = 'arraybuffer';

  try {
    await abortable(new Promise((resolve, reject) => {
      let settled = false;
      const finish = operation => value => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        operation(value);
      };
      const accept = finish(resolve);
      const rejectOnce = finish(reject);
      const timer = setTimeout(() => {
        rejectOnce(new ProtocolError('timed out reaching the encrypted relay'));
        socket.close();
      }, OPEN_TIMEOUT_MS);
      socket.addEventListener('open', accept, { once: true });
      socket.addEventListener('error', () => rejectOnce(new ProtocolError('could not reach the encrypted relay')), { once: true });
      socket.addEventListener('close', () => rejectOnce(new ProtocolError('the encrypted relay closed')), { once: true });
    }), controller.signal);
  } catch (error) {
    if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) socket.close();
    throw error;
  }

  const session = new RelaySession(socket, cipher, controller);
  socket.send(cipher.hello);
  return { session, sessionBinding: cipher.sessionBinding };
}

async function nextCliMessage(session, expectedType) {
  return parseCliMessage(await session.next(), expectedType);
}

async function loadSasWords(signal) {
  sasWordsPromise ??= (async () => {
    const response = await fetch('./nearby-sas-words.txt', { cache: 'force-cache', signal });
    if (!response.ok) throw new ProtocolError('could not load pairing words');
    const declared = Number(response.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > MAX_WORD_LIST_BYTES) {
      throw new ProtocolError('pairing word list is too large');
    }
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length > MAX_WORD_LIST_BYTES) throw new ProtocolError('pairing word list is too large');
    return parseSasWordList(bytes);
  })();
  return abortable(sasWordsPromise, signal);
}

async function deriveEd25519PublicKey(identitySeed) {
  if (!(identitySeed instanceof Uint8Array) || identitySeed.length !== 32) {
    throw new ProtocolError('invalid identity PRF output');
  }
  identityWasmPromise ??= import('./pkg/keytap_web.js').then(async module => {
    await module.default();
    return module;
  });
  const wasm = await identityWasmPromise;
  const publicKey = new Uint8Array(wasm.ed25519PublicKey(identitySeed));
  if (publicKey.length !== 32) throw new ProtocolError('invalid Ed25519 identity');
  return publicKey;
}

function guardPasskeyOrigin() {
  const host = location.hostname;
  if (host === RP_ID || host.endsWith(`.${RP_ID}`)) return;
  throw new Error(`passkey approval only works on https://${RP_ID}`);
}

function runRegistration(request, signal) {
  guardPasskeyOrigin();
  return navigator.credentials.create({
    signal,
    publicKey: {
      challenge: request.challenge,
      rp: { id: RP_ID, name: 'keytap' },
      user: { id: request.userId, name: request.userName, displayName: request.userName },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      attestation: 'none',
      timeout: WEBAUTHN_TIMEOUT_MS,
      extensions: { prf: { eval: { first: request.identitySalt } } },
    },
  });
}

function firstPrfResult(credential) {
  try {
    const first = credential?.getClientExtensionResults?.()?.prf?.results?.first;
    const output = first ? new Uint8Array(first) : new Uint8Array();
    if (output.length === 32) return output;
    output.fill(0);
    return null;
  } catch {
    return null;
  }
}

function equalBytes(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

/** Obtain the registration identity, falling back when create omits PRF results. */
export async function registrationIdentitySeed(
  createdCredential,
  request,
  credentialId,
  signal,
) {
  const createTime = firstPrfResult(createdCredential);
  if (createTime) return createTime;

  guardPasskeyOrigin();
  const asserted = await navigator.credentials.get({
    signal,
    publicKey: {
      challenge: request.challenge,
      rpId: RP_ID,
      userVerification: 'required',
      timeout: WEBAUTHN_TIMEOUT_MS,
      allowCredentials: [{ type: 'public-key', id: credentialId }],
      extensions: { prf: { eval: { first: request.identitySalt } } },
    },
  });
  let assertedId;
  try {
    assertedId = asserted?.rawId ? new Uint8Array(asserted.rawId) : new Uint8Array();
  } catch {
    assertedId = new Uint8Array();
  }
  const assertedSeed = firstPrfResult(asserted);
  if (!assertedSeed || !equalBytes(assertedId, credentialId)) {
    assertedSeed?.fill(0);
    throw new PasskeyPrfUnavailableError();
  }
  return assertedSeed;
}

/** @returns {Promise<ProofBinding>} */
export async function assertionProofBinding(
  identity,
  sessionBinding,
  requestFrameBytes,
  confirmFirstPair,
) {
  switch (identity?.kind) {
    case 'pairing-any':
    case 'pairing-credential':
      return { kind: 'first-pair-sas', digest: await confirmFirstPair() };
    case 'pinned':
      return { kind: 'pinned-identity', sessionBinding, requestFrameBytes };
    default:
      throw new ProtocolError('invalid identity mode');
  }
}

async function runAssertion(request, binding, disposition, signal) {
  guardPasskeyOrigin();
  const publicKey = {
    challenge: request.challenge,
    rpId: RP_ID,
    userVerification: 'required',
    timeout: WEBAUTHN_TIMEOUT_MS,
    extensions: { prf: { eval: { first: request.prfSalt, second: request.identitySalt } } },
  };
  switch (request.identity.kind) {
    case 'pairing-any':
      break;
    case 'pairing-credential':
    case 'pinned':
      publicKey.allowCredentials = [{ type: 'public-key', id: request.identity.credentialId }];
      break;
  }
  const credential = await navigator.credentials.get({ publicKey, signal });
  let credentialId;
  let prfFirst;
  let identitySeed;
  try {
    const results = credential?.getClientExtensionResults?.()?.prf?.results;
    credentialId = credential?.rawId ? new Uint8Array(credential.rawId) : new Uint8Array();
    prfFirst = results?.first ? new Uint8Array(results.first) : new Uint8Array();
    identitySeed = results?.second ? new Uint8Array(results.second) : new Uint8Array();
  } catch {
    throw new PasskeyPrfUnavailableError();
  }
  if (credentialId.length < 1 || credentialId.length > 1024
      || prfFirst.length !== 32 || identitySeed.length !== 32) {
    prfFirst.fill(0);
    identitySeed.fill(0);
    throw new PasskeyPrfUnavailableError();
  }
  let identity;
  try {
    identity = await createNearbyIdentityProof({
      binding,
      challenge: request.challenge,
      credentialId,
      prfFirst,
      keyName: request.keyName,
      disposition,
    }, identitySeed, deriveEd25519PublicKey);
  } catch (error) {
    prfFirst.fill(0);
    throw error;
  } finally {
    identitySeed.fill(0);
  }
  return { credentialId, prfFirst, identity };
}

function assertionResultMessage(request, result, disposition) {
  const message = {
    type: request.identity.kind === 'pinned' ? 'assertion-result' : 'paired-assertion-result',
    credentialId: encodeBase64URL(result.credentialId),
    prfFirst: encodeBase64URL(result.prfFirst),
    identity: {
      algorithm: 'ed25519',
      publicKey: encodeBase64URL(result.identity.publicKey),
      signature: encodeBase64URL(result.identity.signature),
    },
    disposition,
  };
  result.prfFirst.fill(0);
  return message;
}

function isPasskeyCancellation(error) {
  return error?.name === 'NotAllowedError'
    || error?.name === 'AbortError'
    || error?.message === 'cancelled';
}

export function classifyCreatedCredential(credential) {
  try {
    const credentialId = credential?.rawId
      ? new Uint8Array(credential.rawId)
      : new Uint8Array();
    return credentialId.length >= 1 && credentialId.length <= 1024
      ? { kind: 'identified', credentialId }
      : { kind: 'malformed' };
  } catch {
    return { kind: 'malformed' };
  }
}

function registrationCreatedUnsavedOutcome() {
  return {
    kind: 'registration-created-unsaved',
    title: 'Passkey created; setup incomplete',
    message: 'A passkey may have been created on this device, but the CLI did not save it. Check the terminal and this device’s passkey settings; remove the unused passkey before retrying if necessary.',
  };
}

function registrationIndeterminateOutcome() {
  return {
    kind: 'registration-indeterminate',
    title: 'Setup status unknown',
    message: 'The passkey was created and its result was sent, but this page could not confirm whether the CLI saved it. Check the terminal before retrying.',
  };
}

function assertionIndeterminateOutcome() {
  return {
    kind: 'assertion-indeterminate',
    title: 'Approval status unknown',
    message: 'The approved key result was sent, but this page could not confirm whether the CLI accepted it. Check the terminal before retrying.',
  };
}

function expiredOutcome() {
  return {
    kind: 'expired',
    title: 'Request expired',
    message: 'This request expired when you left the page. Run the keytap command again and open the fresh approval link.',
  };
}

export function suspendPhaseForPagehide(currentPhase) {
  switch (currentPhase.kind) {
    case 'registration-created':
      return { kind: 'suspended', work: { kind: 'registration-created' } };
    case 'sent':
      switch (currentPhase.result.kind) {
        case 'registration':
          return { kind: 'suspended', work: { kind: 'registration-sent' } };
        case 'assertion':
          return { kind: 'suspended', work: { kind: 'assertion-sent' } };
      }
      break;
    case 'terminal':
      return { kind: 'suspended', work: { kind: 'terminal', outcome: currentPhase.outcome } };
    case 'suspended':
      return currentPhase;
    case 'boot':
    case 'connecting':
    case 'sas':
    case 'choice':
    case 'ceremony':
    case 'expired':
      return { kind: 'suspended', work: { kind: 'pre-result' } };
  }
  throw new ProtocolError('invalid nearby lifecycle phase');
}

export function outcomeForSuspendedPhase(suspendedPhase) {
  if (suspendedPhase.kind !== 'suspended') {
    throw new ProtocolError('invalid suspended nearby phase');
  }
  switch (suspendedPhase.work.kind) {
    case 'pre-result':
      return expiredOutcome();
    case 'registration-created':
      return registrationCreatedUnsavedOutcome();
    case 'registration-sent':
      return registrationIndeterminateOutcome();
    case 'assertion-sent':
      return assertionIndeterminateOutcome();
    case 'terminal':
      return suspendedPhase.work.outcome;
  }
  throw new ProtocolError('invalid suspended nearby work');
}

const $ = id => document.getElementById(id);

function appendParts(element, parts) {
  for (const part of parts) {
    if (typeof part === 'string') {
      element.append(part);
    } else {
      const code = document.createElement('code');
      code.textContent = part.code;
      element.append(code);
    }
  }
  return element;
}

function paragraph(...parts) {
  return appendParts(document.createElement('p'), parts);
}

function action(label, secondary = false) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = secondary ? 'action action-secondary' : 'action';
  button.textContent = label;
  return button;
}

function setScreen(title, summary, ...content) {
  document.title = `keytap: ${title.toLowerCase()}`;
  $('title').textContent = title;
  $('summary').textContent = summary;
  $('content').replaceChildren(...content);
  $('status').textContent = '';
  $('alert').textContent = '';
  $('details').hidden = false;
  $('title').focus();
}

function setStatus(...parts) {
  $('alert').textContent = '';
  $('status').replaceChildren();
  appendParts($('status'), parts);
}

function waitForChoice(choices, signal) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const listeners = [];
    const finish = operation => value => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', onAbort);
      for (const [button, listener] of listeners) button.removeEventListener('click', listener);
      operation(value);
    };
    const accept = finish(resolve);
    const decline = finish(reject);
    const onAbort = () => decline(abortReason(signal));
    signal.addEventListener('abort', onAbort, { once: true });
    for (const [button, value] of choices) {
      const listener = () => accept(value);
      listeners.push([button, listener]);
      button.addEventListener('click', listener);
    }
    if (signal.aborted) onAbort();
  });
}

async function confirmPairingWords(session, digest, signal) {
  const words = await loadSasWords(signal);
  const phrase = sasPhrase(digest, words);
  const match = action('Words match — continue');
  const reject = action('They do not match', true);
  const output = document.createElement('output');
  output.className = 'pairing-words';
  output.setAttribute('aria-label', 'Pairing words');
  output.textContent = phrase;
  setScreen(
    'Compare pairing words',
    'Compare both words, in order, with the words in the terminal that displayed this approval link.',
    output,
    paragraph('Only continue when both words match exactly. The passkey prompt will not open until this device and the CLI have both confirmed them.'),
    match,
    reject,
  );
  setStatus('Waiting for your comparison…');
  const decision = await waitForChoice([[match, 'confirmed'], [reject, 'rejected']], signal);
  if (decision === 'rejected') {
    await session.send({ type: 'sas-approver-rejected' });
    throw new LocalPairingRejectionError();
  }
  match.disabled = true;
  reject.disabled = true;
  setStatus('Words confirmed here. Confirm them in the terminal…');
  await session.send({ type: 'sas-approver-confirmed' });
  await nextCliMessage(session, 'sas-cli-confirmed');
}

async function runSas(session, sessionBinding, request, requestFrameBytes, signal) {
  const context = await createSasContext(sessionBinding, requestFrameBytes);
  const commitMessage = await nextCliMessage(session, 'sas-cli-commit');
  const cliCommitment = decodeBase64URL(commitMessage.commitment);
  if (cliCommitment.length !== 32) throw new ProtocolError('invalid CLI SAS commitment');
  const approverNonce = crypto.getRandomValues(new Uint8Array(32));
  const approverCommitment = await createSasCommitment('approver', context, approverNonce);
  await session.send({
    type: 'sas-approver-commit',
    commitment: encodeBase64URL(approverCommitment),
  });
  const reveal = await nextCliMessage(session, 'sas-cli-reveal');
  const cliNonce = decodeBase64URL(reveal.nonce);
  if (cliNonce.length !== 32
      || !await verifySasCommitment('cli', context, cliNonce, cliCommitment)) {
    await session.send({ type: 'sas-approver-rejected' });
    throw new ProtocolError('the CLI did not open its pairing commitment');
  }
  await session.send({ type: 'sas-approver-reveal', nonce: encodeBase64URL(approverNonce) });
  const digest = await createSasDigest(
    context,
    cliCommitment,
    approverCommitment,
    cliNonce,
    approverNonce,
  );
  cliNonce.fill(0);
  approverNonce.fill(0);
  phase = { kind: 'sas', session, request, digest };
  await confirmPairingWords(session, digest, signal);
  return digest;
}

async function chooseDisposition(session, request, binding, signal, notice = '') {
  const once = action('Use once');
  const remember = action(request.storage === 'remember' ? 'Approve and remember' : 'Use and remember', true);
  const controls = request.storage === 'remember' ? [remember] : [once, remember];
  setScreen(
    request.storage === 'remember' ? 'Remember this key?' : 'Use once or remember?',
    `Your CLI requested key: ${request.keyName}`,
    paragraph(
      request.storage === 'remember'
        ? 'Store this derived key on that machine.'
        : 'Use it only for this command, or store it on that machine for later commands.',
    ),
    paragraph('Remove a stored key later with ', { code: `keytap forget ${request.keyName}` }, '.'),
    ...controls,
  );
  if (notice) setStatus(notice);
  phase = { kind: 'choice', session, request, binding };
  const choices = request.storage === 'remember'
    ? [[remember, 'remember']]
    : [[once, 'once'], [remember, 'remember']];
  return waitForChoice(choices, signal);
}

async function completeRegistration(session, request, sasDigest, signal) {
  phase = { kind: 'ceremony', session, operation: { kind: 'registration', request } };
  setScreen(
    'Create your passkey',
    'The pairing words matched on both devices.',
    paragraph('Complete the passkey prompt. Some devices may ask you to confirm the new passkey once more to finish pairing.'),
  );
  setStatus('Creating your passkey…');
  const credential = await runRegistration(request, signal);
  const created = classifyCreatedCredential(credential);
  phase = { kind: 'registration-created', session, credential: created };
  if (created.kind === 'malformed') {
    throw new Error('Passkey creation returned no credential identifier.');
  }
  setStatus('Finishing the trusted passkey pairing…');
  const identitySeed = await registrationIdentitySeed(
    credential,
    request,
    created.credentialId,
    signal,
  );
  let identity;
  try {
    identity = await createRegistrationIdentityProof({
      sasDigest,
      challenge: request.challenge,
      credentialId: created.credentialId,
    }, identitySeed, deriveEd25519PublicKey);
  } finally {
    identitySeed.fill(0);
  }
  await session.send({
    type: 'paired-registration-result',
    credentialId: encodeBase64URL(created.credentialId),
    identity: {
      algorithm: 'ed25519',
      publicKey: encodeBase64URL(identity.publicKey),
      signature: encodeBase64URL(identity.signature),
    },
  });
  phase = { kind: 'sent', session, result: { kind: 'registration' } };
  setStatus('Passkey created. Waiting for the CLI to save the trusted credential…');
  await nextCliMessage(session, 'initial-accepted');
  return {
    kind: 'registered',
    title: 'Passkey paired',
    message: 'The CLI saved this passkey as its trusted nearby credential. You can close this page.',
  };
}

async function completeAssertion(session, request, binding, signal) {
  let notice = '';
  for (;;) {
    const disposition = await chooseDisposition(session, request, binding, signal, notice);
    phase = {
      kind: 'ceremony',
      session,
      operation: { kind: 'assertion', request, binding, disposition },
    };
    setScreen(
      'Approve this key request',
      `Approve ${request.keyName} with your passkey.`,
      paragraph('The derived key will be sent only through the end-to-end encrypted relay.'),
    );
    setStatus('Waiting for passkey approval…');
    let result;
    try {
      result = await runAssertion(request, binding, disposition, signal);
    } catch (error) {
      if (!isPasskeyCancellation(error) || signal.aborted) throw error;
      notice = 'The passkey prompt was cancelled or did not open. Nothing was sent; choose again to retry.';
      continue;
    }
    const message = assertionResultMessage(request, result, disposition);
    await session.send(message);
    phase = {
      kind: 'sent',
      session,
      result: { kind: 'assertion', keyName: request.keyName, disposition },
    };
    setStatus('Approved result sent. Waiting for the CLI to verify it…');
    const acknowledgement = await nextCliMessage(session, 'assertion-accepted');
    switch (acknowledgement.storage) {
      case 'once':
        if (disposition !== 'once') throw new ProtocolError('CLI acknowledged the wrong storage disposition');
        return {
          kind: 'once',
          title: 'Key sent',
          message: 'The key was accepted for this command and was not stored on that machine. You can close this page.',
        };
      case 'stored':
        if (disposition !== 'remember') throw new ProtocolError('CLI acknowledged the wrong storage disposition');
        return {
          kind: 'stored',
          title: 'Key remembered',
          message: `The key was accepted and stored on that machine. Remove it later with keytap forget ${request.keyName}.`,
        };
      case 'unavailable':
        if (disposition !== 'remember') throw new ProtocolError('CLI acknowledged the wrong storage disposition');
        return {
          kind: 'storage-unavailable',
          title: 'Could not remember key',
          message: 'The CLI received the approved key but could not confirm that it was stored. Check the terminal before retrying.',
        };
    }
  }
}

export function failureOutcome(error, currentPhase) {
  if (error instanceof CompletedElsewhereError) {
    return {
      kind: 'completed-elsewhere',
      title: 'Approved on the Mac',
      message: 'The passkey approval on the Mac completed first, so this device’s approval was not used. You can close this page.',
    };
  }
  if (error instanceof LocalPairingRejectionError || error instanceof PairingRejectedError) {
    return {
      kind: 'pairing-rejected',
      title: 'Pairing cancelled',
      message: 'The pairing words were not confirmed on both devices. No passkey prompt opened and no key was accepted.',
    };
  }
  if (error instanceof PasskeyPrfUnavailableError) {
    if (currentPhase.kind === 'registration-created') {
      return registrationCreatedUnsavedOutcome();
    }
    return {
      kind: 'capability-unavailable',
      title: 'Passkey not supported here',
      message: 'This browser and passkey did not provide the two PRF outputs required for nearby approval. No key result was sent. Try a current browser or another PRF-capable passkey device.',
    };
  }
  if (error instanceof IdentityProofUnavailableError) {
    if (currentPhase.kind === 'registration-created') {
      return registrationCreatedUnsavedOutcome();
    }
    return {
      kind: 'capability-unavailable',
      title: 'Browser not supported',
      message: 'This browser could not create the passkey identity proof required for nearby approval. No key result was sent. Try a current browser on another device.',
    };
  }
  if (error instanceof InitialRejectionError) {
    if (error.reason === 'identity-store-unavailable') {
      return {
        kind: 'identity-store-unavailable',
        title: 'Could not save trusted identity',
        message: 'The CLI received the passkey result but could not durably save or access its trusted identity. Check the terminal before retrying.',
      };
    }
    return {
      kind: 'identity-rejected',
      title: 'Passkey identity rejected',
      message: 'The passkey identity did not match the identity trusted by the CLI, so no key was accepted.',
    };
  }
  if (error instanceof InitialIndeterminateError) {
    return {
      kind: 'identity-indeterminate',
      title: 'Pairing status unknown',
      message: 'The CLI received the result but could not confirm durable identity storage. Check the terminal before retrying.',
    };
  }
  switch (currentPhase.kind) {
    case 'registration-created':
      return registrationCreatedUnsavedOutcome();
    case 'sent':
      return currentPhase.result.kind === 'registration'
        ? registrationIndeterminateOutcome()
        : assertionIndeterminateOutcome();
    case 'suspended':
      return outcomeForSuspendedPhase(currentPhase);
    case 'boot':
    case 'connecting':
    case 'sas':
    case 'choice':
    case 'ceremony':
      return {
        kind: 'failed',
        title: 'Request failed',
        message: error instanceof ProtocolError && /CLI key|approval link/.test(error.message)
          ? 'This approval link is invalid. Run the keytap command again and open the fresh link.'
          : 'The encrypted request could not be completed. Nothing was sent; run the command again and open the fresh approval link.',
      };
    case 'terminal':
      return currentPhase.outcome;
    case 'expired':
      return expiredOutcome();
  }
  throw new ProtocolError('invalid nearby lifecycle phase');
}

function renderTerminal(outcome) {
  phase = { kind: 'terminal', outcome };
  document.title = `keytap: ${outcome.title.toLowerCase()}`;
  $('title').textContent = outcome.title;
  $('summary').textContent = '';
  $('content').replaceChildren();
  $('details').hidden = true;
  $('status').textContent = '';
  $('alert').textContent = '';
  switch (outcome.kind) {
    case 'registered':
    case 'once':
    case 'stored':
    case 'completed-elsewhere':
      $('status').textContent = outcome.message;
      $('status').focus();
      break;
    case 'storage-unavailable':
    case 'pairing-rejected':
    case 'identity-store-unavailable':
    case 'identity-rejected':
    case 'identity-indeterminate':
    case 'capability-unavailable':
    case 'registration-created-unsaved':
    case 'registration-indeterminate':
    case 'assertion-indeterminate':
    case 'failed':
    case 'expired':
      $('alert').textContent = outcome.message;
      $('alert').focus();
      break;
    default:
      throw new ProtocolError('invalid nearby terminal outcome');
  }
}

export function terminateForPagehide(controller, session) {
  if (!controller.signal.aborted) {
    controller.abort(new DOMException('The page was left.', 'AbortError'));
  }
  session?.close();
}

export function handlePageShow(event, currentPhase = phase) {
  if (!event.persisted) return;
  if (pageLifetime) terminateForPagehide(pageLifetime, activeSession);
  const suspended = currentPhase.kind === 'suspended'
    ? currentPhase
    : suspendPhaseForPagehide(currentPhase);
  phase = suspended;
  renderTerminal(outcomeForSuspendedPhase(suspended));
}

export async function main() {
  if (typeof window !== 'undefined' && !isTopLevelContext(window)) return;
  pageLifetime = new AbortController();
  phase = { kind: 'connecting' };
  setScreen(
    'Connecting to your CLI',
    'Establishing an end-to-end encrypted relay for this one-time request.',
    paragraph('The relay can see that two devices connected, but it cannot read or change an accepted request.'),
  );
  setStatus('Waiting for your CLI…');

  try {
    const cliPublicKey = exactCliPublicKeyFromFragment();
    const established = await openRelay(cliPublicKey, pageLifetime);
    activeSession = established.session;
    setStatus('Encrypted relay connected. Waiting for the request…');
    const requestFrame = await activeSession.nextRaw();
    const request = parseInitialRequest(requestFrame.value);
    let outcome;
    switch (request.kind) {
      case 'register': {
        const sasDigest = await runSas(
          activeSession,
          established.sessionBinding,
          request,
          requestFrame.bytes,
          pageLifetime.signal,
        );
        outcome = await completeRegistration(
          activeSession,
          request,
          sasDigest,
          pageLifetime.signal,
        );
        break;
      }
      case 'assert': {
        const binding = await assertionProofBinding(
          request.identity,
          established.sessionBinding,
          requestFrame.bytes,
          () => runSas(
            activeSession,
            established.sessionBinding,
            request,
            requestFrame.bytes,
            pageLifetime.signal,
          ),
        );
        outcome = await completeAssertion(
          activeSession,
          request,
          binding,
          pageLifetime.signal,
        );
        break;
      }
      default:
        throw new ProtocolError('invalid nearby request');
    }
    renderTerminal(outcome);
    activeSession.close();
  } catch (error) {
    if (phase.kind === 'expired' || pageLifetime.signal.reason?.message === 'The page was left.') return;
    const failure = pageLifetime.signal.aborted && pageLifetime.signal.reason instanceof Error
      ? pageLifetime.signal.reason
      : error;
    const outcome = failureOutcome(failure, phase);
    renderTerminal(outcome);
    activeSession?.close();
  }
}

if (typeof document !== 'undefined' && typeof window !== 'undefined') {
  if (revealTopLevelPage(window, document.documentElement)) {
    window.addEventListener('pagehide', () => {
      const controller = pageLifetime;
      const session = activeSession;
      phase = suspendPhaseForPagehide(phase);
      if (controller) terminateForPagehide(controller, session);
    });
    window.addEventListener('pageshow', handlePageShow);
    main();
  }
}
