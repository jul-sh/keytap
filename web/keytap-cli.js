'use strict';

// The `keytap` command of the web terminal. Parsing, help, and crypto all
// happen inside the wasm build of the real CLI (cliInvoke and friends);
// this module only routes: argv in, ceremonies via WebAuthn, bytes out —
// plus the muted follow-up lines the page prints as chrome.

import {
  cliInvoke,
  deriveRawKey,
  formatPrivateKey,
  formatPublicKey,
  encryptAge,
  decryptAge,
} from './pkg/keytap_web.js';

import { register, assertPrf, webAuthnAvailable, hasStoredCredential } from './webauthn.js';
import { encode } from './shell.js';

const empty = new Uint8Array(0);

// Commands that store state on "this machine" have no home in a page that
// deliberately keeps none. One loud error, naming the fix.
const STATELESS =
  'this web terminal keeps no state, so keys are never remembered here. ' +
  'Install the CLI to remember keys on a machine: https://github.com/jul-sh/keytap';

const NEXT_REVEAL = 'keytap reveal demo --as ssh';

/**
 * Create the `keytap` handler.
 * @param {{ begin: (kind: 'create'|'get', name?: string) => Promise<void>,
 *           signal: () => AbortSignal, end: () => void }} ceremony
 * @param {{ hint: (t: string) => void,
 *           hintCmd: (pre: string, cmd: string, post: string) => void,
 *           hintLink: (pre: string, url: string) => void }} ui
 */
export function createKeytapCommand(ceremony, ui) {
  async function registerHere() {
    await ceremony.begin('create');
    try {
      await register(ceremony.signal());
    } finally {
      ceremony.end();
    }
  }

  async function assertOnce(name) {
    await ceremony.begin('get', name);
    try {
      const prf = await assertPrf(name, ceremony.signal());
      return new Uint8Array(deriveRawKey(prf));
    } finally {
      ceremony.end();
    }
  }

  // Resolve the raw key for `name`. When this browser has never completed a
  // ceremony and the prompt comes back empty-handed, init is implicit: create
  // the passkey (narrated), then continue the original command. The assertion
  // is still attempted first so a visitor whose passkey synced from another
  // device picks it instead of minting a new root.
  async function rawKeyFor(name, err) {
    try {
      return await assertOnce(name);
    } catch (error) {
      const cancelled = error instanceof Error && error.message === 'cancelled';
      if (!cancelled || hasStoredCredential()) throw error;
      ui.hint('no passkey in this browser yet — creating one, then continuing.');
      await registerHere();
      err('Passkey registered successfully.');
      return await assertOnce(name);
    }
  }


  // Muted reassurance under a freshly revealed key — the moment of maximum
  // "should this be on my screen?".
  function revealFooter(name, format) {
    ui.hint(
      `derived, not stored, not sent — same passkey + name '${name}' reproduces this exact key on any device`
    );
    if (format === 'ssh') {
      ui.hintCmd('the public half: ', `keytap public ${name} --as ssh`, '');
    }
    try {
      if (!sessionStorage.getItem('keytap:web:cli-bridge')) {
        sessionStorage.setItem('keytap:web:cli-bridge', '1');
        ui.hintLink(
          'use it for real work: install the CLI (it uses this same passkey) — ',
          'https://github.com/jul-sh/keytap'
        );
      }
    } catch {
      // Ignore storage errors
    }
  }

  return async function keytap(argv, stdin, fs, err) {
    const outcome = cliInvoke(argv);

    if (outcome.kind === 'output') {
      if (outcome.stderr) err(outcome.stderr.replace(/\n$/, ''));
      const result = { stdout: encode(outcome.stdout), code: outcome.exit };
      // The bare `keytap` reference ends on a long command list; leave a
      // tappable next step so mobile visitors aren't stranded at the bottom.
      if (argv.length === 1 && outcome.exit === 0) {
        result.after = () =>
          ui.hintCmd('next: ', hasStoredCredential() ? NEXT_REVEAL : 'keytap init', '');
      }
      return result;
    }

    const cmd = outcome.command;

    // Stateless-by-design commands answer without any ceremony.
    if (cmd.cmd === 'remember' || cmd.cmd === 'forget' || cmd.cmd === 'remembered') {
      err(`error: ${STATELESS}`);
      return { stdout: empty, code: 1 };
    }

    if (!webAuthnAvailable()) {
      err('error: WebAuthn is not available in this browser, so no passkey ceremony can run.');
      return { stdout: empty, code: 1 };
    }

    try {
      switch (cmd.cmd) {
        case 'init': {
          await registerHere();
          err('Passkey registered successfully.');
          return {
            stdout: empty,
            code: 0,
            after: () =>
              ui.hintCmd(
                'your password manager syncs this passkey — that sync is your backup. next: ',
                NEXT_REVEAL,
                ' (Touch ID / Face ID again — every reveal asks)'
              ),
          };
        }

        case 'public': {
          const rawKey = await rawKeyFor(cmd.name, err);
          const text = formatPublicKey(rawKey, cmd.format, cmd.name);
          return { stdout: encode(text + '\n'), code: 0 };
        }

        case 'reveal': {
          const rawKey = await rawKeyFor(cmd.name, err);
          const bytes = new Uint8Array(formatPrivateKey(rawKey, cmd.format));
          // SSH PEM already ends in a newline; others are single-line values.
          const newline = cmd.format === 'ssh' ? empty : encode('\n');
          const stdout = new Uint8Array(bytes.length + newline.length);
          stdout.set(bytes);
          stdout.set(newline, bytes.length);
          return { stdout, code: 0, after: () => revealFooter(cmd.name, cmd.format) };
        }

        case 'encrypt': {
          const labels = [];
          const contents = [];
          for (const file of cmd.recipientsFile) {
            const data = fs.get(file);
            if (data === undefined) {
              err(`error: failed to read recipients file ${file}: no such file`);
              return { stdout: empty, code: 1 };
            }
            labels.push(file);
            contents.push(new TextDecoder().decode(data));
          }
          const rawKey = await rawKeyFor(cmd.name, err);
          const selfKey = cmd.noSelf ? undefined : rawKey;
          const stdout = new Uint8Array(encryptAge(selfKey, cmd.recipients, labels, contents, stdin));
          return { stdout, code: 0 };
        }

        case 'decrypt': {
          const rawKey = await rawKeyFor(cmd.name, err);
          const stdout = new Uint8Array(decryptAge(rawKey, stdin));
          return { stdout, code: 0 };
        }

        default:
          err(`error: unhandled command: ${cmd.cmd}`);
          return { stdout: empty, code: 1 };
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      err(`error: ${message}`);
      return { stdout: empty, code: 1 };
    }
  };
}
