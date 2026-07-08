'use strict';

// The `keytap` command of the web terminal. Parsing, help, and crypto all
// happen inside the wasm build of the real CLI (cliInvoke and friends);
// this module only routes: argv in, ceremonies via WebAuthn, bytes out.

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

/**
 * Create the `keytap` handler.
 * @param {{ begin: (label: string) => void, signal: () => AbortSignal, end: () => void }} ceremony
 *   UI hooks: `begin` marks a pending passkey prompt (arming an abort
 *   controller wired to Ctrl+C), `signal` exposes it, `end` clears it.
 */
export function createKeytapCommand(ceremony) {
  async function rawKeyFor(name) {
    ceremony.begin(`waiting for passkey · ${name}`);
    try {
      const prf = await assertPrf(name, ceremony.signal());
      return new Uint8Array(deriveRawKey(prf));
    } finally {
      ceremony.end();
    }
  }

  return async function keytap(argv, stdin, fs, err) {
    const outcome = cliInvoke(argv);

    if (outcome.kind === 'output') {
      if (outcome.stderr) err(outcome.stderr.replace(/\n$/, ''));
      return { stdout: encode(outcome.stdout), code: outcome.exit };
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
          ceremony.begin('waiting for passkey · init');
          try {
            await register(ceremony.signal());
          } finally {
            ceremony.end();
          }
          err('Passkey registered successfully.');
          return { stdout: empty, code: 0 };
        }

        case 'public': {
          const rawKey = await rawKeyFor(cmd.name);
          const text = formatPublicKey(rawKey, cmd.format, cmd.name);
          return { stdout: encode(text + '\n'), code: 0 };
        }

        case 'reveal': {
          const rawKey = await rawKeyFor(cmd.name);
          const bytes = new Uint8Array(formatPrivateKey(rawKey, cmd.format));
          // SSH PEM already ends in a newline; others are single-line values.
          const newline = cmd.format === 'ssh' ? empty : encode('\n');
          const stdout = new Uint8Array(bytes.length + newline.length);
          stdout.set(bytes);
          stdout.set(newline, bytes.length);
          return { stdout, code: 0 };
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
          const rawKey = await rawKeyFor(cmd.name);
          const selfKey = cmd.noSelf ? undefined : rawKey;
          const stdout = new Uint8Array(encryptAge(selfKey, cmd.recipients, labels, contents, stdin));
          return { stdout, code: 0 };
        }

        case 'decrypt': {
          const rawKey = await rawKeyFor(cmd.name);
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
      // A dismissed prompt in a browser that has never completed a ceremony
      // usually means there is no passkey to pick — say so.
      if (message === 'cancelled' && cmd.cmd !== 'init' && !hasStoredCredential()) {
        err('hint: no passkey seen in this browser yet — `keytap init` creates one.');
      }
      return { stdout: empty, code: 1 };
    }
  };
}
