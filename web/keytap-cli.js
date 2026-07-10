'use strict';

// The `keytap` command of the web terminal. Parsing, help, and execution all
// happen inside the wasm build of the real CLI (cliRun); this module is the
// platform: WebAuthn ceremonies, the shell's files, stderr, and the muted
// follow-up hints the page prints as chrome.

import { cliRun } from './pkg/keytap_web.js';
import { register, assertPrf, webAuthnAvailable, hasStoredCredential } from './webauthn.js';

const empty = new Uint8Array(0);

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
  function requireWebAuthn() {
    if (!webAuthnAvailable()) {
      throw new Error('WebAuthn is not available in this browser, so no passkey ceremony can run.');
    }
  }

  // What the wasm CLI calls back into; ceremony UX included.
  function makeHost(fs, err) {
    return {
      async register() {
        requireWebAuthn();
        await ceremony.begin('create');
        try {
          await register(ceremony.signal());
        } finally {
          ceremony.end();
        }
      },
      async prf(name) {
        requireWebAuthn();
        await ceremony.begin('get', name);
        try {
          return await assertPrf(name, ceremony.signal());
        } finally {
          ceremony.end();
        }
      },
      readFile: (name) => fs.get(name),
      stderr: (text) => err(text),
    };
  }

  // Muted follow-ups under a command's output; chrome, never CLI behavior.
  function followUp(argv, ran) {
    if (ran === null) {
      // The bare `keytap` reference ends on a long command list; leave a
      // tappable next step so mobile visitors aren't stranded at the bottom.
      if (argv.length === 1) {
        return () => ui.hintCmd('next: ', hasStoredCredential() ? NEXT_REVEAL : 'keytap init', '');
      }
      return undefined;
    }
    if (ran.cmd === 'init') {
      return () =>
        ui.hintCmd(
          "this passkey syncs across your devices; that's the backup. next: ",
          NEXT_REVEAL,
          ' (it asks again; every reveal does)'
        );
    }
    if (ran.cmd === 'reveal') {
      return () => {
        ui.hint(
          `derived, not stored, not sent; same passkey + name '${ran.name}' reproduces this exact key on any device`
        );
        if (ran.format === 'ssh') {
          ui.hintCmd('the public half: ', `keytap public ${ran.name} --as ssh`, '');
        }
        try {
          if (!sessionStorage.getItem('keytap:web:cli-bridge')) {
            sessionStorage.setItem('keytap:web:cli-bridge', '1');
            ui.hintLink(
              'use it for real work: install keytap (it uses this same passkey): ',
              'https://github.com/jul-sh/keytap'
            );
          }
        } catch {
          // Ignore storage errors
        }
      };
    }
    return undefined;
  }

  return async function keytap(argv, stdin, fs, err) {
    let result;
    try {
      result = await cliRun(argv, stdin, makeHost(fs, err));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      err(`error: ${message}`);
      // A dismissed prompt in a browser that has never completed a ceremony
      // usually means there is no passkey to pick; offer the fix, one tap.
      if (message === 'cancelled' && argv[1] !== 'init' && !hasStoredCredential()) {
        ui.hintCmd('no passkey in this browser yet; ', 'keytap init', ' creates one.');
      }
      return { stdout: empty, code: 1 };
    }

    return {
      stdout: result.stdout ?? empty,
      code: result.exit,
      after: result.exit === 0 ? followUp(argv, result.ran) : undefined,
    };
  };
}
