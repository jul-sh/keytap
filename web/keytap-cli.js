'use strict';

// The `keytap` command of the web terminal. Parsing and help come from the
// shared CLI spec, and derivation comes from keytap-core, all through cliRun.
// This module supplies the browser platform: WebAuthn ceremonies, the shell's
// files, stderr, and the muted follow-up hints the page prints as chrome.

import { cliRun } from './pkg/keytap_web.js';
import {
  register,
  assertPrf,
  webAuthnAvailable,
  hasStoredCredentialId,
} from './webauthn.js';

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
      hasCredentialId: () => hasStoredCredentialId(),
      readFile: (name) => fs.get(name),
      stderr: (text) => err(text),
    };
  }

  // Muted follow-ups under a command's output; chrome, never CLI behavior.
  function followUp(argv, ran) {
    if (ran === null) {
      // The bare `keytap` reference ends on a long command list; leave a
      // pair of honest next steps without treating this browser's local
      // credential-ID cache as proof that an existing passkey does not exist.
      if (argv.length === 1) {
        return () => {
          ui.hintCmd('already have a keytap passkey? try ', NEXT_REVEAL, ' and choose it.');
          ui.hintCmd('new to keytap? ', 'keytap init', ' creates a new passkey.');
        };
      }
      return undefined;
    }
    if (ran.cmd === 'init') {
      return () => {
        ui.hint(
          'make sure this passkey is available on another device or has a recovery path; keytap cannot recover derived keys without it'
        );
        ui.hintCmd(
          'next: ',
          NEXT_REVEAL,
          ' (it asks again; every reveal does)'
        );
      };
    }
    if (ran.cmd === 'reveal') {
      return () => {
        ui.hint(
          `this named derived key was not persisted or sent over the network; same passkey + name '${ran.name}' reproduces it wherever that passkey is available`
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
      if (message === 'cancelled' && argv[1] !== 'init') {
        ui.hint(
          'approval cancelled. an existing synced or security-key passkey may still be available even if this browser has not seen it before; retry and choose it. run keytap init only to create a new passkey.'
        );
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
