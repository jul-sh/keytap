'use strict';

// The terminal: rendering, line editing, history, completion. All keytap
// behavior comes from the wasm CLI via keytap-cli.js; this file is chrome.
//
// The hidden input (#term-kbd) is the real line editor: its value is the
// buffer, its selectionStart is the caret. The visible prompt line is an
// aria-hidden mirror of it. Native editing (backspace, arrows, selection,
// IME) therefore just works, and assistive tech sees a real text field.

import init, { cliVersion, cliCompletions } from './pkg/keytap_web.js';
import { createFs, runPipeline, decode, builtins, ShellError } from './shell.js';
import { createKeytapCommand } from './keytap-cli.js';

const PROMPT = '$ ';

// Chrome-authored literal commands; what they do is decided by the CLI.
const SUGGESTIONS = [
  { cmd: 'keytap init', note: 'creates a passkey (no account, deletable anytime)' },
  { cmd: 'keytap reveal demo --as ssh', note: 'turns it into an ssh key named demo' },
  { cmd: 'keytap', note: 'full command list' },
];

const HELP = `keytap web terminal; the real CLI, compiled to WebAssembly.

  keytap …                      the actual keytap CLI (start with \`keytap\`)
  ls · cat · echo · rm · xxd    a tiny in-memory filesystem
  pipes and redirects           echo hi | keytap encrypt > hi.age
  clear (or ctrl+l)             wipe the screen

tab key completes · ↑ ↓ history · ctrl+c or esc cancels a passkey prompt
shift+tab moves focus out of the terminal.

how keys derive: WebAuthn PRF; your authenticator releases a per-name secret
after Touch ID, and keys are HKDF-derived from it. same input, same key. the
installed tool reaches the same passkey for this domain, so web and cli derive
identical keys (how: the install keytap readme).
network: locked down by the CSP meta tag (view-source); static page, no
server code, no analytics.
printed output is readable by your browser and its extensions; don't reuse
this demo's key names. real key work belongs in the installed tool.
`;

// ── DOM ──

const el = {
  screen: document.getElementById('term-screen'),
  out: document.getElementById('term-out'),
  promptEl: document.getElementById('term-prompt'),
  pre: document.getElementById('term-pre'),
  cursor: document.getElementById('term-cursor'),
  post: document.getElementById('term-post'),
  kbd: document.getElementById('term-kbd'),
  inputLine: document.getElementById('term-input-line'),
};

// ── State ──

const fs = createFs();
let history = [];
let historyAt = -1; // -1 = editing a fresh line
let stashedLine = '';
let running = false;
const pendingLines = [];
let pendingFragment = null;
let completionsSpec = [];

try {
  history = JSON.parse(sessionStorage.getItem('keytap:web:history') || '[]');
} catch {
  history = [];
}

// ── Ceremony hooks ──
// One busy line in the log carries the state, the trust claim (front-loaded,
// so screen readers hear it before the OS sheet seizes focus), and; being a
// button; the tap-to-cancel that mobile otherwise lacks.

let abortController = null;
let busyLine = null;
let busyAlert = null;

const ceremony = {
  async begin(kind, name) {
    abortController = new AbortController();
    const text =
      kind === 'create'
        ? 'passkey prompt; nothing is sent by this page · creating your passkey · tap this line or esc cancels'
        : `passkey prompt; nothing is sent by this page · waiting for ${name} · tap this line or esc cancels`;
    busyLine = document.createElement('button');
    busyLine.type = 'button';
    busyLine.className = 'ln busy';
    busyLine.textContent = text;
    busyAlert = document.createElement('div');
    busyAlert.className = 'visually-hidden';
    busyAlert.setAttribute('role', 'alert');
    busyAlert.textContent = text;
    el.out.append(busyLine, busyAlert);
    scrollToBottom();
    // Give assistive tech a beat to speak before the OS sheet takes over.
    await new Promise((r) => setTimeout(r, 220));
  },
  signal: () => abortController?.signal,
  end() {
    abortController = null;
    const hadFocus = busyLine?.contains(document.activeElement);
    busyLine?.remove();
    busyAlert?.remove();
    busyLine = null;
    busyAlert = null;
    // Safari parks focus on <body> after system sheets; bring it home.
    if (hadFocus || document.activeElement === document.body) {
      el.kbd.focus({ preventScroll: true });
    }
  },
};

// ── Output ──

function scrollToBottom() {
  el.screen.scrollTop = el.screen.scrollHeight;
}

// Control characters other than newline/tab render as middle dots; binary
// output (age ciphertext) stays legible instead of wrecking the layout.
function sanitize(text) {
  // eslint-disable-next-line no-control-regex
  return text.replace(/[\x00-\x08\x0B-\x1F\x7F]/g, '·');
}

function writeBlock(text, className) {
  const div = document.createElement('div');
  div.className = className;
  div.textContent = sanitize(text.replace(/\n$/, ''));
  el.out.appendChild(div);
  scrollToBottom();
  return div;
}

// An echoed prompt line: the prompt keeps its color, the command is plain.
function writeEcho(line) {
  const div = document.createElement('div');
  div.className = 'ln echo';
  const p = document.createElement('span');
  p.className = 'p';
  p.textContent = PROMPT;
  div.append(p, sanitize(line));
  el.out.appendChild(div);
  scrollToBottom();
}

// Pipeline stdout: rendered sanitized, copied raw; SSH keys and age
// ciphertext must survive the trip to the clipboard byte-for-byte. Long
// blocks (key material) are kept out of the live region so screen readers
// don't dictate private keys; a short summary speaks instead.
function writeResult(text) {
  const div = writeBlock(text, 'ln res');
  const lines = div.textContent.split('\n').length;
  if (lines > 4) {
    div.setAttribute('aria-live', 'off');
    const summary = document.createElement('div');
    summary.className = 'visually-hidden';
    summary.textContent = `output, ${lines} lines; copy button follows`;
    el.out.appendChild(summary);
  }
  const copy = document.createElement('button');
  copy.type = 'button';
  copy.className = 'copy';
  copy.setAttribute('aria-label', 'copy output');
  const label = document.createElement('span');
  label.setAttribute('aria-live', 'polite');
  label.textContent = 'copy';
  copy.appendChild(label);
  copy.raw = text.replace(/\n$/, '');
  div.appendChild(copy);
  scrollToBottom();
}

// A muted line with an embedded tap-to-run command.
function writeHintCmd(pre, cmd, post) {
  const div = document.createElement('div');
  div.className = 'ln hint';
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'cmd';
  btn.textContent = cmd;
  div.append(pre, btn, post);
  el.out.appendChild(div);
  scrollToBottom();
}

// A line with a real link (the only place the page points off-site).
function writeLinkLine(pre, url, label, post = '', className = 'ln hint') {
  const div = document.createElement('div');
  div.className = className;
  const a = document.createElement('a');
  a.href = url;
  a.textContent = label;
  if (label !== url.replace(/^https:\/\//, '')) a.setAttribute('aria-label', 'install keytap, on github');
  div.append(pre, a, post);
  el.out.appendChild(div);
  scrollToBottom();
}

function writeHintLink(pre, url) {
  writeLinkLine(pre, url, url.replace(/^https:\/\//, ''));
}

const io = {
  out: (text) => writeBlock(text, 'ln'),
  err: (text) => writeBlock(text, 'ln err'),
  hint: (text) => writeBlock(text, 'ln hint'),
  hintCmd: writeHintCmd,
  hintLink: writeHintLink,
  echo: writeEcho,
  result: writeResult,
};

function printSuggestions() {
  io.hint('tap a command to run it, or type:');
  const width = Math.max(...SUGGESTIONS.map((s) => s.cmd.length));
  for (const { cmd, note } of SUGGESTIONS) {
    const div = document.createElement('div');
    div.className = 'ln hint';
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'cmd';
    btn.textContent = cmd;
    div.append('  ', btn, ' '.repeat(width - cmd.length) + '    ' + note);
    el.out.appendChild(div);
  }
  scrollToBottom();
}

// ── Line editing (the input is the source of truth) ──

function renderLine() {
  const text = el.kbd.value;
  const at = el.kbd.selectionStart ?? text.length;
  el.pre.textContent = text.slice(0, at);
  el.cursor.textContent = text[at] ?? ' ';
  el.post.textContent = text.slice(at + 1);
}

function setBuffer(text, at = text.length) {
  el.kbd.value = text;
  el.kbd.setSelectionRange(at, at);
  renderLine();
}

function insertText(text) {
  const at = el.kbd.selectionStart ?? el.kbd.value.length;
  const end = el.kbd.selectionEnd ?? at;
  setBuffer(el.kbd.value.slice(0, at) + text + el.kbd.value.slice(end), at + text.length);
  historyAt = -1;
}

function killLine() {
  setBuffer('');
}

function killWord() {
  const at = el.kbd.selectionStart ?? el.kbd.value.length;
  const head = el.kbd.value.slice(0, at).replace(/\S+\s*$/, '');
  setBuffer(head + el.kbd.value.slice(at), head.length);
}

function clearScreen() {
  el.out.textContent = '';
}

// ── History ──

function pushHistory(line) {
  if (line.trim() === '' || history[history.length - 1] === line) return;
  history.push(line);
  if (history.length > 200) history = history.slice(-200);
  try {
    sessionStorage.setItem('keytap:web:history', JSON.stringify(history));
  } catch {
    // Ignore storage errors
  }
}

function historyStep(direction) {
  if (history.length === 0) return;
  if (historyAt === -1) {
    if (direction > 0) return;
    stashedLine = el.kbd.value;
    historyAt = history.length - 1;
  } else {
    historyAt += direction;
  }
  if (historyAt >= history.length) {
    historyAt = -1;
    setBuffer(stashedLine);
    return;
  }
  if (historyAt < 0) historyAt = 0;
  setBuffer(history[historyAt]);
}

// ── Completion ──
// keytap subcommands and flags come from the CLI's own clap metadata
// (cliCompletions); shell names and filenames are chrome.

function completionCandidates(tokens, endsWithSpace) {
  const shellNames = [...Object.keys(builtins), 'keytap', 'help', 'clear'];
  const current = endsWithSpace ? '' : tokens[tokens.length - 1] || '';
  const prior = endsWithSpace ? tokens : tokens.slice(0, -1);

  if (prior.length === 0) return { current, options: shellNames };

  const last = prior[prior.length - 1];
  if (last === '|') return { current, options: shellNames };

  if (last === '<' || last === '>' || last === '>>') {
    return { current, options: [...fs.keys()] };
  }

  const keytapAt = prior.lastIndexOf('keytap');
  const pipeAt = prior.lastIndexOf('|');
  if (keytapAt > pipeAt) {
    const sub = prior[keytapAt + 1];
    if (sub === undefined) {
      return { current, options: completionsSpec.map(([name]) => name) };
    }
    const spec = completionsSpec.find(([name]) => name === sub);
    if (current.startsWith('-') && spec) return { current, options: spec[1] };
    if (sub === 'encrypt' && last === '-R') return { current, options: [...fs.keys()] };
    return { current, options: [] };
  }

  return { current, options: [...fs.keys()] };
}

let optionsPrintedFor = null;

function complete() {
  const at = el.kbd.selectionStart ?? el.kbd.value.length;
  const head = el.kbd.value.slice(0, at);
  const endsWithSpace = /\s$/.test(head) || at === 0;
  const tokens = head.split(/\s+/).filter(Boolean);
  const { current, options } = completionCandidates(tokens, endsWithSpace);
  const matches = options.filter((o) => o.startsWith(current) && o !== current);
  if (matches.length === 0) return;

  if (matches.length === 1) {
    insertText(matches[0].slice(current.length) + ' ');
    return;
  }

  let prefix = matches[0];
  for (const m of matches) {
    while (!m.startsWith(prefix)) prefix = prefix.slice(0, -1);
  }
  if (prefix.length > current.length) {
    insertText(prefix.slice(current.length));
  } else if (optionsPrintedFor !== el.kbd.value) {
    // List candidates once per line state; holding Tab shouldn't spam.
    io.out(matches.join('  '));
    optionsPrintedFor = el.kbd.value;
  }
}

// ── Execution ──
// Exit codes are not displayed: every failing path already prints stderr.
// A future command that fails silently would break that convention.

async function execute(line) {
  io.echo(line);
  pushHistory(line);
  setBuffer('');
  historyAt = -1;

  const trimmed = line.trim();
  if (trimmed === '') return;
  if (trimmed === 'clear') {
    clearScreen();
    return;
  }
  if (trimmed === 'help') {
    io.out(HELP);
    printSuggestions();
    return;
  }

  running = true;
  // The mirror goes invisible but the line (and the focused input inside
  // it) stays in the layout, so the mobile keyboard never dismisses.
  el.inputLine.classList.add('running');
  el.kbd.readOnly = true;
  try {
    const result = await runPipeline(line, fs, commands, io.err);
    if (result.stdout.length > 0) io.result(decode(result.stdout));
    result.after?.();
  } catch (error) {
    if (error instanceof ShellError) {
      io.err(`sh: ${error.message}`);
    } else {
      io.err(`error: ${error instanceof Error ? error.message : String(error)}`);
    }
  } finally {
    running = false;
    el.inputLine.classList.remove('running');
    el.kbd.readOnly = false;
    scrollToBottom();
  }

  if (pendingLines.length > 0) {
    await execute(pendingLines.shift());
  } else if (pendingFragment !== null) {
    setBuffer(pendingFragment);
    pendingFragment = null;
  }
}

const commands = {};

// ── Keyboard ──
// Editing keys are native (the input is real); keydown handles only what a
// text field doesn't already do: run, complete, history, chords, abort.

function onKeyDown(event) {
  const { key, ctrlKey, metaKey, altKey } = event;
  // Chord letters compare case-insensitively (shift or caps must not matter).
  const chord = key.length === 1 ? key.toLowerCase() : key;

  // Ctrl+C / Esc abort a pending ceremony even while a command runs.
  if ((ctrlKey && chord === 'c') || key === 'Escape') {
    if (abortController) {
      abortController.abort();
      event.preventDefault();
      return;
    }
    if (!running && ctrlKey && chord === 'c') {
      io.echo(el.kbd.value + '^C');
      setBuffer('');
      historyAt = -1;
      event.preventDefault();
    }
    return;
  }

  if (running) return;
  if (metaKey) return; // Leave cmd+c/cmd+v etc. to the browser.

  if (ctrlKey) {
    const handled = {
      l: clearScreen,
      u: killLine,
      w: killWord,
      a: () => setBuffer(el.kbd.value, 0),
      e: () => setBuffer(el.kbd.value, el.kbd.value.length),
      k: () => {
        const at = el.kbd.selectionStart ?? 0;
        setBuffer(el.kbd.value.slice(0, at), at);
      },
    }[chord];
    if (handled) {
      handled();
      event.preventDefault();
    }
    return;
  }
  if (altKey) return;

  switch (key) {
    case 'Enter':
      event.preventDefault();
      void execute(el.kbd.value);
      break;
    case 'ArrowUp':
      historyStep(-1);
      event.preventDefault();
      break;
    case 'ArrowDown':
      historyStep(1);
      event.preventDefault();
      break;
    case 'Tab':
      // Shift+Tab moves native focus out (to the github link); the
      // keyboard-only escape from the terminal.
      if (event.shiftKey) return;
      complete();
      event.preventDefault();
      break;
    default:
      // Everything else (characters, backspace, arrows, selection) is the
      // input's own business; the mirror re-renders from events below.
      historyAt = -1;
  }
}

function onPaste(event) {
  const text = event.clipboardData?.getData('text');
  if (!text || running) return;
  if (!text.includes('\n') && !text.includes('\r')) return; // native insert

  event.preventDefault();
  const lines = text.split(/\r?\n/);
  const fragment = lines.pop(); // text after the last newline stays editable
  // The first pasted line completes the current buffer and runs; complete
  // lines after it queue up behind it.
  insertText(lines[0]);
  pendingLines.push(...lines.slice(1));
  if (fragment) pendingFragment = fragment;
  void execute(el.kbd.value);
}

// ── Focus & pointer ──

const finePointer = window.matchMedia?.('(hover: hover) and (pointer: fine)');

function focusKeyboard(event) {
  // Reviewing output (or tapping a button in it) must not pop the keyboard.
  if (event?.target instanceof Element && event.target.closest('#term-out')) return;
  if (document.getSelection()?.toString()) return; // don't steal a selection
  el.kbd.focus({ preventScroll: true });
}

// One delegated listener covers every button the log will ever hold.
function onOutClick(event) {
  if (!(event.target instanceof Element)) return;

  const cmd = event.target.closest('button.cmd');
  if (cmd) {
    if (running || document.getSelection()?.toString()) return;
    // On keyboard-first devices, hand focus back to the prompt; on touch,
    // don't summon the software keyboard.
    if (finePointer?.matches) el.kbd.focus({ preventScroll: true });
    void execute(cmd.textContent);
    return;
  }

  const copy = event.target.closest('button.copy');
  if (copy) {
    navigator.clipboard
      .writeText(copy.raw ?? '')
      .then(() => flipCopy(copy, 'copied'))
      .catch(() => {
        flipCopy(copy, 'failed');
        const range = document.createRange();
        range.selectNodeContents(copy.parentElement);
        const selection = document.getSelection();
        selection?.removeAllRanges();
        selection?.addRange(range);
      });
    return;
  }

  if (event.target.closest('button.busy')) {
    abortController?.abort();
  }
}

function flipCopy(button, state) {
  const label = button.firstElementChild ?? button;
  button.dataset.state = state;
  label.textContent = state;
  setTimeout(() => {
    label.textContent = 'copy';
    delete button.dataset.state;
  }, 1200);
}

// ── Boot ──

async function main() {
  el.promptEl.textContent = PROMPT;
  renderLine();

  el.screen.addEventListener('mouseup', focusKeyboard);
  el.screen.addEventListener('touchend', focusKeyboard);
  el.out.addEventListener('click', onOutClick);
  el.kbd.addEventListener('keydown', onKeyDown);
  el.kbd.addEventListener('paste', onPaste);
  el.kbd.addEventListener('input', renderLine);
  el.kbd.addEventListener('keyup', renderLine);
  el.kbd.addEventListener('mouseup', renderLine);
  document.addEventListener('selectionchange', () => {
    if (document.activeElement === el.kbd) renderLine();
  });
  el.kbd.addEventListener('focus', () => el.screen.classList.add('focused'));
  el.kbd.addEventListener('blur', () => el.screen.classList.remove('focused'));

  // Keep the prompt above the software keyboard.
  window.visualViewport?.addEventListener('resize', () => {
    document.documentElement.style.setProperty('--vvh', `${window.visualViewport.height}px`);
  });

  const loading = io.hint('loading…');
  await init();
  loading.remove();
  completionsSpec = cliCompletions();
  commands.keytap = createKeytapCommand(ceremony, io);

  io.out(`keytap ${cliVersion()} · a convenience CLI that derives stable secrets from a passkey, e.g. ssh keys or file encryption.`);
  writeLinkLine(
    'this page runs the CLI compiled to WebAssembly as a demo; install on your machine ',
    'https://github.com/jul-sh/keytap#install',
    'here',
    '.',
    'ln'
  );
  io.out('');
  printSuggestions();
  io.out('');
  writeHintLine();
  focusKeyboard();
}

// The bottom hint line, with `help` tappable; touch devices get the
// tap-first variant instead of keyboard lore.
function writeHintLine() {
  const coarse = window.matchMedia?.('(pointer: coarse)').matches;
  const pre = coarse ? 'tap any printed command to run it · ' : 'tab key completes · ↑ history · ';
  io.hintCmd(pre, 'help', ' for more');
}

main().catch((error) => {
  io.err(`error: failed to initialize: ${error instanceof Error ? error.message : String(error)}`);
});
