'use strict';

// The terminal: rendering, line editing, history, completion. All keytap
// behavior comes from the wasm CLI via keytap-cli.js; this file is chrome.

import init, { cliVersion, cliCompletions } from './pkg/keytap_web.js';
import { createFs, runPipeline, decode, builtins, ShellError } from './shell.js';
import { createKeytapCommand } from './keytap-cli.js';

const PROMPT = 'guest@keytap:~$ ';

const HELP = `keytap web terminal — the real CLI, compiled to WebAssembly.

  keytap …            the actual keytap CLI (start with \`keytap\`)
  ls · cat · echo · rm · xxd    a tiny in-memory filesystem
  pipes and redirects           echo hi | keytap encrypt > hi.age
  clear (or ctrl+l)             wipe the screen

History with ↑/↓, completion with tab, ctrl+c cancels a passkey prompt.
Nothing here is stored or sent anywhere: keys derive locally and the
filesystem lives in this tab's memory.
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
  status: document.getElementById('term-status'),
  inputLine: document.getElementById('term-input-line'),
};

// ── State ──

const fs = createFs();
let buffer = '';
let cursorAt = 0; // index into buffer
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
historyAt = -1;

// ── Ceremony hooks (status line + Ctrl+C abort) ──

let abortController = null;

const ceremony = {
  begin(label) {
    abortController = new AbortController();
    setStatus(label + ' — esc or ctrl+c cancels', 'busy');
  },
  signal: () => abortController?.signal,
  end() {
    abortController = null;
    setStatus('ready', 'idle');
  },
};

function setStatus(text, mode) {
  el.status.textContent = text;
  el.status.dataset.mode = mode;
}

// ── Output ──

function scrollToBottom() {
  el.screen.scrollTop = el.screen.scrollHeight;
}

// Control characters other than newline/tab render as middle dots — binary
// output (age ciphertext) stays legible instead of wrecking the layout.
function sanitize(text) {
  // eslint-disable-next-line no-control-regex
  return text.replace(/[\x00-\x08\x0B-\x1F\x7F]/g, '\u00B7');
}

function writeBlock(text, className) {
  const div = document.createElement('div');
  div.className = className;
  div.textContent = sanitize(text.replace(/\n$/, ''));
  el.out.appendChild(div);
  scrollToBottom();
}

const io = {
  out: (text) => writeBlock(text, 'ln'),
  err: (text) => writeBlock(text, 'ln err'),
  echo: (text) => writeBlock(text, 'ln echo'),
};

// ── Line rendering ──

function renderLine() {
  el.pre.textContent = buffer.slice(0, cursorAt);
  el.cursor.textContent = buffer[cursorAt] ?? ' ';
  el.post.textContent = buffer.slice(cursorAt + 1);
}

function setBuffer(text, at = text.length) {
  buffer = text;
  cursorAt = at;
  renderLine();
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
    stashedLine = buffer;
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

  if (prior[prior.length - 1] === '<' || last === '>' || last === '>>') {
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

function complete() {
  const endsWithSpace = /\s$/.test(buffer.slice(0, cursorAt)) || cursorAt === 0;
  const head = buffer.slice(0, cursorAt);
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
  } else {
    io.out(matches.join('  '));
  }
}

// ── Editing ──

function insertText(text) {
  setBuffer(buffer.slice(0, cursorAt) + text + buffer.slice(cursorAt), cursorAt + text.length);
  historyAt = -1;
}

function backspace() {
  if (cursorAt === 0) return;
  setBuffer(buffer.slice(0, cursorAt - 1) + buffer.slice(cursorAt), cursorAt - 1);
}

function deleteForward() {
  setBuffer(buffer.slice(0, cursorAt) + buffer.slice(cursorAt + 1), cursorAt);
}

function killLine() {
  setBuffer('');
}

function killWord() {
  const head = buffer.slice(0, cursorAt).replace(/\S+\s*$/, '');
  setBuffer(head + buffer.slice(cursorAt), head.length);
}

function clearScreen() {
  el.out.textContent = '';
}

// ── Execution ──

async function execute(line) {
  io.echo(PROMPT + line);
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
    return;
  }

  running = true;
  el.inputLine.hidden = true;
  setStatus('running…', 'busy');
  try {
    const result = await runPipeline(line, fs, commands, io.err);
    if (result.stdout.length > 0) io.out(decode(result.stdout));
    setStatus(result.code === 0 ? 'ready' : `exit ${result.code}`, result.code === 0 ? 'idle' : 'error');
  } catch (error) {
    if (error instanceof ShellError) {
      io.err(`sh: ${error.message}`);
    } else {
      io.err(`error: ${error instanceof Error ? error.message : String(error)}`);
    }
    setStatus('ready', 'idle');
  } finally {
    running = false;
    el.inputLine.hidden = false;
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
    if (!running && ctrlKey && key === 'c') {
      io.echo(PROMPT + buffer + '^C');
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
      a: () => setBuffer(buffer, 0),
      e: () => setBuffer(buffer, buffer.length),
      k: () => setBuffer(buffer.slice(0, cursorAt), cursorAt),
    }[chord];
    if (handled) {
      handled();
      event.preventDefault();
    }
    return;
  }
  if (altKey) return;

  switch (key) {
    case 'Enter': {
      const line = buffer;
      event.preventDefault();
      void execute(line);
      break;
    }
    case 'Backspace':
      backspace();
      event.preventDefault();
      break;
    case 'Delete':
      deleteForward();
      event.preventDefault();
      break;
    case 'ArrowLeft':
      setBuffer(buffer, Math.max(0, cursorAt - 1));
      event.preventDefault();
      break;
    case 'ArrowRight':
      setBuffer(buffer, Math.min(buffer.length, cursorAt + 1));
      event.preventDefault();
      break;
    case 'ArrowUp':
      historyStep(-1);
      event.preventDefault();
      break;
    case 'ArrowDown':
      historyStep(1);
      event.preventDefault();
      break;
    case 'Home':
      setBuffer(buffer, 0);
      event.preventDefault();
      break;
    case 'End':
      setBuffer(buffer, buffer.length);
      event.preventDefault();
      break;
    case 'Tab':
      complete();
      event.preventDefault();
      break;
    default:
      if (key.length === 1) {
        insertText(key);
        event.preventDefault();
      }
  }
}

function onPaste(event) {
  const text = event.clipboardData?.getData('text');
  if (!text || running) return;
  event.preventDefault();

  const lines = text.split(/\r?\n/);
  const fragment = lines.pop(); // text after the last newline stays editable
  if (lines.length === 0) {
    insertText(fragment);
    return;
  }
  // The first pasted line completes the current buffer and runs; complete
  // lines after it queue up behind it.
  insertText(lines[0]);
  pendingLines.push(...lines.slice(1));
  if (fragment) pendingFragment = fragment;
  void execute(buffer);
}

// ── Focus ──

function focusKeyboard() {
  if (document.getSelection()?.toString()) return; // don't steal a selection
  el.kbd.focus({ preventScroll: true });
}

// ── Boot ──

async function main() {
  el.promptEl.textContent = PROMPT;
  renderLine();

  el.screen.addEventListener('mouseup', focusKeyboard);
  el.screen.addEventListener('touchend', focusKeyboard);
  el.kbd.addEventListener('keydown', onKeyDown);
  el.kbd.addEventListener('paste', onPaste);
  el.kbd.addEventListener('input', () => {
    // Mobile/IME text arrives via the hidden input's value.
    if (el.kbd.value) {
      insertText(el.kbd.value);
      el.kbd.value = '';
    }
  });
  el.kbd.addEventListener('focus', () => el.screen.classList.add('focused'));
  el.kbd.addEventListener('blur', () => el.screen.classList.remove('focused'));

  setStatus('loading wasm…', 'busy');
  await init();
  completionsSpec = cliCompletions();
  commands.keytap = createKeytapCommand(ceremony);

  io.out(`keytap ${cliVersion()} — the real CLI, compiled to WebAssembly.`);
  io.out('keys derive from your passkey, locally in this tab; nothing leaves it.');
  io.out('');
  io.out('type `keytap` for the command reference, `help` for this shell.');
  io.out('try:  keytap init');
  io.out('      keytap reveal demo --as ssh');
  setStatus('ready', 'idle');
  focusKeyboard();
}

main().catch((error) => {
  setStatus('failed to load', 'error');
  io.err(`error: failed to initialize: ${error instanceof Error ? error.message : String(error)}`);
});
