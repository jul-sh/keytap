'use strict';

// The demo shell around the keytap CLI: tokenizer, pipelines, redirects, an
// in-memory filesystem, and a few coreutils. Deliberately tiny; everything
// keytap behavior lives in the shared WASM command runner, not here.

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: false });

export const encode = (text) => encoder.encode(text);
export const decode = (bytes) => decoder.decode(bytes);

// ── Tokenizer ──
// Words with 'single', "double" quotes and \ escapes; |, <, >, >> operators.

export function tokenize(line) {
  const tokens = [];
  let i = 0;
  const n = line.length;
  while (i < n) {
    while (i < n && /\s/.test(line[i])) i++;
    if (i >= n) break;

    const c = line[i];
    if (c === '|' || c === '<') {
      tokens.push({ op: c });
      i++;
      continue;
    }
    if (c === '>') {
      const op = line[i + 1] === '>' ? '>>' : '>';
      tokens.push({ op });
      i += op.length;
      continue;
    }

    let word = '';
    while (i < n && !/[\s|<>]/.test(line[i])) {
      const ch = line[i];
      if (ch === "'") {
        const end = line.indexOf("'", i + 1);
        if (end === -1) throw new ShellError('unterminated quote');
        word += line.slice(i + 1, end);
        i = end + 1;
      } else if (ch === '"') {
        i++;
        while (i < n && line[i] !== '"') {
          if (line[i] === '\\' && i + 1 < n) i++;
          word += line[i++];
        }
        if (i >= n) throw new ShellError('unterminated quote');
        i++;
      } else if (ch === '\\' && i + 1 < n) {
        word += line[i + 1];
        i += 2;
      } else {
        word += ch;
        i++;
      }
    }
    tokens.push({ word });
  }
  return tokens;
}

export class ShellError extends Error {}

// ── Pipeline parsing ──
// line := command ('|' command)*   command := word+ with <file, >file, >>file

export function parsePipeline(tokens) {
  const commands = [];
  let current = { argv: [], stdinFile: null, stdoutFile: null, append: false };

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.op === '|') {
      if (current.argv.length === 0) throw new ShellError('syntax error near `|`');
      commands.push(current);
      current = { argv: [], stdinFile: null, stdoutFile: null, append: false };
    } else if (t.op === '<' || t.op === '>' || t.op === '>>') {
      const target = tokens[++i];
      if (!target || target.op) throw new ShellError(`syntax error near \`${t.op}\``);
      if (t.op === '<') current.stdinFile = target.word;
      else {
        current.stdoutFile = target.word;
        current.append = t.op === '>>';
      }
    } else {
      current.argv.push(t.word);
    }
  }
  if (current.argv.length === 0 && commands.length > 0) throw new ShellError('syntax error near `|`');
  if (current.argv.length > 0) commands.push(current);
  return commands;
}

// ── In-memory filesystem ──
// Flat namespace of Uint8Array values. Nothing persists past a reload.

export function createFs() {
  const files = new Map();
  files.set(
    'notes.txt',
    encode('in-memory demo filesystem; nothing here survives a reload.\ntry: keytap encrypt < notes.txt > notes.age\n')
  );
  return files;
}

// ── Coreutils ──
// Each builtin: (argv, stdin, fs, err) → { stdout: Uint8Array, code }
// `err` appends a line to the terminal's stderr as it happens.

const empty = new Uint8Array(0);

function concat(chunks) {
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

export const builtins = {
  echo(argv, _stdin, _fs, _err) {
    let args = argv.slice(1);
    let newline = '\n';
    if (args[0] === '-n') {
      newline = '';
      args = args.slice(1);
    }
    return { stdout: encode(args.join(' ') + newline), code: 0 };
  },

  cat(argv, stdin, fs, err) {
    const names = argv.slice(1);
    if (names.length === 0) return { stdout: stdin, code: 0 };
    const chunks = [];
    let code = 0;
    for (const name of names) {
      const data = fs.get(name);
      if (data === undefined) {
        err(`cat: ${name}: no such file`);
        code = 1;
      } else {
        chunks.push(data);
      }
    }
    return { stdout: concat(chunks), code };
  },

  ls(_argv, _stdin, fs) {
    const names = [...fs.keys()].sort();
    return { stdout: encode(names.map((n) => n + '\n').join('')), code: 0 };
  },

  rm(argv, _stdin, fs, err) {
    const names = argv.slice(1);
    if (names.length === 0) {
      err('rm: missing operand');
      return { stdout: empty, code: 1 };
    }
    let code = 0;
    for (const name of names) {
      if (!fs.delete(name)) {
        err(`rm: ${name}: no such file`);
        code = 1;
      }
    }
    return { stdout: empty, code };
  },

  xxd(argv, stdin, fs, err) {
    let data = stdin;
    const name = argv[1];
    if (name !== undefined) {
      data = fs.get(name);
      if (data === undefined) {
        err(`xxd: ${name}: no such file`);
        return { stdout: empty, code: 1 };
      }
    }
    let out = '';
    for (let row = 0; row < data.length; row += 16) {
      const slice = data.slice(row, row + 16);
      const hex = [...slice]
        .map((b, i) => b.toString(16).padStart(2, '0') + (i % 2 ? ' ' : ''))
        .join('')
        .padEnd(40);
      const ascii = [...slice].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('');
      out += row.toString(16).padStart(8, '0') + ': ' + hex + ' ' + ascii + '\n';
    }
    return { stdout: encode(out), code: 0 };
  },
};

// ── Runner ──
// Executes one parsed pipeline. `commands` maps a name to an async handler
// with the same shape as a builtin; unknown names report like a real shell.

export async function runPipeline(line, fs, commands, err) {
  const stages = parsePipeline(tokenize(line));
  let stdin = empty;
  let code = 0;
  let after = undefined;

  for (const stage of stages) {
    if (stage.stdinFile !== null) {
      const data = fs.get(stage.stdinFile);
      if (data === undefined) {
        err(`sh: ${stage.stdinFile}: no such file`);
        return { code: 1, stdout: empty };
      }
      stdin = data;
    }

    const name = stage.argv[0];
    const handler = commands[name] || builtins[name];
    if (!handler) {
      err(`sh: command not found: ${name} (try 'help')`);
      return { code: 127, stdout: empty };
    }

    const result = await handler(stage.argv, stdin, fs, err);
    code = result.code;
    // A command's follow-up chrome (footers under its output) survives only
    // when its output actually reaches the screen unredirected.
    after = result.after;

    if (stage.stdoutFile !== null) {
      const prior = stage.append ? fs.get(stage.stdoutFile) : undefined;
      fs.set(stage.stdoutFile, prior ? concat([prior, result.stdout]) : result.stdout);
      stdin = empty;
      after = undefined;
    } else {
      stdin = result.stdout;
    }
  }
  return { code, stdout: stdin, after };
}
