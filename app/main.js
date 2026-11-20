const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const path = require('path');
const { Worker } = require('worker_threads');

const rootDir = path.resolve(__dirname, '..');
const enginePath = path.join(rootDir, 'xdis.exe');
const prefsPath = path.join(rootDir, 'xdis-prefs.json');

let win = null;
let proc = null;
let buf = '';
const queue = [];
let bridgeSrv = null;
let bridgePort = 0;
const bridgeToken = crypto.randomBytes(32).toString('hex');
const MUTATING_OPS = new Set(['rename', 'cmt', 'mark', 'patch', 'patch_bytes', 'unpatch', 'lvar', 'asm', 'type_add', 'chdr_parse', 'chdr_stdlib', 'pdb_load', 'pdb_msf', 'dwarf_load', 'sig_apply', 'undo', 'redo', 'snap_load', 'unp_hashes', 'unp_strs', 'sug_decide']);
let pyMutated = false;

function timingSafeStrEq(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const ha = crypto.createHash('sha256').update(a, 'utf8').digest();
    const hb = crypto.createHash('sha256').update(b, 'utf8').digest();
    return crypto.timingSafeEqual(ha, hb);
}

const collab = {
    active: false,
    role: '',
    host: '127.0.0.1',
    port: 0,
    nick: 'analyst',
    pass: '',
    srv: null,
    sock: null,
    clients: new Map()
};

const COLLAB_MAX_BUF = 4 * 1024 * 1024;
const COLLAB_ALLOWED_TYPES = new Set(['cursor', 'rename', 'cmt', 'chat']);

function collabEmit(ev) {
    if (win && !win.isDestroyed()) win.webContents.send('collab-event', ev);
}

function collabPeers() {
    const out = [collab.nick];
    for (const info of collab.clients.values()) {
        if (!info.authed) continue;
        if (info.nick && !out.includes(info.nick)) out.push(info.nick);
    }
    return out;
}

function collabStop() {
    if (collab.srv) {
        try { collab.srv.close(); } catch (_) {}
        collab.srv = null;
    }
    for (const sock of collab.clients.keys()) {
        try { sock.destroy(); } catch (_) {}
    }
    collab.clients.clear();
    if (collab.sock) {
        try { collab.sock.destroy(); } catch (_) {}
        collab.sock = null;
    }
    collab.active = false;
    collab.role = '';
    collab.port = 0;
    collab.pass = '';
    collabEmit({ type: 'status', active: false, role: '', peers: [] });
}

function collabBroadcast(msg, excludeSock) {
    const wire = JSON.stringify(msg) + '\n';
    for (const [sock, info] of collab.clients.entries()) {
        if (!info.authed || sock === excludeSock || sock.destroyed) continue;
        try { sock.write(wire); } catch (_) {}
    }
}

function startBridge() {
    if (bridgeSrv) return;
    bridgeSrv = net.createServer((sock) => {
        sock.setEncoding('utf8');
        let sbuf = '';
        let sockAuthed = false;
        let badAuth = 0;
        let closed = false;
        sock.on('error', () => {});
        sock.on('data', (chunk) => {
            if (closed) return;
            sbuf += chunk;
            if (sbuf.length > 4 * 1024 * 1024) {
                closed = true;
                sock.destroy();
                return;
            }
            let nl;
            while ((nl = sbuf.indexOf('\n')) !== -1) {
                const line = sbuf.slice(0, nl).trim();
                sbuf = sbuf.slice(nl + 1);
                if (!line) continue;
                let req;
                try { req = JSON.parse(line); } catch (_) {
                    sock.write('{"ok":false,"err":"bad json"}\n');
                    continue;
                }
                if (!req || typeof req !== 'object' || Array.isArray(req)) {
                    if (!sockAuthed) {
                        badAuth++;
                        sock.write('{"ok":false,"err":"unauthorized"}\n');
                        if (badAuth >= 3) { closed = true; sock.end(); return; }
                    } else {
                        sock.write('{"ok":false,"err":"bad json"}\n');
                    }
                    continue;
                }
                if (req.op === 'auth') {
                    if (typeof req.token === 'string' && timingSafeStrEq(req.token, bridgeToken)) {
                        sockAuthed = true;
                        badAuth = 0;
                        sock.write('{"ok":true}\n');
                    } else {
                        badAuth++;
                        sock.write('{"ok":false,"err":"unauthorized"}\n');
                        if (badAuth >= 3) { closed = true; sock.end(); return; }
                    }
                    continue;
                }
                const authed = sockAuthed || (typeof req.token === 'string' && timingSafeStrEq(req.token, bridgeToken));
                if (!authed) {
                    badAuth++;
                    sock.write('{"ok":false,"err":"unauthorized"}\n');
                    if (badAuth >= 3) { closed = true; sock.end(); return; }
                    continue;
                }
                badAuth = 0;
                const fwd = { ...req };
                delete fwd.token;
                if (MUTATING_OPS.has(fwd.op)) pyMutated = true;
                rpcCall(fwd).then((res) => {
                    if (!sock.destroyed) sock.write(JSON.stringify(res) + '\n');
                });
            }
        });
    });
    // bind loopback only for local python sdk
    bridgeSrv.listen(0, '127.0.0.1', () => {
        const addr = bridgeSrv.address();
        bridgePort = addr ? addr.port : 0;
    });
}

function startEngine() {
    proc = spawn(enginePath, ['--rpc'], { cwd: rootDir, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    proc.stdout.setEncoding('utf8');
    proc.stdout.on('data', (chunk) => {
        buf += chunk;
        let nl;
        while ((nl = buf.indexOf('\n')) !== -1) {
            const line = buf.slice(0, nl).trim();
            buf = buf.slice(nl + 1);
            if (!line || queue.length === 0) continue;
            const job = queue.shift();
            try {
                job.resolve(JSON.parse(line));
            } catch (err) {
                job.resolve({ ok: false, err: String(err) });
            }
        }
    });
    proc.on('exit', () => {
        while (queue.length) queue.shift().resolve({ ok: false, err: 'engine exited' });
        proc = null;
    });
}

function rpcCall(req) {
    if (!proc) startEngine();
    return new Promise((resolve) => {
        queue.push({ resolve });
        proc.stdin.write(JSON.stringify(req) + '\n');
    });
}

function createWindow() {
    win = new BrowserWindow({
        width: 1520,
        height: 940,
        minWidth: 980,
        minHeight: 620,
        backgroundColor: '#1e1e1e',
        titleBarStyle: 'hidden',
        titleBarOverlay: { color: '#252526', symbolColor: '#9e9e9e', height: 30 },
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false
        }
    });
    win.webContents.on('will-navigate', (event) => {
        event.preventDefault();
    });
    win.webContents.on('will-frame-navigate', (event) => {
        event.preventDefault();
    });
    win.webContents.on('will-redirect', (event) => {
        event.preventDefault();
    });
    win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    win.setMenuBarVisibility(false);
    win.loadFile(path.join(__dirname, 'index.html'));
}

ipcMain.handle('rpc', (_, req) => rpcCall(req));

ipcMain.handle('pick-file', async (_, opts) => {
    const o = opts || {};
    const res = await dialog.showOpenDialog(win, {
        title: o.title || 'Open binary',
        properties: ['openFile'],
        filters: o.filters || [
            { name: 'Binaries', extensions: ['exe', 'dll', 'sys', 'elf', 'so', 'dylib', 'macho', 'bin', 'o'] },
            { name: 'All files', extensions: ['*'] }
        ]
    });
    return res.canceled ? null : res.filePaths[0];
});

const confirmedSavePaths = new Set();
function normalizeSaveKey(p) {
    const abs = path.resolve(String(p));
    return process.platform === 'win32' ? abs.toLowerCase() : abs;
}

ipcMain.handle('save-file', async (_, opts) => {
    const { title, defaultName, filters } = opts || {};
    const res = await dialog.showSaveDialog(win, {
        title: title || 'Save file',
        defaultPath: defaultName || 'out.txt',
        filters: filters || [{ name: 'All files', extensions: ['*'] }]
    });
    if (res.canceled || !res.filePath) return null;
    confirmedSavePaths.add(normalizeSaveKey(res.filePath));
    return res.filePath;
});

ipcMain.handle('write-text', (_, payload) => {
    try {
        if (!payload || typeof payload.filePath !== 'string' || !payload.filePath || typeof payload.text !== 'string') {
            return { ok: false, err: 'invalid write-text arguments' };
        }
        const abs = path.resolve(payload.filePath);
        const key = normalizeSaveKey(abs);
        if (!confirmedSavePaths.has(key)) {
            return { ok: false, err: 'write-text denied: path not confirmed by save dialog' };
        }
        confirmedSavePaths.delete(key);
        fs.writeFileSync(abs, payload.text, 'utf8');
        return { ok: true };
    } catch (err) {
        return { ok: false, err: String(err) };
    }
});

ipcMain.handle('read-text', async () => {
    const res = await dialog.showOpenDialog(win, {
        title: 'Import JSON',
        properties: ['openFile'],
        filters: [{ name: 'JSON', extensions: ['json'] }]
    });
    if (res.canceled || !res.filePaths[0]) return { ok: false };
    try {
        return { ok: true, text: fs.readFileSync(res.filePaths[0], 'utf8') };
    } catch (err) {
        return { ok: false, err: String(err) };
    }
});

ipcMain.handle('load-prefs', () => {
    try {
        return JSON.parse(fs.readFileSync(prefsPath, 'utf8'));
    } catch (_) {
        return null;
    }
});

ipcMain.handle('save-prefs', (_, obj) => {
    try {
        fs.writeFileSync(prefsPath, JSON.stringify(obj, null, 2), 'utf8');
        return true;
    } catch (_) {
        return false;
    }
});

const SCRIPT_ALLOWED_OPS = new Set([
    'info', 'list', 'dis', 'dec', 'cfg', 'read', 'find', 'xrefs', 'callgraph',
    'entropy_map', 'triage', 'deobf', 'emu', 'ir', 'ssa', 'lang', 'cff',
    'mba_eval', 'mba_scan', 'vm', 'unp_hashes', 'unp_strs', 'taint', 'sym_solve',
    'dmp_open', 'make_sig', 'chdr_parse', 'chdr_stdlib', 'dotnet', 'struct_apply',
    'yara', 'yara_defaults', 'carve', 'carve_extract', 'iocs', 'vuln', 'pdiff',
    'hilbert', 'sug_add', 'sug_list', 'sug_decide', 'undo', 'redo', 'snap_save',
    'snap_list', 'snap_load', 'vtables', 'switches', 'crypto', 'diff', 'pathfind',
    'xgraph', 'types', 'type_add', 'asm', 'demangle', 'sig_save', 'sig_apply',
    'pdb_load', 'rename', 'cmt', 'patch_bytes', 'cmd'
]);

const SCRIPT_MUTATING_OPS = new Set([
    'undo', 'redo', 'snap_load', 'type_add', 'chdr_parse', 'chdr_stdlib',
    'sig_apply', 'pdb_load', 'rename', 'cmt', 'patch_bytes'
]);

const SCRIPT_WORKER_SOURCE = [
    "'use strict';",
    "const { parentPort, workerData } = require('worker_threads');",
    "const util = require('util');",
    "const vm = require('vm');",
    "const ctx = vm.createContext(Object.create(null), { codeGeneration: { strings: false, wasm: false } });",
    "let replyFn = null;",
    "let _logCount = 0;",
    "let _logBytes = 0;",
    "let _logTruncated = false;",
    "const MAX_LOG_LINES = 5000;",
    "const MAX_LOG_BYTES = 1048576;",
    "const MAX_LOG_LINE_LEN = 16384;",
    "let _gotoCount = 0;",
    "let _lastGoto = null;",
    "const MAX_GOTO = 1000;",
    "const _inFlight = new Set();",
    "let _totalRpcs = 0;",
    "const MAX_INFLIGHT_RPCS = 256;",
    "const MAX_TOTAL_RPCS = 10000;",
    "function safeErrStr(e) {",
    "  try {",
    "    if (typeof e === 'string') return e;",
    "    if (typeof e === 'number' || typeof e === 'boolean' || e === null || e === undefined || typeof e === 'bigint') return String(e);",
    "    if (typeof e === 'symbol') return e.toString();",
    "    if (typeof e === 'object') {",
    "      if (util.types.isProxy(e)) return 'script error (Proxy)';",
    "      const msgDesc = Object.getOwnPropertyDescriptor(e, 'message');",
    "      if (msgDesc && 'value' in msgDesc && typeof msgDesc.value === 'string') {",
    "        let prefix = 'Error';",
    "        const nameDesc = Object.getOwnPropertyDescriptor(e, 'name');",
    "        if (nameDesc && 'value' in nameDesc && typeof nameDesc.value === 'string') {",
    "          prefix = nameDesc.value;",
    "        } else {",
    "          const proto = Object.getPrototypeOf(e);",
    "          if (proto && typeof proto === 'object' && !util.types.isProxy(proto)) {",
    "            const pName = Object.getOwnPropertyDescriptor(proto, 'name');",
    "            if (pName && 'value' in pName && typeof pName.value === 'string') prefix = pName.value;",
    "          }",
    "        }",
    "        return prefix + ': ' + msgDesc.value;",
    "      }",
    "    }",
    "    return String(e);",
    "  } catch (_) {",
    "    return 'script error';",
    "  }",
    "}",
    "const bootstrapSrc = [",
    "  \"'use strict';\",",
    "  \"const _String = globalThis.String;\",",
    "  \"const _Number = globalThis.Number;\",",
    "  \"const _TypeError = globalThis.TypeError;\",",
    "  \"const _Error = globalThis.Error;\",",
    "  \"const _Promise = globalThis.Promise;\",",
    "  \"const _Map = globalThis.Map;\",",
    "  \"const _stringify = globalThis.JSON.stringify;\",",
    "  \"const _parse = globalThis.JSON.parse;\",",
    "  \"const _arrJoin = globalThis.Array.prototype.join;\",",
    "  \"const _arrPush = globalThis.Array.prototype.push;\",",
    "  \"const _mapGet = globalThis.Map.prototype.get;\",",
    "  \"const _mapSet = globalThis.Map.prototype.set;\",",
    "  \"const _mapDelete = globalThis.Map.prototype.delete;\",",
    "  \"const _mapSizeDesc = globalThis.Object.getOwnPropertyDescriptor(globalThis.Map.prototype, 'size');\",",
    "  \"const _mapSize = _mapSizeDesc && _mapSizeDesc.get;\",",
    "  \"const _bigintToStr = globalThis.BigInt.prototype.toString;\",",
    "  \"const _reflectApply = globalThis.Reflect.apply;\",",
    "  \"const _toStr = (v) => {\",",
    "  \"  if (typeof v === 'string') return v;\",",
    "  \"  if (typeof v === 'bigint') return _reflectApply(_bigintToStr, v, []);\",",
    "  \"  const s = _String(v);\",",
    "  \"  if (typeof s !== 'string') throw new _TypeError('Cannot convert value to string');\",",
    "  \"  return s;\",",
    "  \"};\",",
    "  \"const curVa = _toStr(initCurVa || '0x0');\",",
    "  \"const _pending = new _Map();\",",
    "  \"let _nextId = 1;\",",
    "  \"let _totalRpcCalls = 0;\",",
    "  \"const _limitErr = new _Error('rpc rate limit exceeded');\",",
    "  \"const _limitRejected = _Promise.reject(_limitErr);\",",
    "  \"_reflectApply(_Promise.prototype.catch, _limitRejected, [() => {}]);\",",
    "  \"const _fmt = (v) => {\",",
    "  \"  if (typeof v === 'object' && v !== null) {\",",
    "  \"    try {\",",
    "  \"      const j = _stringify(v, (_, x) => typeof x === 'bigint' ? _toStr(x) : x);\",",
    "  \"      if (typeof j === 'string') return j;\",",
    "  \"    } catch (_) {}\",",
    "  \"    return _toStr(v);\",",
    "  \"  }\",",
    "  \"  return _toStr(v);\",",
    "  \"};\",",
    "  \"globalThis.print = (...args) => {\",",
    "  \"  const parts = [];\",",
    "  \"  for (let i = 0; i < args.length; i++) {\",",
    "  \"    _reflectApply(_arrPush, parts, [_fmt(args[i])]);\",",
    "  \"  }\",",
    "  \"  const out = _reflectApply(_arrJoin, parts, [' ']);\",",
    "  \"  if (typeof out !== 'string') throw new _TypeError('print output must be a string');\",",
    "  \"  hostLog(out);\",",
    "  \"};\",",
    "  \"const _ser = (obj) => {\",",
    "  \"  const s = _stringify(obj, (_, x) => typeof x === 'bigint' ? ('0x' + _reflectApply(_bigintToStr, x, [16])) : x);\",",
    "  \"  if (typeof s !== 'string') throw new _TypeError('rpc payload must be a string');\",",
    "  \"  return s;\",",
    "  \"};\",",
    "  \"const _rpc = (req) => {\",",
    "  \"  const pendingSize = _mapSize ? _reflectApply(_mapSize, _pending, []) : 0;\",",
    "  \"  if (pendingSize >= 256 || _totalRpcCalls >= 10000) return _limitRejected;\",",
    "  \"  const id = _Number(_nextId++);\",",
    "  \"  _totalRpcCalls++;\",",
    "  \"  const payload = _ser(req);\",",
    "  \"  if (typeof id !== 'number' || typeof payload !== 'string') throw new _TypeError('invalid rpc payload');\",",
    "  \"  return new _Promise((resolve, reject) => {\",",
    "  \"    _reflectApply(_mapSet, _pending, [id, { resolve, reject }]);\",",
    "  \"    if (!hostRpc(id, payload)) {\",",
    "  \"      _reflectApply(_mapDelete, _pending, [id]);\",",
    "  \"      reject(_limitErr);\",",
    "  \"    }\",",
    "  \"  });\",",
    "  \"};\",",
    "  \"registerReply((id, ok, resJson, errMsg) => {\",",
    "  \"  const p = _reflectApply(_mapGet, _pending, [id]);\",",
    "  \"  if (!p) return;\",",
    "  \"  _reflectApply(_mapDelete, _pending, [id]);\",",
    "  \"  if (!ok) { p.reject(new _Error(typeof errMsg === 'string' && errMsg ? errMsg : 'rpc error')); return; }\",",
    "  \"  try { p.resolve(_parse(typeof resJson === 'string' ? resJson : '{}')); } catch (e) { p.reject(e); }\",",
    "  \"});\",",
    "  \"globalThis.xdis = {\",",
    "  \"  curVa,\",",
    "  \"  info: () => _rpc({ op: 'info' }),\",",
    "  \"  funcs: (q = '', lim = 200) => _rpc({ op: 'list', tab: 'funcs', q, off: 0, lim }),\",",
    "  \"  syms: (q = '', lim = 200) => _rpc({ op: 'list', tab: 'syms', q, off: 0, lim }),\",",
    "  \"  strs: (q = '', lim = 200) => _rpc({ op: 'list', tab: 'strs', q, off: 0, lim }),\",",
    "  \"  dis: (va = curVa, n = 32) => _rpc({ op: 'dis', va, n }),\",",
    "  \"  dec: (va = curVa) => _rpc({ op: 'dec', va }),\",",
    "  \"  cfg: (va = curVa) => _rpc({ op: 'cfg', va }),\",",
    "  \"  read: (va = curVa, n = 64) => _rpc({ op: 'read', va, n }),\",",
    "  \"  find: (q) => _rpc({ op: 'find', q }),\",",
    "  \"  xrefs: (va = curVa) => _rpc({ op: 'xrefs', va }),\",",
    "  \"  callgraph: (va = curVa) => _rpc({ op: 'callgraph', va }),\",",
    "  \"  entropy: () => _rpc({ op: 'entropy_map' }),\",",
    "  \"  triage: () => _rpc({ op: 'triage' }),\",",
    "  \"  deobf: (va = curVa) => _rpc({ op: 'deobf', va }),\",",
    "  \"  emu: (va = curVa, n = 48) => _rpc({ op: 'emu', va, n }),\",",
    "  \"  ir: (va = curVa) => _rpc({ op: 'ir', va }),\",",
    "  \"  ssa: (va = curVa, tier = 'mlir') => _rpc({ op: 'ssa', va, tier }),\",",
    "  \"  lang: () => _rpc({ op: 'lang' }),\",",
    "  \"  cff: (va = curVa) => _rpc({ op: 'cff', va }),\",",
    "  \"  mbaEval: (expr) => _rpc({ op: 'mba_eval', expr }),\",",
    "  \"  mbaScan: (va = curVa) => _rpc({ op: 'mba_scan', va }),\",",
    "  \"  vm: (va = curVa) => _rpc({ op: 'vm', va }),\",",
    "  \"  unpHashes: (apply = 0) => _rpc({ op: 'unp_hashes', apply }),\",",
    "  \"  unpStrs: (va = curVa, apply = 0) => _rpc({ op: 'unp_strs', va, apply }),\",",
    "  \"  taint: (va = curVa, reg = 'rcx', bufLen = 0, n = 128) => _rpc({ op: 'taint', va, reg, buf_len: bufLen, n }),\",",
    "  \"  symSolve: (from = curVa, to = 0) => _rpc({ op: 'sym_solve', from, to }),\",",
    "  \"  dmpOpen: (p) => _rpc({ op: 'dmp_open', path: p }),\",",
    "  \"  makeSig: (va = curVa) => _rpc({ op: 'make_sig', va }),\",",
    "  \"  chdrParse: (text) => _rpc({ op: 'chdr_parse', text }),\",",
    "  \"  chdrStdlib: (pack = 'win32') => _rpc({ op: 'chdr_stdlib', pack }),\",",
    "  \"  dotnet: () => _rpc({ op: 'dotnet' }),\",",
    "  \"  structApply: (name, va = curVa) => _rpc({ op: 'struct_apply', name, va }),\",",
    "  \"  yara: (rules = '') => _rpc({ op: 'yara', rules }),\",",
    "  \"  yaraDefaults: () => _rpc({ op: 'yara_defaults' }),\",",
    "  \"  carve: () => _rpc({ op: 'carve' }),\",",
    "  \"  carveExtract: (off, size, outPath) => _rpc({ op: 'carve_extract', off, size, path: outPath }),\",",
    "  \"  iocs: () => _rpc({ op: 'iocs' }),\",",
    "  \"  vuln: () => _rpc({ op: 'vuln' }),\",",
    "  \"  pdiff: (otherPath = '') => _rpc({ op: 'pdiff', path: otherPath }),\",",
    "  \"  hilbert: (order = 6) => _rpc({ op: 'hilbert', order }),\",",
    "  \"  propose: (va, kind, val, reason = '', conf = 85) => _rpc({ op: 'sug_add', va, kind, val, reason, conf }),\",",
    "  \"  suggestions: () => _rpc({ op: 'sug_list' }),\",",
    "  \"  decideSuggestion: (id, accept = 1, minConf = 0) => _rpc({ op: 'sug_decide', id, accept, min_conf: minConf }),\",",
    "  \"  undo: () => _rpc({ op: 'undo' }),\",",
    "  \"  redo: () => _rpc({ op: 'redo' }),\",",
    "  \"  snapSave: (name) => _rpc({ op: 'snap_save', name }),\",",
    "  \"  snapList: () => _rpc({ op: 'snap_list' }),\",",
    "  \"  snapLoad: (name) => _rpc({ op: 'snap_load', name }),\",",
    "  \"  vtables: () => _rpc({ op: 'vtables' }),\",",
    "  \"  switches: (va = curVa) => _rpc({ op: 'switches', va }),\",",
    "  \"  crypto: () => _rpc({ op: 'crypto' }),\",",
    "  \"  diff: (otherPath) => _rpc({ op: 'diff', path: otherPath }),\",",
    "  \"  pathfind: (from, to) => _rpc({ op: 'pathfind', from, to }),\",",
    "  \"  xgraph: (va = curVa, depth = 2) => _rpc({ op: 'xgraph', va, depth }),\",",
    "  \"  types: () => _rpc({ op: 'types' }),\",",
    "  \"  typeAdd: (decl) => _rpc({ op: 'type_add', decl }),\",",
    "  \"  asm: (va, text, apply = 1) => _rpc({ op: 'asm', va, text, apply }),\",",
    "  \"  demangle: (name) => _rpc({ op: 'demangle', name }),\",",
    "  \"  sigSave: (p) => _rpc({ op: 'sig_save', path: p }),\",",
    "  \"  sigApply: (p) => _rpc({ op: 'sig_apply', path: p }),\",",
    "  \"  pdbLoad: (p) => _rpc({ op: 'pdb_load', path: p }),\",",
    "  \"  rename: (va, name) => _rpc({ op: 'rename', va, name }),\",",
    "  \"  cmt: (va, text) => _rpc({ op: 'cmt', va, text }),\",",
    "  \"  patch: (va, hex) => _rpc({ op: 'patch_bytes', va, hex }),\",",
    "  \"  cmd: (name, args = '') => _rpc({ op: 'cmd', name, args }),\",",
    "  \"  goto: (va) => { if (va !== undefined && va !== null) { const s = _toStr(va); if (typeof s !== 'string') throw new _TypeError('goto va must be a string'); hostGoto(s); } }\",",
    "  \"};\"",
    "].join('\\n');",
    "const boot = vm.compileFunction(bootstrapSrc, ['initCurVa', 'hostLog', 'hostRpc', 'hostGoto', 'registerReply'], { parsingContext: ctx });",
    "boot(",
    "  String(workerData.curVa || '0x0'),",
    "  (s) => {",
    "    try {",
    "      if (typeof s !== 'string' || _logTruncated) return;",
    "      let txt = s;",
    "      if (txt.length > MAX_LOG_LINE_LEN) txt = txt.slice(0, MAX_LOG_LINE_LEN);",
    "      if (_logCount >= MAX_LOG_LINES || _logBytes + txt.length > MAX_LOG_BYTES) {",
    "        _logTruncated = true;",
    "        parentPort.postMessage({ type: 'log', text: '[log truncated]' });",
    "        return;",
    "      }",
    "      _logCount++;",
    "      _logBytes += txt.length;",
    "      parentPort.postMessage({ type: 'log', text: txt });",
    "    } catch (_) {}",
    "  },",
    "  (id, reqJson) => {",
    "    try {",
    "      if (typeof id !== 'number' || !Number.isFinite(id) || typeof reqJson !== 'string') return false;",
    "      if (_inFlight.size >= MAX_INFLIGHT_RPCS || _totalRpcs >= MAX_TOTAL_RPCS) return false;",
    "      _inFlight.add(id);",
    "      _totalRpcs++;",
    "      parentPort.postMessage({ type: 'rpc', id, reqJson });",
    "      return true;",
    "    } catch (_) {",
    "      return false;",
    "    }",
    "  },",
    "  (va) => {",
    "    try {",
    "      if (typeof va !== 'string') return;",
    "      if (va === _lastGoto || _gotoCount >= MAX_GOTO) return;",
    "      _lastGoto = va;",
    "      _gotoCount++;",
    "      parentPort.postMessage({ type: 'goto', va });",
    "    } catch (_) {}",
    "  },",
    "  (fn) => {",
    "    try {",
    "      if (typeof fn === 'function') replyFn = fn;",
    "    } catch (_) {}",
    "  }",
    ");",
    "parentPort.on('message', (msg) => {",
    "  try {",
    "    if (msg && msg.type === 'rpc-reply' && replyFn) {",
    "      const nid = typeof msg.id === 'number' ? msg.id : Number(msg.id);",
    "      _inFlight.delete(nid);",
    "      replyFn(",
    "        nid,",
    "        !!msg.ok,",
    "        typeof msg.resJson === 'string' ? msg.resJson : '{}',",
    "        typeof msg.err === 'string' ? msg.err : ''",
    "      );",
    "    }",
    "  } catch (_) {}",
    "});",
    "(async () => {",
    "  try {",
    "    const script = new vm.Script('(async () => {\\n' + String(workerData.code || '') + '\\n})()');",
    "    await script.runInContext(ctx);",
    "    parentPort.postMessage({ type: 'done', ok: true });",
    "  } catch (err) {",
    "    parentPort.postMessage({ type: 'done', ok: false, err: safeErrStr(err) });",
    "  }",
    "})();"
].join('\n');

function runSandboxedScript(code, curVa, timeoutMs = 4000) {
    const logs = [];
    let logBytes = 0;
    let jumpTo = null;
    let mutated = false;
    if (typeof code !== 'string') {
        return Promise.resolve({ ok: false, err: 'invalid script code', logs, jumpTo, mutated });
    }
    return new Promise((resolve) => {
        let settled = false;
        let worker = null;
        const finish = (res) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            if (worker) {
                worker.terminate().catch(() => {});
            }
            resolve(res);
        };
        const timer = setTimeout(() => {
            finish({ ok: false, err: 'script timed out', logs, jumpTo, mutated });
        }, timeoutMs);
        try {
            worker = new Worker(SCRIPT_WORKER_SOURCE, {
                eval: true,
                workerData: { code, curVa: String(curVa || '0x0') },
                resourceLimits: { maxOldGenerationSizeMb: 256 }
            });
        } catch (err) {
            finish({ ok: false, err: String(err), logs, jumpTo, mutated });
            return;
        }
        worker.on('message', (msg) => {
            if (settled || !msg || typeof msg !== 'object') return;
            if (msg.type === 'log') {
                const line = String(msg.text || '');
                if (logs.length < 5000 && logBytes + line.length <= 1048576) {
                    logs.push(line);
                    logBytes += line.length;
                } else if (line === '[log truncated]' && logs[logs.length - 1] !== '[log truncated]') {
                    logs.push(line);
                }
                return;
            }
            if (msg.type === 'goto') {
                jumpTo = String(msg.va || '');
                return;
            }
            if (msg.type === 'rpc') {
                let req;
                try {
                    req = JSON.parse(String(msg.reqJson || ''));
                } catch (_) {
                    worker.postMessage({ type: 'rpc-reply', id: msg.id, ok: false, err: 'invalid rpc payload' });
                    return;
                }
                if (!req || typeof req !== 'object' || Array.isArray(req) || typeof req.op !== 'string' || !SCRIPT_ALLOWED_OPS.has(req.op)) {
                    worker.postMessage({ type: 'rpc-reply', id: msg.id, ok: false, err: 'disallowed rpc op' });
                    return;
                }
                if (
                    SCRIPT_MUTATING_OPS.has(req.op) ||
                    (req.op === 'sug_decide' && req.accept) ||
                    (req.op === 'asm' && req.apply) ||
                    (req.op === 'unp_hashes' && req.apply) ||
                    (req.op === 'unp_strs' && req.apply)
                ) {
                    mutated = true;
                }
                rpcCall(req).then((res) => {
                    if (!settled) {
                        worker.postMessage({ type: 'rpc-reply', id: msg.id, ok: true, resJson: JSON.stringify(res) });
                    }
                }).catch((err) => {
                    if (!settled) {
                        worker.postMessage({ type: 'rpc-reply', id: msg.id, ok: false, err: String(err) });
                    }
                });
                return;
            }
            if (msg.type === 'done') {
                if (msg.ok) {
                    finish({ ok: true, logs, jumpTo, mutated });
                } else {
                    finish({ ok: false, err: String(msg.err || 'script error'), logs, jumpTo, mutated });
                }
            }
        });
        worker.on('error', (err) => {
            finish({ ok: false, err: String(err), logs, jumpTo, mutated });
        });
        worker.on('exit', (exitCode) => {
            if (!settled) {
                finish({ ok: false, err: 'script worker exited unexpectedly (' + exitCode + ')', logs, jumpTo, mutated });
            }
        });
    });
}

ipcMain.handle('run-script', (_, payload) => {
    const { code, curVa } = payload || {};
    return runSandboxedScript(code, curVa, 4000);
});

function runPythonCode(code, curVa, timeoutMs = 12000) {
    return new Promise((resolve) => {
        if (!bridgePort) startBridge();
        pyMutated = false;
        const env = {
            ...process.env,
            PYTHONPATH: path.join(rootDir, 'sdk'),
            XDIS_RPC_PORT: String(bridgePort),
            XDIS_RPC_TOKEN: bridgeToken,
            XDIS_CUR_VA: String(curVa || '0x0'),
            PYTHONIOENCODING: 'utf-8',
            PYTHONDONTWRITEBYTECODE: '1'
        };
        const py = spawn('python', ['-B', '-u', '-c', code], { cwd: rootDir, env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
        let out = '', err = '', done = false;
        const timer = setTimeout(() => {
            if (done) return;
            done = true;
            try { py.kill(); } catch (_) {}
            resolve({ ok: false, logs: out ? out.split(/\r?\n/) : [], err: 'python script timed out', mutated: pyMutated });
        }, timeoutMs);
        py.stdout.setEncoding('utf8');
        py.stderr.setEncoding('utf8');
        py.stdout.on('data', (d) => { out += d; });
        py.stderr.on('data', (d) => { err += d; });
        py.on('error', (e) => {
            if (done) return;
            done = true;
            clearTimeout(timer);
            resolve({ ok: false, logs: [], err: 'python launch failed: ' + String(e), mutated: false });
        });
        py.on('close', (exitCode) => {
            if (done) return;
            done = true;
            clearTimeout(timer);
            const logs = out.replace(/\r?\n$/, '') ? out.replace(/\r?\n$/, '').split(/\r?\n/) : [];
            resolve({ ok: exitCode === 0, logs, err: err.trim(), mutated: pyMutated });
        });
    });
}

ipcMain.handle('run-python', (_, { code, curVa }) => runPythonCode(code, curVa, 12000));

ipcMain.handle('export-report', async (_, payload) => {
    const { filePath, fmt } = payload || {};
    if (typeof filePath !== 'string' || !filePath) {
        return { ok: false, logs: [], err: 'invalid export-report path', mutated: false };
    }
    if (fmt !== undefined && typeof fmt !== 'string') {
        return { ok: false, logs: [], err: 'invalid export-report format', mutated: false };
    }
    const reportFmt = fmt ? fmt : 'html';
    const abs = path.resolve(filePath);
    const key = normalizeSaveKey(abs);
    if (!confirmedSavePaths.has(key)) {
        return { ok: false, logs: [], err: 'export-report denied: path not confirmed by save dialog', mutated: false };
    }
    confirmedSavePaths.delete(key);
    const code = `import sys, xdis\ndb = xdis.connect()\nprint(db.export_report(${JSON.stringify(abs)}, ${JSON.stringify(reportFmt)}))\n`;
    return runPythonCode(code, '0x0', 15000);
});

ipcMain.handle('initial-file', () => {
    for (let i = 1; i < process.argv.length; i++) {
        const a = process.argv[i];
        if (a.startsWith('-') || a === '.' || a === 'app' || a.endsWith('main.js')) continue;
        try {
            const p = path.resolve(a);
            if (fs.statSync(p).isFile()) return p;
        } catch (_) {}
    }
    return null;
});

ipcMain.handle('collab-host', (_, { port = 0, host = '127.0.0.1', nick = 'host', pass = '' } = {}) => {
    collabStop();
    const roomPass = typeof pass === 'string' ? pass : '';
    const cleanHostNick = String(nick || 'host').replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, 32) || 'host';
    return new Promise((resolve) => {
        const srv = net.createServer((sock) => {
            sock.setEncoding('utf8');
            const info = { nick: '', buf: '', authed: false, closed: false };
            collab.clients.set(sock, info);
            sock.on('data', (chunk) => {
                if (info.closed) return;
                info.buf += chunk;
                if (info.buf.length > COLLAB_MAX_BUF) {
                    info.closed = true;
                    info.buf = '';
                    sock.destroy();
                    return;
                }
                let nl;
                while ((nl = info.buf.indexOf('\n')) !== -1) {
                    const raw = info.buf.slice(0, nl).trim();
                    info.buf = info.buf.slice(nl + 1);
                    if (!raw) continue;
                    let msg;
                    try {
                        msg = JSON.parse(raw);
                    } catch (_) {
                        if (!info.authed) {
                            info.closed = true;
                            try { sock.write('{"type":"auth_err","err":"bad json"}\n'); } catch (_) {}
                            sock.end();
                            return;
                        }
                        continue;
                    }
                    if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
                        if (!info.authed) {
                            info.closed = true;
                            try { sock.write('{"type":"auth_err","err":"invalid message"}\n'); } catch (_) {}
                            sock.end();
                            return;
                        }
                        continue;
                    }
                    if (msg.type === 'hello') {
                        if (info.authed) {
                            info.closed = true;
                            try { sock.write('{"type":"auth_err","err":"already authenticated"}\n'); } catch (_) {}
                            sock.end();
                            return;
                        }
                        if (roomPass) {
                            if (typeof msg.pass !== 'string' || !timingSafeStrEq(msg.pass, roomPass)) {
                                info.closed = true;
                                try { sock.write('{"type":"auth_err","err":"invalid room secret"}\n'); } catch (_) {}
                                sock.end();
                                return;
                            }
                        }
                        if (typeof msg.nick !== 'string') {
                            info.closed = true;
                            try { sock.write('{"type":"auth_err","err":"invalid nick"}\n'); } catch (_) {}
                            sock.end();
                            return;
                        }
                        const reqNick = msg.nick.trim().slice(0, 32);
                        if (!reqNick || /[\x00-\x1f\x7f]/.test(reqNick)) {
                            info.closed = true;
                            try { sock.write('{"type":"auth_err","err":"invalid nick"}\n'); } catch (_) {}
                            sock.end();
                            return;
                        }
                        let nickTaken = (reqNick === collab.nick);
                        if (!nickTaken) {
                            for (const other of collab.clients.values()) {
                                if (other !== info && other.authed && other.nick === reqNick) {
                                    nickTaken = true;
                                    break;
                                }
                            }
                        }
                        if (nickTaken) {
                            info.closed = true;
                            try { sock.write('{"type":"auth_err","err":"nick already in use"}\n'); } catch (_) {}
                            sock.end();
                            return;
                        }
                        info.authed = true;
                        info.nick = reqNick;
                        const peers = collabPeers();
                        collabEmit({ type: 'peers', peers, joined: info.nick });
                        collabBroadcast({ type: 'peers', peers, joined: info.nick }, null);
                        continue;
                    }
                    if (!info.authed) {
                        info.closed = true;
                        try { sock.write('{"type":"auth_err","err":"unauthorized"}\n'); } catch (_) {}
                        sock.end();
                        return;
                    }
                    if (typeof msg.type !== 'string' || !COLLAB_ALLOWED_TYPES.has(msg.type)) {
                        continue;
                    }
                    msg.from = info.nick;
                    collabEmit(msg);
                    collabBroadcast(msg, sock);
                }
            });
            const drop = () => {
                if (!collab.clients.has(sock)) return;
                const wasAuthed = info.authed;
                const left = info.nick;
                collab.clients.delete(sock);
                if (!wasAuthed) return;
                const peers = collabPeers();
                collabEmit({ type: 'peers', peers, left });
                collabBroadcast({ type: 'peers', peers, left }, null);
            };
            sock.on('close', drop);
            sock.on('error', drop);
        });
        srv.on('error', (err) => {
            resolve({ ok: false, err: String(err) });
        });
        srv.listen(Number(port) || 0, host || '127.0.0.1', () => {
            const addr = srv.address();
            collab.active = true;
            collab.role = 'host';
            collab.host = host || '127.0.0.1';
            collab.port = addr ? addr.port : Number(port);
            collab.nick = cleanHostNick;
            collab.pass = roomPass;
            collab.srv = srv;
            const res = { ok: true, active: true, role: 'host', host: collab.host, port: collab.port, nick: collab.nick, peers: collabPeers() };
            collabEmit({ type: 'status', ...res });
            resolve(res);
        });
    });
});

ipcMain.handle('collab-join', (_, { host = '127.0.0.1', port = 4545, nick = 'guest', pass = '' } = {}) => {
    collabStop();
    const joinPass = typeof pass === 'string' ? pass : '';
    const cleanNick = String(nick || 'guest').replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, 32) || 'guest';
    return new Promise((resolve) => {
        const sock = net.createConnection({ host: host || '127.0.0.1', port: Number(port) || 4545 });
        let settled = false;
        let closed = false;
        let sbuf = '';
        sock.setEncoding('utf8');
        sock.on('connect', () => {
            collab.active = true;
            collab.role = 'client';
            collab.host = host || '127.0.0.1';
            collab.port = Number(port) || 4545;
            collab.nick = cleanNick;
            collab.pass = joinPass;
            collab.sock = sock;
            const hello = { type: 'hello', nick: collab.nick };
            if (joinPass) hello.pass = joinPass;
            sock.write(JSON.stringify(hello) + '\n');
            settled = true;
            const res = { ok: true, active: true, role: 'client', host: collab.host, port: collab.port, nick: collab.nick, peers: [collab.nick] };
            collabEmit({ type: 'status', ...res });
            resolve(res);
        });
        sock.on('data', (chunk) => {
            if (closed) return;
            sbuf += chunk;
            if (sbuf.length > COLLAB_MAX_BUF) {
                closed = true;
                sbuf = '';
                sock.destroy();
                return;
            }
            let nl;
            while ((nl = sbuf.indexOf('\n')) !== -1) {
                const raw = sbuf.slice(0, nl).trim();
                sbuf = sbuf.slice(nl + 1);
                if (!raw) continue;
                try {
                    const ev = JSON.parse(raw);
                    if (ev && typeof ev === 'object' && !Array.isArray(ev)) collabEmit(ev);
                } catch (_) {}
            }
        });
        sock.on('error', (err) => {
            if (!settled) { settled = true; resolve({ ok: false, err: String(err) }); }
            collabStop();
        });
        sock.on('close', () => {
            if (collab.sock === sock) collabStop();
        });
    });
});

ipcMain.handle('collab-send', (_, msg) => {
    if (!collab.active || !msg || typeof msg !== 'object' || Array.isArray(msg)) return { ok: false };
    const out = { ...msg, from: collab.nick, ts: Date.now() };
    if (collab.role === 'host') {
        collabBroadcast(out, null);
        return { ok: true };
    }
    if (collab.sock && !collab.sock.destroyed) {
        collab.sock.write(JSON.stringify(out) + '\n');
        return { ok: true };
    }
    return { ok: false };
});

ipcMain.handle('collab-stop', () => {
    collabStop();
    return { ok: true };
});

ipcMain.handle('collab-status', () => ({
    active: collab.active,
    role: collab.role,
    host: collab.host,
    port: collab.port,
    nick: collab.nick,
    peers: collab.active ? collabPeers() : []
}));

ipcMain.on('title-colors', (_, { bg, fg }) => {
    if (win && win.setTitleBarOverlay) {
        win.setTitleBarOverlay({ color: bg, symbolColor: fg, height: 30 });
    }
});

app.whenReady().then(() => {
    startEngine();
    startBridge();
    createWindow();
});

app.on('window-all-closed', () => {
    collabStop();
    if (bridgeSrv) { try { bridgeSrv.close(); } catch (_) {} }
    if (proc) {
        try { proc.stdin.write('{"op":"quit"}\n'); } catch (_) {}
        proc.kill();
    }
    app.quit();
});
