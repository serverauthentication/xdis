(() => {
    const $ = (id) => document.getElementById(id);

    const st = {
        info: null,
        entMap: null,
        triage: null,
        crypto: null,
        vtables: null,
        lang: null,
        dotnet: null,
        mode: 'split',
        irSub: 'mlir',
        deobfSub: 'junk',
        mbaExpr: '(x ^ y) + 2 * (x & y)',
        mbaEval: null,
        callsSub: 'calls',
        undoN: 0,
        redoN: 0,
        pathSt: { from: '', to: '', res: null },
        diffSt: { otherPath: '', data: null, filter: 'all', sel: null, codeA: [], codeB: [], pdiff: null, view: 'diff' },
        auditSub: 'vuln',
        auditSt: {
            vuln: null,
            vulnLoaded: false,
            yaraRules: '',
            yaraDefaultsLoaded: false,
            yaraRes: null,
            carve: null,
            iocs: null,
            iocFilter: '',
            hilbertOrder: 6,
            hilbert: null,
            sugs: null,
            sugDraft: { va: '', kind: 'rename', val: '', reason: '', conf: '85' }
        },
        collabSt: {
            active: false,
            role: '',
            host: '127.0.0.1',
            port: '4545',
            nick: 'analyst',
            pass: '',
            peers: [],
            peerCursors: {},
            log: [],
            chatDraft: '',
            err: ''
        },
        lastCollabVa: '',
        typeDraft: '',
        structOverlay: null,
        dbgTab: 'local',
        dbgSideTab: 'stack',
        dbgSt: null,
        dbgPrev: null,
        dbgSnapIdx: -1,
        dbgMods: null,
        dbgThreads: null,
        dbgBt: null,
        dbgMmap: null,
        dbgWho: null,
        gdbHost: '127.0.0.1',
        gdbPort: '1234',
        gdbSt: null,
        gdbPrev: null,
        gdbBps: [],
        dmpSt: null,
        dmpSelTid: null,
        traceSub: 'emu',
        taintCfg: { reg: 'rcx', bufLen: 0, steps: 128 },
        taintRes: null,
        symSt: { from: '', to: '', res: null },
        tab: 'funcs',
        topVa: '0x0',
        curVa: '0x0',
        emuSteps: 48,
        hist: [],
        histPos: 0,
        tabs: [],
        activeTab: 0,
        disRows: [],
        cfgData: null,
        decData: null,
        selVar: null,
        listItems: [],
        listTotal: 0,
        listOff: 0,
        peekTimer: null
    };

    function prefs() { return window.studio.getPrefs(); }

    function logLine(msg) {
        const el = $('console-log');
        el.textContent += (el.textContent ? '\n' : '') + msg;
        el.scrollTop = el.scrollHeight;
    }

    function hidePeek() {
        clearTimeout(st.peekTimer);
        $('peek').classList.add('hidden');
    }

    function schedulePeek(vaOrSym, ev) {
        if (!prefs().peekEnabled || !st.info || !vaOrSym) return;
        clearTimeout(st.peekTimer);
        const mx = ev.clientX, my = ev.clientY;
        st.peekTimer = setTimeout(async () => {
            let va = vaOrSym;
            if (!/^0x[0-9a-f]+$/i.test(va)) {
                const clean = va.replace(/^(loc_|g_)/, '0x');
                if (/^0x[0-9a-f]+$/i.test(clean)) va = clean;
                else {
                    const r = await window.xdis.call({ op: 'resolve', q: va });
                    if (!r.ok) return;
                    va = r.va;
                }
            }
            const p = await window.xdis.call({ op: 'peek', va });
            if (!p.ok) return;
            const box = $('peek');
            box.innerHTML = window.vw.renderPeekHtml(p);
            box.classList.remove('hidden');
            const x = Math.min(window.innerWidth - 456, mx + 16);
            const y = Math.min(window.innerHeight - box.offsetHeight - 14, my + 16);
            box.style.left = Math.max(8, x) + 'px';
            box.style.top = Math.max(40, y) + 'px';
        }, 160);
    }

    async function resolveAndJump(vaOrSym) {
        hidePeek();
        if (!vaOrSym) return;
        if (/^0x[0-9a-f]+$/i.test(vaOrSym)) return gotoVa(vaOrSym, true);
        const clean = vaOrSym.replace(/^(loc_|g_)/, '0x');
        if (/^0x[0-9a-f]+$/i.test(clean)) return gotoVa(clean, true);
        const r = await window.xdis.call({ op: 'resolve', q: vaOrSym });
        if (r.ok) gotoVa(r.va, true);
    }

    function syncActiveTab() {
        if (!st.tabs.length) return;
        const t = st.tabs[st.activeTab];
        if (!t) return;
        t.va = st.curVa;
        t.topVa = st.topVa;
        t.mode = st.mode;
        t.label = (st.decData && st.decData.name) ? st.decData.name : st.curVa;
        renderTabs();
    }

    function renderTabs() {
        const el = $('tab-list');
        el.innerHTML = st.tabs.map((t, i) =>
            `<div class="w-tab${i === st.activeTab ? ' active' : ''}" data-ti="${i}">`
            + `<span>${window.vw.esc(t.label)}</span>`
            + (st.tabs.length > 1 ? `<span class="tx" data-close="${i}">×</span>` : '')
            + `</div>`
        ).join('');
        el.querySelectorAll('.w-tab').forEach((n) => {
            n.onclick = (e) => {
                if (e.target.dataset.close !== undefined) {
                    const idx = Number(e.target.dataset.close);
                    st.tabs.splice(idx, 1);
                    st.activeTab = Math.min(st.activeTab, st.tabs.length - 1);
                    const cur = st.tabs[st.activeTab];
                    st.curVa = cur.va; st.topVa = cur.topVa; st.mode = cur.mode;
                    renderTabs();
                    renderMain(true);
                    return;
                }
                const idx = Number(n.dataset.ti);
                st.activeTab = idx;
                const cur = st.tabs[idx];
                st.curVa = cur.va; st.topVa = cur.topVa; st.mode = cur.mode;
                renderTabs();
                renderMain(true);
            };
        });
    }

    function pinTab() {
        if (!st.info) return;
        const label = (st.decData && st.decData.name) ? st.decData.name : st.curVa;
        st.tabs.push({ va: st.curVa, topVa: st.topVa, mode: st.mode, label });
        st.activeTab = st.tabs.length - 1;
        renderTabs();
    }

    function renderStatusStats() {
        const r = st.info;
        if (!r) { $('st-stats').innerHTML = ''; return; }
        const simd = r.avx2 ? 'AVX2' : 'SSE2';
        const cls = r.avx2 ? 'simd-badge simd-avx2' : 'simd-badge';
        $('st-stats').innerHTML =
            `<span class="${cls}" title="Active SIMD scanner backend">${simd}</span>`
            + `<span>${r.ana_ms.toFixed(1)} ms | ${r.nfunc} funcs | ${r.nxref} xrefs | ${r.nstr} strs</span>`;
    }

    function updateActionButtons() {
        const loaded = !!st.info;
        $('btn-undo').disabled = !loaded;
        $('btn-redo').disabled = !loaded;
        $('btn-snaps').disabled = !loaded;
        $('btn-undo').classList.toggle('dim', !loaded || st.undoN === 0);
        $('btn-redo').classList.toggle('dim', !loaded || st.redoN === 0);
        $('btn-undo').title = st.undoN ? `Undo (${st.undoN}) (Ctrl+Z)` : 'Undo (Ctrl+Z)';
        $('btn-redo').title = st.redoN ? `Redo (${st.redoN}) (Ctrl+Y)` : 'Redo (Ctrl+Y)';
        const ibu = $('ib-undo'), ibr = $('ib-redo');
        if (ibu) { ibu.disabled = !loaded || st.undoN === 0; ibu.title = $('btn-undo').title; }
        if (ibr) { ibr.disabled = !loaded || st.redoN === 0; ibr.title = $('btn-redo').title; }
    }

    async function refreshInfoStats() {
        if (!st.info) return;
        const r = await window.xdis.call({ op: 'info' });
        if (!r.ok) return;
        st.info = r;
        st.undoN = r.undo_n || 0;
        st.redoN = r.redo_n || 0;
        renderStatusStats();
        updateActionButtons();
    }

    async function refreshAfterMutation() {
        await refreshInfoStats();
        await loadList(true);
        await renderMain(true);
    }

    async function doUndo() {
        if (!st.info) return;
        const r = await window.xdis.call({ op: 'undo' });
        st.undoN = r.undo_n || 0;
        st.redoN = r.redo_n || 0;
        updateActionButtons();
        if (!r.ok) return logLine('nothing to undo');
        logLine(`undo (${st.undoN} undo / ${st.redoN} redo)`);
        await refreshAfterMutation();
    }

    async function doRedo() {
        if (!st.info) return;
        const r = await window.xdis.call({ op: 'redo' });
        st.undoN = r.undo_n || 0;
        st.redoN = r.redo_n || 0;
        updateActionButtons();
        if (!r.ok) return logLine('nothing to redo');
        logLine(`redo (${st.undoN} undo / ${st.redoN} redo)`);
        await refreshAfterMutation();
    }

    async function openSnapshots() {
        if (!st.info) return;
        const r = await window.xdis.call({ op: 'snap_list' });
        window.proView.renderSnapshotsModal($('modal-title'), $('modal-body'), $('modal-bg'), (r.ok && r.items) ? r.items : [], {
            onSave: async (name) => {
                const sv = await window.xdis.call({ op: 'snap_save', name });
                logLine(sv.ok ? `saved snapshot "${name}" (.xdb v3)` : `failed to save snapshot "${name}"`);
                openSnapshots();
            },
            onLoad: async (name) => {
                const ld = await window.xdis.call({ op: 'snap_load', name });
                logLine(ld.ok ? `restored snapshot "${name}"` : `failed to restore snapshot "${name}"`);
                if (ld.ok) {
                    closeModal();
                    await refreshAfterMutation();
                }
            },
            onClose: closeModal
        });
    }

    function pushCollabLog(entry) {
        st.collabSt.log.push({ ts: Date.now(), ...entry });
        if (st.collabSt.log.length > 200) st.collabSt.log.splice(0, st.collabSt.log.length - 200);
    }

    function updateCollabIndicator() {
        if (window.xdisPro && window.xdisPro.setCollabActive) {
            window.xdisPro.setCollabActive(st.collabSt.active);
        }
        const el = $('st-collab');
        if (!el) return;
        if (!st.collabSt.active) {
            el.classList.add('hidden');
            el.textContent = '';
            return;
        }
        const n = st.collabSt.peers.length || 1;
        el.textContent = `LIVE ${st.collabSt.role === 'host' ? 'HOST' : 'PEER'} :${st.collabSt.port} (${n})`;
        el.classList.remove('hidden');
    }

    function refreshCollabUiIfVisible() {
        if (st.mode === 'audit' && st.auditSub === 'queue' && window.xdisPro && window.xdisPro.updateAuditCollab) {
            window.xdisPro.updateAuditCollab($('left-body'), st.collabSt, {
                onJump: (va) => { st.mode = 'split'; gotoVa(va, true); }
            });
        }
    }

    function broadcastCursorIfNeeded() {
        if (!st.collabSt.active || !st.info || !st.curVa || st.curVa === st.lastCollabVa) return;
        st.lastCollabVa = st.curVa;
        const fn = (st.decData && st.decData.name) ? st.decData.name : '';
        st.collabSt.peerCursors[st.collabSt.nick] = { va: st.curVa, fn };
        if (window.xdisPro && window.xdisPro.broadcastCollab) {
            window.xdisPro.broadcastCollab({ type: 'cursor', va: st.curVa, fn });
        }
        refreshCollabUiIfVisible();
    }

    async function handleCollabEvent(ev) {
        if (!ev || !ev.type) return;
        if (ev.type === 'status') {
            st.collabSt.active = !!ev.active;
            st.collabSt.role = ev.role || '';
            if (ev.host) st.collabSt.host = ev.host;
            if (ev.port) st.collabSt.port = String(ev.port);
            if (ev.nick) st.collabSt.nick = ev.nick;
            st.collabSt.peers = Array.isArray(ev.peers) ? ev.peers : [];
            if (ev.active) st.collabSt.err = '';
            if (!ev.active) {
                st.collabSt.peerCursors = {};
                st.lastCollabVa = '';
                pushCollabLog({ kind: 'sys', text: 'Disconnected from room.' });
            } else {
                const msg = ev.role === 'host'
                    ? `Hosting room on ${ev.host}:${ev.port} as ${ev.nick}`
                    : `Joined room ${ev.host}:${ev.port} as ${ev.nick}`;
                pushCollabLog({ kind: 'sys', text: msg });
                logLine('[collab] ' + msg);
            }
            updateCollabIndicator();
            refreshCollabUiIfVisible();
            if (ev.active && st.info && st.curVa) {
                st.lastCollabVa = '';
                broadcastCursorIfNeeded();
            }
            return;
        }
        if (ev.type === 'peers') {
            st.collabSt.peers = Array.isArray(ev.peers) ? ev.peers : [];
            if (ev.joined) pushCollabLog({ kind: 'sys', text: `${ev.joined} joined the room` });
            if (ev.left) {
                delete st.collabSt.peerCursors[ev.left];
                pushCollabLog({ kind: 'sys', text: `${ev.left} left the room` });
            }
            updateCollabIndicator();
            refreshCollabUiIfVisible();
            return;
        }
        if (ev.type === 'cursor' && ev.from && ev.va) {
            st.collabSt.peerCursors[ev.from] = { va: ev.va, fn: ev.fn || '' };
            refreshCollabUiIfVisible();
            return;
        }
        if (ev.type === 'rename' && ev.va && ev.name) {
            pushCollabLog({ kind: 'act', from: ev.from || 'peer', text: `renamed -> ${ev.name}`, va: ev.va, ts: ev.ts });
            if (st.info) {
                await window.xdis.call({ op: 'rename', va: ev.va, name: ev.name });
                logLine(`[collab] ${ev.from || 'peer'} renamed ${ev.va} -> ${ev.name}`);
                await refreshAfterMutation();
            } else {
                refreshCollabUiIfVisible();
            }
            return;
        }
        if (ev.type === 'cmt' && ev.va) {
            pushCollabLog({ kind: 'act', from: ev.from || 'peer', text: `comment: ${ev.text || ''}`, va: ev.va, ts: ev.ts });
            if (st.info) {
                await window.xdis.call({ op: 'cmt', va: ev.va, text: ev.text || '' });
                logLine(`[collab] ${ev.from || 'peer'} commented @ ${ev.va}`);
                await refreshInfoStats();
                await renderMain(false);
            } else {
                refreshCollabUiIfVisible();
            }
            return;
        }
        if (ev.type === 'auth_err') {
            st.collabSt.err = ev.err || 'Authentication failed';
            pushCollabLog({ kind: 'sys', text: 'Auth rejected: ' + st.collabSt.err });
            logLine('[collab] ' + st.collabSt.err);
            refreshCollabUiIfVisible();
            return;
        }
        if (ev.type === 'chat') {
            pushCollabLog({ kind: 'chat', from: ev.from || 'peer', text: ev.text || '', ts: ev.ts });
            refreshCollabUiIfVisible();
        }
    }

    function updateStatus() {
        const p = prefs();
        $('st-va').textContent = st.info ? st.curVa : '0x0';
        $('st-var').textContent = st.selVar ? ('var: ' + st.selVar + ' (N rename · Y type)') : '';
        const tName = (window.studio.THEMES[p.theme] || window.studio.THEMES.ida).name;
        const tSpan = $('st-theme-txt');
        if (tSpan) tSpan.textContent = tName;
        else $('st-theme').textContent = tName;
        $('btn-retype').classList.toggle('hidden', !st.selVar);
        $('btn-renvar').classList.toggle('hidden', !st.selVar);
        $('btn-navmode').textContent = p.navMode === 'entropy' ? 'Sections' : 'Entropy';
        $('btn-explain').classList.toggle('hi', !!p.explain);
        $('btn-ins').classList.toggle('hi', !!p.showInspector);
        updateActionButtons();
        updateCollabIndicator();
        if (!st.info) return;
        const cur = BigInt(st.curVa);
        const sec = st.info.secs.find((s) => cur >= BigInt(s.va) && cur < BigInt(s.va) + BigInt(s.vsize));
        $('st-sec').textContent = sec ? sec.name : '';
        $('st-fn').textContent = st.decData && st.decData.name ? st.decData.name : '';
        window.vw.renderNav($('navstrip'), st.info, st.curVa, p.navMode, st.entMap);
        syncActiveTab();
        broadcastCursorIfNeeded();
    }

    async function refreshInspector() {
        const show = prefs().showInspector;
        $('inspector').classList.toggle('hidden', !show);
        $('split-ins').classList.toggle('hidden', !show);
        if (!show || !st.info) return;
        const ins = await window.xdis.call({ op: 'inspect', va: st.curVa });
        window.vw.renderInspector($('ins-body'), ins, { onQuickPatch: applyQuickPatch });
    }

    async function applyQuickPatch(kind) {
        if (!st.info) return;
        if (kind === 'nop') {
            const curRow = st.disRows.find((r) => r.va.toLowerCase() === st.curVa.toLowerCase());
            const len = curRow ? curRow.len : 1;
            const hex = Array(len).fill('90').join(' ');
            const r = await window.xdis.call({ op: 'patch_bytes', va: st.curVa, hex });
            if (r.ok) logLine(`NOP filled ${r.n} bytes at ${st.curVa}`);
            return refreshAfterMutation();
        }
        if (kind === 'ret0') {
            await window.xdis.call({ op: 'patch_bytes', va: st.curVa, hex: '31 c0 c3' });
            logLine(`patched xor eax,eax; ret at ${st.curVa}`);
            return refreshAfterMutation();
        }
        if (kind === 'ret1') {
            await window.xdis.call({ op: 'patch_bytes', va: st.curVa, hex: 'b8 01 00 00 00 c3' });
            logLine(`patched mov eax,1; ret at ${st.curVa}`);
            return refreshAfterMutation();
        }
        if (kind === 'asm') {
            openPrompt(`Assemble x86-64 at ${st.curVa} (e.g. mov eax, 1 / nop / jmp 0x...)`, '', async (v) => {
                if (!v) return;
                const r = await window.xdis.call({ op: 'asm', va: st.curVa, text: v, apply: 1 });
                logLine(r.ok ? `assembled "${v}" -> ${r.hex} (${r.n}B) at ${st.curVa}` : 'assemble failed: ' + (r.err || ''));
                await refreshAfterMutation();
            });
            return;
        }
        if (kind === 'hex') {
            openPrompt(`Patch hex bytes at ${st.curVa} (e.g. 90 90 90)`, '', async (v) => {
                const r = await window.xdis.call({ op: 'patch_bytes', va: st.curVa, hex: v });
                logLine(r.ok ? `patched ${r.n} bytes at ${st.curVa}` : 'patch failed');
                await refreshAfterMutation();
            });
            return;
        }
        if (kind === 'sig') {
            const sr = await window.xdis.call({ op: 'make_sig', va: st.curVa });
            if (!sr.ok) return logLine('make_sig failed at ' + st.curVa);
            logLine(`sig @ ${sr.va}: ${sr.len}B (${sr.hits} hit${sr.hits === 1 ? '' : 's'})`);
            window.proView.renderSigModal($('modal-title'), $('modal-body'), $('modal-bg'), sr, {
                onClose: closeModal,
                onCopy: () => logLine('copied signature to clipboard')
            });
        }
    }

    function findDecVar(vname) {
        if (!st.decData || !Array.isArray(st.decData.vars) || !vname) return null;
        return st.decData.vars.find((v) => v.orig === vname || v.name === vname) || null;
    }

    function promptRenameVar(vname) {
        if (!st.decData || !vname) return;
        const vi = findDecVar(vname);
        const orig = vi ? vi.orig : vname;
        const curName = vi ? vi.name : vname;
        openPrompt(`Rename local variable "${curName}" (${orig})`, curName, async (nv) => {
            if (!nv) return;
            await window.xdis.call({ op: 'lvar', func_va: st.decData.func_va, orig, name: nv, type: '' });
            st.selVar = orig;
            await refreshInfoStats();
            await renderMain(true);
        });
    }

    async function promptRetypeVar(vname) {
        if (!st.decData || !vname) return;
        const vi = findDecVar(vname);
        const orig = vi ? vi.orig : vname;
        const curName = vi ? vi.name : vname;
        const curType = (vi && vi.type) ? vi.type : 'uint32_t';

        const td = await window.xdis.call({ op: 'types' });
        const structs = (td && td.ok && Array.isArray(td.items)) ? td.items.slice(0, 12).map((t) => `${t.name} *`) : [];
        const presets = ['const char *', 'char *', 'void *', 'uint8_t *', 'uint32_t', 'int32_t', 'size_t', 'HANDLE', 'bool', ...structs];

        $('modal-title').textContent = `Retype "${curName}" (${orig})`;
        const body = $('modal-body');
        body.innerHTML =
            `<div class="m-field"><input class="m-in" id="retype-in" value="${window.vw.esc(curType)}" placeholder="e.g. IMAGE_DOS_HEADER *, const char *, uint32_t"></div>`
            + `<div class="retype-chips">${presets.map((p) => `<button class="mini-btn retype-chip" data-ty="${window.vw.esc(p)}">${window.vw.esc(p)}</button>`).join('')}</div>`
            + `<div class="m-acts"><button class="tb-btn" id="retype-cancel">Cancel</button><button class="tb-btn primary" id="retype-ok">Apply Type</button></div>`;
        $('modal-bg').classList.remove('hidden');

        const inp = $('retype-in');
        const applyType = async () => {
            const nt = inp.value.trim();
            if (!nt) return;
            closeModal();
            await window.xdis.call({ op: 'lvar', func_va: st.decData.func_va, orig, name: '', type: nt });
            logLine(`retyped ${curName} (${orig}) -> ${nt}`);
            await refreshInfoStats();
            await renderMain(true);
        };
        $('retype-ok').addEventListener('click', applyType);
        $('retype-cancel').addEventListener('click', closeModal);
        inp.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') applyType();
            else if (e.key === 'Escape') closeModal();
        });
        body.querySelectorAll('.retype-chip').forEach((btn) => {
            btn.addEventListener('click', () => { inp.value = btn.dataset.ty; applyType(); });
        });
        inp.focus();
        inp.select();
    }

    async function refreshDecompiler(target, force) {
        const r = await window.xdis.call({ op: 'dec', va: st.curVa });
        if (r.ok) {
            st.decData = r;
            const title = r.name || ('sub_' + r.func_va.slice(2));
            const vcnt = Array.isArray(r.vars) ? ` · ${r.vars.length} vars` : '';
            if (target === $('left-body')) {
                $('left-title').textContent = 'Pseudocode-A';
                $('left-meta').textContent = `${title} (${r.lines.length} lines${vcnt})`;
            } else {
                $('right-title').textContent = 'Pseudocode-A';
                $('right-meta').textContent = `${title} (${r.lines.length} lines${vcnt})`;
            }
        } else if (force) {
            st.decData = null;
        }

        window.vw.renderDec(target, st.decData, st.curVa, st.selVar, {
            onSyncVa: (va) => { st.selVar = null; syncSelectVa(va); },
            onSelectVar: (v) => { st.selVar = v; renderMain(false); },
            onRenameVar: (v) => promptRenameVar(v),
            onRetypeVar: (v) => promptRetypeVar(v),
            onCopyC: () => {
                if (!st.decData || !st.decData.lines) return;
                navigator.clipboard.writeText(st.decData.lines.map((l) => l.text).join('\n') + '\n');
                logLine('copied decompiled C to clipboard');
            },
            onSymJump: (s) => resolveAndJump(s),
            onSymPeek: (s, e) => schedulePeek(s, e),
            onHidePeek: hidePeek
        });
    }

    async function syncSelectVa(va) {
        st.curVa = va;
        const inView = st.disRows.some((r) => r.va.toLowerCase() === va.toLowerCase());
        if (!inView && (st.mode === 'dis' || st.mode === 'split' || st.mode === 'dhex')) st.topVa = va;
        await renderMain(false);
    }

    function hideUnusedVScrolls() {
        const leftUses = !!st.info && (st.mode === 'dis' || st.mode === 'split' || st.mode === 'dhex' || st.mode === 'hex');
        const rightUses = !!st.info && st.mode === 'dhex';
        if (!leftUses) window.vw.updateVScroll($('left-vscroll'), $('left-body'), null, null, 0, false, false);
        if (!rightUses) window.vw.updateVScroll($('right-vscroll'), $('right-body'), null, null, 0, false, false);
    }

    async function renderDisPane(leftBody) {
        $('left-title').textContent = 'IDA View-A';
        const rowsWant = Math.max(36, Math.ceil((leftBody.clientHeight || 640) / 19) + 8);
        const res = await window.xdis.call({ op: 'dis', va: st.topVa, n: rowsWant });
        if (res.ok) {
            st.disRows = res.rows;
            $('left-meta').textContent = st.curVa;
            window.vw.renderDis(leftBody, st.disRows, st.curVa, st.curVa, prefs().showBytes, prefs().explain, {
                onSelect: (va) => { st.curVa = va; st.selVar = null; renderMain(false); },
                onJump: (va) => gotoVa(va, true),
                onPeek: (va, e) => schedulePeek(va, e),
                onHidePeek: hidePeek
            });
            let visBytes = 0;
            for (const r of st.disRows) visBytes += (r.len || 1);
            window.vw.updateVScroll($('left-vscroll'), leftBody, st.info, st.topVa, visBytes || rowsWant * 4, false, true);
        }
    }

    async function renderViewportFast() {
        if (!st.info) return;
        const leftBody = $('left-body');
        const rightBody = $('right-body');
        if (st.mode === 'dis' || st.mode === 'split' || st.mode === 'dhex') {
            await renderDisPane(leftBody);
            if (st.mode === 'dhex') await renderHexPane(rightBody, 'right');
        } else if (st.mode === 'hex') {
            await renderHexPane(leftBody, 'left');
        }
        const t = st.tabs[st.activeTab];
        if (t) t.topVa = st.topVa;
    }

    async function resolveVaStr(q) {
        const s = String(q || '').trim();
        if (!s) return null;
        if (/^0x[0-9a-f]+$/i.test(s)) return s;
        if (/^[0-9a-f]+$/i.test(s) && s.length >= 4 && !st.info) return '0x' + s;
        if (!st.info) return null;
        const r = await window.xdis.call({ op: 'resolve', q: s });
        return r.ok ? r.va : null;
    }

    function clearDbgCaches() {
        st.dbgMods = null;
        st.dbgThreads = null;
        st.dbgBt = null;
        st.dbgMmap = null;
    }

    async function dbgStepCmd(op, extra) {
        st.dbgPrev = st.dbgSt && st.dbgSt.snap ? st.dbgSt.snap : null;
        st.dbgSnapIdx = -1;
        clearDbgCaches();
        await window.xdis.call({ op, ...(extra || {}) });
        renderMain(false);
    }

    async function dbgTtdBack() {
        st.dbgPrev = st.dbgSt && st.dbgSt.snap ? st.dbgSt.snap : null;
        st.dbgSnapIdx = -1;
        clearDbgCaches();
        const r = await window.xdis.call({ op: 'dbg_ttd_back' });
        if (!r.ok) logLine('TTD step back unavailable');
        renderMain(false);
    }

    const TOOL_TAB_LABELS = {
        gdec: ['Graph + C', 'gdec'],
        calls: ['Call Graph', 'calls'],
        ir: ['SSA IR', 'ir'],
        deobf: ['Deobf Lab', 'deobf'],
        trace: ['Trace & Taint', 'trace'],
        diff: ['Binary Diff', 'diff'],
        audit: ['Audit', 'audit'],
        types: ['Local Types', 'types'],
        debug: ['Debugger', 'debug'],
        dhex: ['Disasm + Hex', 'hex']
    };

    function syncDocTabs() {
        const core = new Set(['split', 'graph', 'hex', 'overview']);
        document.querySelectorAll('#mode-tabs > .m-btn').forEach((b) => {
            b.classList.toggle('active', b.dataset.mode === st.mode);
        });
        document.querySelectorAll('#iconbar .ib-btn[data-ib-mode]').forEach((b) => {
            b.classList.toggle('active', b.dataset.ibMode === st.mode);
        });
        const slot = $('tool-tab-slot');
        const btn = $('tool-tab-btn');
        if (!slot || !btn) return;
        const meta = TOOL_TAB_LABELS[st.mode];
        if (!core.has(st.mode) && meta) {
            const ic = window.xdisIcons ? window.xdisIcons.svg(meta[1], 'ic ic-sm') : '';
            btn.innerHTML = ic + window.vw.esc(meta[0]);
            btn.dataset.mode = st.mode;
            slot.classList.remove('hidden');
        } else {
            slot.classList.add('hidden');
        }
    }

    async function renderMain(forceDec) {
        syncDocTabs();
        if (!st.info && st.mode !== 'debug') {
            $('pane-right').classList.add('hidden');
            $('split-mid').classList.add('hidden');
            hideUnusedVScrolls();
            $('left-body').innerHTML = `
              <div class="welcome">
                <h2>xdis</h2>
                <p>Drop any PE, ELF, Mach-O, WASM, DEX, or raw binary to start disassembling.</p>
                <button class="tb-btn hi" id="w-open">Open binary (Ctrl+O)</button>
                <div class="keys">
                  <span>F5 Pseudocode</span><span>Space Graph</span><span>G Jump</span>
                  <span>Ctrl+K Commands</span><span>F9 Debug</span>
                </div>
              </div>`;
            const b = $('w-open');
            if (b) b.addEventListener('click', openDialog);
            refreshInspector();
            updateActionButtons();
            return;
        }

        const hasRight = !!st.info && (st.mode === 'split' || st.mode === 'gdec' || st.mode === 'dhex');
        $('pane-right').classList.toggle('hidden', !hasRight);
        $('split-mid').classList.toggle('hidden', !hasRight);
        hideUnusedVScrolls();

        const leftBody = $('left-body');
        const rightBody = $('right-body');

        if (st.mode === 'overview') {
            $('left-title').textContent = 'Triage Overview';
            $('left-meta').textContent = st.triage ? st.triage.verdict : '';
            window.triView.renderOverview(leftBody, st.info, st.triage, st.entMap, { crypto: st.crypto, vtables: st.vtables, lang: st.lang }, {
                onAction: (act) => {
                    if (act === 'entry') { st.mode = 'split'; gotoVa(st.info.entry, true); }
                    else if (act === 'gdec') { st.mode = 'gdec'; gotoVa(st.info.entry, true); }
                    else if (act === 'deobf') { st.mode = 'deobf'; gotoVa(st.info.entry, true); }
                    else if (act === 'trace') { st.mode = 'trace'; gotoVa(st.info.entry, true); }
                    else if (act === 'ir') { st.mode = 'ir'; st.irSub = 'ir'; renderMain(false); }
                    else if (act === 'lang') { st.mode = 'ir'; st.irSub = 'lang'; renderMain(false); }
                    else if (act === 'pdb') loadPdbDialog();
                    else if (act === 'sig_apply') applySigDialog();
                    else if (act === 'rep_html') exportReportDialog('html');
                    else if (act === 'rep_md') exportReportDialog('md');
                    else if (act === 'guide') window.triView.openGuide($('modal-title'), $('modal-body'), $('modal-bg'));
                },
                onJump: (va) => { st.mode = 'split'; gotoVa(va, true); },
                onDeobf: (va) => { st.mode = 'deobf'; gotoVa(va, true); },
                onTrace: (va) => { st.mode = 'trace'; gotoVa(va, true); },
                onPeek: (va, e) => schedulePeek(va, e),
                onHidePeek: hidePeek
            });
        } else if (st.mode === 'ir') {
            const sub = st.irSub || 'mlir';
            let ssa = null, ir = null, sws = null;
            if (sub === 'mlir' || sub === 'llir') {
                $('left-title').textContent = sub === 'llir' ? 'SSA LLIR & Types' : 'SSA MLIR & Types';
                [ssa, ir, sws] = await Promise.all([
                    window.xdis.call({ op: 'ssa', va: st.curVa, tier: sub }),
                    window.xdis.call({ op: 'ir', va: st.curVa }),
                    window.xdis.call({ op: 'switches', va: st.curVa })
                ]);
                $('left-meta').textContent = ssa.ok ? `${ssa.ops.length} ops · ${ssa.nblk} blk · ${ssa.nphi} phi` : '';
            } else if (sub === 'ir') {
                $('left-title').textContent = 'Microcode IR (Legacy)';
                [ir, sws] = await Promise.all([
                    window.xdis.call({ op: 'ir', va: st.curVa }),
                    window.xdis.call({ op: 'switches', va: st.curVa })
                ]);
                if (!st.vtables) st.vtables = await window.xdis.call({ op: 'vtables' });
                $('left-meta').textContent = ir.ok ? `${ir.ops.length} IR ops · ${ir.structs.length} structs` : '';
            } else {
                $('left-title').textContent = 'Classes & Runtime Recovery';
                const fetches = [];
                if (!st.lang) fetches.push(window.xdis.call({ op: 'lang' }).then((r) => { st.lang = r; }));
                if (st.info.has_clr && !st.dotnet) fetches.push(window.xdis.call({ op: 'dotnet' }).then((r) => { st.dotnet = r; }));
                if (fetches.length) await Promise.all(fetches);
                const metaParts = [];
                if (st.lang && st.lang.ok) metaParts.push(`${st.lang.runtime} · ${(st.lang.classes || []).length} classes`);
                if (st.dotnet && st.dotnet.ok) metaParts.push(`CLR ${st.dotnet.ver || ''} (${(st.dotnet.types || []).length}T/${(st.dotnet.methods || []).length}M)`);
                $('left-meta').textContent = metaParts.join(' · ');
            }
            window.proView.renderIR(leftBody, sub, { ssa, ir, vts: st.vtables, sws, lang: st.lang, dotnet: st.dotnet }, st.curVa, {
                onSub: (next) => { st.irSub = next; renderMain(false); },
                onSelect: (va) => { st.curVa = va; refreshInspector(); updateStatus(); },
                onJump: (va) => { st.mode = 'split'; gotoVa(va, true); },
                onAddStruct: async (decl) => {
                    const r = await window.xdis.call({ op: 'type_add', decl });
                    logLine(r.ok ? 'added auto-recovered struct to local types' : 'failed to add struct');
                }
            });
        } else if (st.mode === 'diff') {
            $('left-title').textContent = st.diffSt.view === 'triage' ? 'Security Patch Triage' : 'Semantic Binary Diff';
            $('left-meta').textContent = st.diffSt.view === 'triage' && st.diffSt.pdiff && st.diffSt.pdiff.ok
                ? `${st.diffSt.pdiff.items.length} security-ranked functions`
                : (st.diffSt.data && st.diffSt.data.ok
                    ? `MOD ${st.diffSt.data.mod} · ADD ${st.diffSt.data.add} · DEL ${st.diffSt.data.del}` : '');
            window.proView.renderDiff(leftBody, st.diffSt, {
                onPick: async () => {
                    const p = await window.xdis.pickFile({ title: 'Pick second binary to diff' });
                    if (!p) return;
                    logLine('diffing against ' + p + '...');
                    const r = await window.xdis.call({ op: 'diff', path: p });
                    st.diffSt = { otherPath: p, data: r, filter: 'all', sel: null, codeA: [], codeB: [], pdiff: null, view: 'diff' };
                    renderMain(false);
                },
                onFilter: (f) => { st.diffSt.filter = f; st.diffSt.view = 'diff'; renderMain(false); },
                onTriage: async () => {
                    if (!st.diffSt.data || !st.diffSt.data.ok) return;
                    const rerun = st.diffSt.view === 'triage';
                    st.diffSt.view = 'triage';
                    if (!st.diffSt.pdiff || rerun) {
                        st.diffSt.pdiff = null;
                        renderMain(false);
                        const pr = await window.xdis.call({ op: 'pdiff', path: '' });
                        st.diffSt.pdiff = pr;
                        logLine(pr.ok
                            ? `security patch triage ranked ${pr.items.length} functions`
                            : `security patch triage failed: ${pr.err || ''}`);
                    }
                    renderMain(false);
                },
                onSelect: async (it) => {
                    if (!it) return;
                    st.diffSt.sel = it;
                    const [da, db] = await Promise.all([
                        it.va_a !== '0x0' ? window.xdis.call({ op: 'dec', va: it.va_a }) : Promise.resolve({ ok: false }),
                        it.va_b !== '0x0' ? window.xdis.call({ op: 'diff_dec', va: it.va_b }) : Promise.resolve({ ok: false })
                    ]);
                    st.diffSt.codeA = da.ok ? da.lines.map((l) => l.text) : [];
                    st.diffSt.codeB = db.ok ? db.lines : [];
                    renderMain(false);
                },
                onJumpA: (va) => { st.mode = 'split'; gotoVa(va, true); }
            });
        } else if (st.mode === 'audit') {
            const sub = st.auditSub || 'vuln';
            const ast = st.auditSt;
            if (sub === 'vuln') {
                $('left-title').textContent = 'Audit · Vulnerability Slicer';
                if (!ast.vulnLoaded) {
                    ast.vulnLoaded = true;
                    ast.vuln = await window.xdis.call({ op: 'vuln' });
                }
                $('left-meta').textContent = ast.vuln && ast.vuln.ok
                    ? `HIGH ${ast.vuln.nhigh} · MED ${ast.vuln.nmed} · ${(ast.vuln.items || []).length} findings` : '';
            } else if (sub === 'yara') {
                $('left-title').textContent = 'Audit · YARA Scanner';
                if (!ast.yaraDefaultsLoaded && !ast.yaraRules) {
                    ast.yaraDefaultsLoaded = true;
                    const dr = await window.xdis.call({ op: 'yara_defaults' });
                    if (dr && dr.ok && dr.rules) ast.yaraRules = dr.rules;
                }
                $('left-meta').textContent = ast.yaraRes && ast.yaraRes.ok
                    ? `${ast.yaraRes.nrules} rules · ${(ast.yaraRes.hits || []).length} hits` : '';
            } else if (sub === 'carve') {
                $('left-title').textContent = 'Audit · Carver & IOC Extractor';
                const nc = ast.carve && ast.carve.ok ? (ast.carve.items || []).length : 0;
                const ni = ast.iocs && ast.iocs.ok ? (ast.iocs.items || []).length : 0;
                $('left-meta').textContent = `${nc} carved · ${ni} IOCs`;
            } else if (sub === 'hilbert') {
                $('left-title').textContent = 'Audit · Hilbert Entropy Map';
                if (!ast.hilbert) {
                    ast.hilbert = await window.xdis.call({ op: 'hilbert', order: ast.hilbertOrder || 6 });
                }
                $('left-meta').textContent = ast.hilbert && ast.hilbert.ok
                    ? `${ast.hilbert.side}x${ast.hilbert.side} (${ast.hilbert.ncell} cells)` : '';
            } else {
                $('left-title').textContent = 'Audit · AI Suggestion Queue & Live Collab';
                ast.sugs = await window.xdis.call({ op: 'sug_list' });
                const pend = ast.sugs && ast.sugs.ok ? ast.sugs.pending : 0;
                const live = st.collabSt.active ? ` · LIVE (${st.collabSt.peers.length || 1} peers)` : '';
                $('left-meta').textContent = `${pend} pending suggestions${live}`;
            }

            const jumpHexFromOff = (off) => {
                if (!st.info) return;
                const o = BigInt(off || 0);
                let targetVa = null;
                if (Array.isArray(st.info.secs)) {
                    for (const s of st.info.secs) {
                        if (s.foff !== undefined && s.fsize > 0) {
                            const so = BigInt(s.foff);
                            if (o >= so && o < so + BigInt(s.fsize)) {
                                targetVa = '0x' + (BigInt(s.va) + (o - so)).toString(16);
                                break;
                            }
                        }
                    }
                }
                if (!targetVa) {
                    const base = BigInt(st.info.base || st.info.min_va || '0x0');
                    const minVa = BigInt(st.info.min_va || '0x0');
                    const maxVa = BigInt(st.info.max_va || '0x0');
                    let cand = base + o;
                    if (cand < minVa) cand = minVa;
                    if (maxVa > 16n && cand >= maxVa) cand = maxVa - 16n;
                    targetVa = '0x' + cand.toString(16);
                }
                st.mode = 'hex';
                gotoVa(targetVa, true);
            };

            window.xdisPro.renderAudit(leftBody, sub, {
                vuln: ast.vuln,
                yaraRules: ast.yaraRules,
                yaraRes: ast.yaraRes,
                carve: ast.carve,
                iocs: ast.iocs,
                iocFilter: ast.iocFilter,
                hilbertOrder: ast.hilbertOrder,
                hilbert: ast.hilbert,
                sugs: ast.sugs,
                sugDraft: ast.sugDraft,
                collab: st.collabSt
            }, st.curVa, {
                onSub: (next) => { st.auditSub = next; renderMain(false); },
                onJump: (va) => { st.mode = 'split'; gotoVa(va, true); },
                onJumpHex: (off) => jumpHexFromOff(off),
                onVulnScan: async () => {
                    ast.vulnLoaded = true;
                    ast.vuln = await window.xdis.call({ op: 'vuln' });
                    if (ast.vuln && ast.vuln.ok) {
                        logLine(`vuln slicer: HIGH ${ast.vuln.nhigh}, MED ${ast.vuln.nmed}, total ${(ast.vuln.items || []).length}`);
                    }
                    renderMain(false);
                },
                onYaraDraft: (txt) => { ast.yaraRules = txt; },
                onYaraDefaults: async () => {
                    const dr = await window.xdis.call({ op: 'yara_defaults' });
                    if (dr && dr.ok && dr.rules) {
                        ast.yaraRules = dr.rules;
                        ast.yaraDefaultsLoaded = true;
                        logLine('loaded built-in default YARA rules');
                    }
                    renderMain(false);
                },
                onYaraRun: async (rules) => {
                    ast.yaraRules = rules;
                    ast.yaraRes = await window.xdis.call({ op: 'yara', rules });
                    logLine(ast.yaraRes && ast.yaraRes.ok
                        ? `YARA scan: ${ast.yaraRes.nrules} rules, ${(ast.yaraRes.hits || []).length} hits`
                        : `YARA scan error: ${(ast.yaraRes && ast.yaraRes.err) || 'failed'}`);
                    renderMain(false);
                },
                onCarveScan: async () => {
                    ast.carve = await window.xdis.call({ op: 'carve' });
                    logLine(ast.carve && ast.carve.ok ? `carver found ${(ast.carve.items || []).length} embedded artifacts` : 'carve failed');
                    renderMain(false);
                },
                onCarveExtract: async (item) => {
                    const ext = String(item.kind || 'bin').toLowerCase().replace(/[^a-z0-9]/g, '') || 'bin';
                    const defName = `carved_${Number(item.off || 0).toString(16)}.${ext}`;
                    const p = await window.xdis.saveFile({
                        title: `Extract carved ${item.kind || 'artifact'} (${item.size} bytes)`,
                        defaultName: defName
                    });
                    if (!p) return;
                    const r = await window.xdis.call({ op: 'carve_extract', off: Number(item.off || 0), size: Number(item.size || 0), path: p });
                    logLine(r && r.ok ? `extracted ${item.size}B ${item.kind} -> ${p}` : `carve extract failed -> ${p}`);
                },
                onIocScan: async () => {
                    ast.iocs = await window.xdis.call({ op: 'iocs' });
                    logLine(ast.iocs && ast.iocs.ok ? `extracted ${(ast.iocs.items || []).length} IOCs` : 'IOC extraction failed');
                    renderMain(false);
                },
                onIocFilter: (txt) => { ast.iocFilter = txt; },
                onHilbertOrder: (ord) => { ast.hilbertOrder = ord; },
                onHilbertRender: async (ord) => {
                    ast.hilbertOrder = ord;
                    ast.hilbert = await window.xdis.call({ op: 'hilbert', order: ord });
                    renderMain(false);
                },
                onSugDraft: (d) => { ast.sugDraft = d; },
                onSugRefresh: async () => {
                    ast.sugs = await window.xdis.call({ op: 'sug_list' });
                    renderMain(false);
                },
                onSugAdd: async (req) => {
                    const va = (await resolveVaStr(req.va)) || st.curVa;
                    const r = await window.xdis.call({
                        op: 'sug_add',
                        va,
                        kind: req.kind,
                        val: req.val,
                        reason: req.reason,
                        conf: req.conf
                    });
                    if (r && r.ok) {
                        ast.sugDraft = { va: st.curVa, kind: req.kind, val: '', reason: '', conf: String(req.conf) };
                        logLine(`queued suggestion #${r.id} (${req.kind} @ ${va})`);
                    } else {
                        logLine('failed to queue suggestion: ' + ((r && r.err) || ''));
                    }
                    ast.sugs = await window.xdis.call({ op: 'sug_list' });
                    renderMain(false);
                },
                onSugDecide: async (id, accept, minConf) => {
                    const prevItems = (ast.sugs && ast.sugs.ok && Array.isArray(ast.sugs.items)) ? ast.sugs.items : [];
                    const toBroadcast = accept ? prevItems.filter((s) =>
                        String(s.status || '').toLowerCase() === 'pending'
                        && (id > 0 ? s.id === id : Number(s.conf || 0) >= minConf)
                    ) : [];
                    const r = await window.xdis.call({ op: 'sug_decide', id, accept, min_conf: minConf });
                    ast.sugs = await window.xdis.call({ op: 'sug_list' });
                    logLine(r && r.ok
                        ? `${accept ? 'accepted' : 'rejected'} ${r.applied} suggestion(s) (${r.pending} pending)`
                        : 'suggestion decision failed');
                    if (accept && r && r.ok && r.applied > 0) {
                        for (const s of toBroadcast) {
                            if (s.kind === 'rename') {
                                window.xdisPro.broadcastCollab({ type: 'rename', va: s.va, name: s.val });
                            } else if (s.kind === 'cmt') {
                                window.xdisPro.broadcastCollab({ type: 'cmt', va: s.va, text: s.val });
                            }
                        }
                        await refreshAfterMutation();
                    } else {
                        renderMain(false);
                    }
                },
                onCollabDraft: (d) => {
                    st.collabSt.nick = d.nick;
                    st.collabSt.host = d.host;
                    st.collabSt.port = d.port;
                    st.collabSt.pass = d.pass || '';
                    st.collabSt.chatDraft = d.chatDraft;
                },
                onCollabHost: async ({ nick, host, port, pass = '' }) => {
                    st.collabSt.nick = nick;
                    st.collabSt.host = host;
                    st.collabSt.port = String(port);
                    st.collabSt.pass = pass;
                    st.collabSt.err = '';
                    const r = await window.xdis.collabHost({ host, port, nick, pass });
                    if (!r || !r.ok) {
                        st.collabSt.err = (r && r.err) || 'Failed to host room';
                        logLine('[collab] host failed: ' + st.collabSt.err);
                    }
                    refreshCollabUiIfVisible();
                },
                onCollabJoin: async ({ nick, host, port, pass = '' }) => {
                    st.collabSt.nick = nick;
                    st.collabSt.host = host;
                    st.collabSt.port = String(port);
                    st.collabSt.pass = pass;
                    st.collabSt.err = '';
                    const r = await window.xdis.collabJoin({ host, port, nick, pass });
                    if (!r || !r.ok) {
                        st.collabSt.err = (r && r.err) || 'Failed to join room';
                        logLine('[collab] join failed: ' + st.collabSt.err);
                    }
                    refreshCollabUiIfVisible();
                },
                onCollabStop: async () => {
                    st.collabSt.err = '';
                    await window.xdis.collabStop();
                    refreshCollabUiIfVisible();
                },
                onCollabChat: async (text) => {
                    if (!st.collabSt.active || !text) return;
                    await window.xdisPro.broadcastCollab({ type: 'chat', text });
                    pushCollabLog({ kind: 'chat', from: st.collabSt.nick, text });
                    refreshCollabUiIfVisible();
                }
            });
        } else if (st.mode === 'types') {
            $('left-title').textContent = 'Local C Type Library';
            const td = await window.xdis.call({ op: 'types' });
            const ovMeta = st.structOverlay && st.structOverlay.ok ? ` · ${st.structOverlay.name} @ ${st.structOverlay.va}` : '';
            $('left-meta').textContent = td.ok ? `${td.items.length} types${ovMeta}` : '';
            window.proView.renderTypes(leftBody, td, st.typeDraft, st.structOverlay, st.curVa, {
                onDraft: (v) => { st.typeDraft = v; },
                onAdd: async (decl) => {
                    const r = await window.xdis.call({ op: 'type_add', decl });
                    logLine(r.ok ? `parsed & added ${r.added || 1} type(s)` : 'failed to parse C type declaration');
                    renderMain(false);
                },
                onLoadHeader: async () => {
                    const p = await window.xdis.pickFile({
                        title: 'Load C/C++ Header (.h / .hpp)',
                        filters: [{ name: 'C/C++ Headers', extensions: ['h', 'hpp', 'hh', 'hxx'] }, { name: 'All files', extensions: ['*'] }]
                    });
                    if (!p) return;
                    const r = await window.xdis.call({ op: 'chdr_parse', path: p });
                    const bn = p.split(/[\\/]/).pop();
                    logLine(r.ok
                        ? `parsed ${bn}: +${r.added} types, ${r.defines} #defines`
                        : `header parse failed (${bn}): ${r.err || 'no types found'}`);
                    renderMain(false);
                },
                onLoadStdlib: async (pack) => {
                    const r = await window.xdis.call({ op: 'chdr_stdlib', pack });
                    logLine(r.ok ? `loaded ${pack} .xtil (+${r.added} types)` : `${pack} .xtil: no new types added`);
                    renderMain(false);
                },
                onLoadPdbMsf: async () => {
                    const p = await window.xdis.pickFile({
                        title: 'Load Native MSF PDB (.pdb)',
                        filters: [{ name: 'Program Database', extensions: ['pdb'] }, { name: 'All files', extensions: ['*'] }]
                    });
                    if (!p) return;
                    const r = await window.xdis.call({ op: 'pdb_msf', path: p });
                    logLine(r.ok
                        ? `MSF PDB (${r.fmt || 'PDB'}): +${r.syms} syms, +${r.types} types, +${r.funcs} funcs`
                        : `MSF PDB load failed: ${r.err || 'parse error'}`);
                    await refreshAfterMutation();
                },
                onLoadDwarf: async () => {
                    const r = await window.xdis.call({ op: 'dwarf_load' });
                    logLine(r.ok
                        ? `DWARF (${r.fmt || 'DWARF'}): +${r.syms} syms, +${r.types} types, +${r.funcs} funcs`
                        : `DWARF scan: ${r.err || 'no DWARF debug sections found'}`);
                    await refreshAfterMutation();
                },
                onApplyStruct: async (name, rawVa) => {
                    const va = (await resolveVaStr(rawVa)) || st.curVa;
                    const r = await window.xdis.call({ op: 'struct_apply', name, va });
                    st.structOverlay = r;
                    logLine(r.ok
                        ? `overlay ${r.name} @ ${r.va} (${r.got}/${r.size}B · ${r.live ? 'LIVE' : 'STATIC'})`
                        : `struct_apply failed: ${r.err || 'unknown type'}`);
                    renderMain(false);
                },
                onCloseOverlay: () => { st.structOverlay = null; renderMain(false); },
                onJump: (va) => { st.mode = 'split'; gotoVa(va, true); }
            });
        } else if (st.mode === 'debug') {
            const tab = st.dbgTab || 'local';
            if (tab === 'local') {
                $('left-title').textContent = 'Debugger v2 · Win32 & Delta Time-Travel';
                st.dbgSt = st.dbgSnapIdx >= 0
                    ? await window.xdis.call({ op: 'dbg_snap', idx: st.dbgSnapIdx })
                    : await window.xdis.call({ op: 'dbg_snap' });
                if (st.dbgSt && st.dbgSt.attached && !st.dbgMods) {
                    [st.dbgMods, st.dbgThreads, st.dbgBt, st.dbgMmap] = await Promise.all([
                        window.xdis.call({ op: 'dbg_mods' }),
                        window.xdis.call({ op: 'dbg_threads' }),
                        window.xdis.call({ op: 'dbg_bt' }),
                        window.xdis.call({ op: 'dbg_mmap' })
                    ]);
                }
                $('left-meta').textContent = st.dbgSt && st.dbgSt.attached
                    ? `PID ${st.dbgSt.pid} · ${st.dbgSt.nsnap} snaps · ${st.dbgSt.nttd || 0} TTD`
                    : 'Idle';
            } else if (tab === 'gdb') {
                $('left-title').textContent = 'Debugger v2 · Remote GDB Stub';
                $('left-meta').textContent = st.gdbSt && st.gdbSt.connected
                    ? `${st.gdbSt.host}:${st.gdbSt.port} · ${st.gdbSt.rip}`
                    : 'Disconnected';
            } else {
                $('left-title').textContent = 'Debugger v2 · Windows Crash Dump (.dmp)';
                $('left-meta').textContent = st.dmpSt && st.dmpSt.loaded
                    ? `OS ${st.dmpSt.os} · ${st.dmpSt.exc_code}`
                    : 'No dump loaded';
            }

            const isPe = !!(st.info && String(st.info.fmt || '').toUpperCase().startsWith('PE'));
            const dbgBundle = {
                tab,
                sideTab: st.dbgSideTab,
                dbg: st.dbgSt,
                prevSnap: st.dbgPrev,
                mods: st.dbgMods,
                threads: st.dbgThreads,
                bt: st.dbgBt,
                mmap: st.dbgMmap,
                who: st.dbgWho,
                gdbHost: st.gdbHost,
                gdbPort: st.gdbPort,
                gdb: st.gdbSt,
                gdbPrev: st.gdbPrev,
                gdbBps: st.gdbBps,
                dmp: st.dmpSt,
                dmpSelTid: st.dmpSelTid
            };

            window.proView.renderDebug(leftBody, dbgBundle, st.curVa, {
                hasBinary: !!st.info,
                canDump: isPe || !!(st.dbgSt && st.dbgSt.attached),
                onTab: (next) => { st.dbgTab = next; renderMain(false); },
                onSideTab: (next) => { st.dbgSideTab = next; renderMain(false); },
                onRefreshSide: () => { clearDbgCaches(); renderMain(false); },
                onJump: (va) => {
                    if (st.info && va && va !== '0x0') { st.mode = 'split'; gotoVa(va, true); }
                },
                onLaunch: async () => {
                    let target = st.info ? st.info.path : '';
                    if (!target) {
                        target = await window.xdis.pickFile({ title: 'Pick executable to launch' });
                        if (!target) return;
                    }
                    openPrompt('Launch executable args (empty = default)', '', async (args) => {
                        st.dbgPrev = null; st.dbgSnapIdx = -1; st.dbgWho = null; clearDbgCaches();
                        await window.xdis.call({ op: 'dbg_launch', path: target, args });
                        renderMain(false);
                    });
                },
                onAttach: () => openPrompt('Attach to running Win32 PID (decimal)', '', async (v) => {
                    const pid = parseInt(v, 10);
                    if (!pid) return;
                    st.dbgPrev = null; st.dbgSnapIdx = -1; st.dbgWho = null; clearDbgCaches();
                    await window.xdis.call({ op: 'dbg_attach', pid });
                    renderMain(false);
                }),
                onStep: () => dbgStepCmd('dbg_step'),
                onStepOver: () => dbgStepCmd('dbg_step_over'),
                onStepOut: () => dbgStepCmd('dbg_step_out'),
                onCont: () => dbgStepCmd('dbg_cont', { ms: 1500 }),
                onPause: () => dbgStepCmd('dbg_pause'),
                onSetReg: (reg, curVal) => {
                    const name = String(reg || '').trim().toLowerCase();
                    if (!name) return;
                    if (!st.dbgSt || !st.dbgSt.attached || !st.dbgSt.paused) {
                        logLine('debugger must be attached and paused to modify registers');
                        return;
                    }
                    openPrompt(`Set register ${name} (hex, e.g. 0x1234)`, curVal || '0x0', async (v) => {
                        const raw = (v || '').trim();
                        if (!raw) return;
                        const newHex = /^0x[0-9a-f]+$/i.test(raw)
                            ? raw
                            : (/^[0-9a-f]+$/i.test(raw) ? '0x' + raw : raw);
                        st.dbgPrev = st.dbgSt && st.dbgSt.snap ? st.dbgSt.snap : null;
                        st.dbgSnapIdx = -1;
                        clearDbgCaches();
                        const r = await window.xdis.call({ op: 'dbg_set_reg', reg: name, val: newHex });
                        if (!r || !r.ok) {
                            logLine(`dbg_set_reg(${name}) failed: ${(r && r.err) || 'error'}`);
                        } else {
                            logLine(`set ${name} = ${newHex}`);
                        }
                        renderMain(false);
                    });
                },
                onTtdRec: () => openPrompt('Record delta TTD steps (max count)', '128', async (v) => {
                    const n = parseInt(v, 10) || 128;
                    st.dbgPrev = st.dbgSt && st.dbgSt.snap ? st.dbgSt.snap : null;
                    st.dbgSnapIdx = -1;
                    clearDbgCaches();
                    const r = await window.xdis.call({ op: 'dbg_ttd_rec', n });
                    logLine(r.ok ? `TTD recorded ${r.recorded} steps (total ${r.nttd})` : 'TTD record failed');
                    renderMain(false);
                }),
                onTtdBack: dbgTtdBack,
                onTtdWho: () => openPrompt('Who Wrote? Register (e.g. rax) or hex memory VA (0x...)', 'rax', async (v) => {
                    const q = (v || '').trim();
                    if (!q) return;
                    const isHex = /^0x[0-9a-f]+$/i.test(q);
                    const req = isHex ? { op: 'dbg_ttd_who', va: q, reg: '' } : { op: 'dbg_ttd_who', va: 0, reg: q.toLowerCase() };
                    const r = await window.xdis.call(req);
                    st.dbgWho = { query: q, res: r };
                    logLine(r.ok ? `who_wrote(${q}) -> #${r.idx} @ ${r.rip} (${r.old} -> ${r.new})` : `who_wrote(${q}) -> not found`);
                    renderMain(false);
                }),
                onBp: async (va, del) => {
                    if (!del && (!va || va === '0x0')) {
                        openPrompt('Software Breakpoint VA (0x...)', '', async (v) => {
                            const addr = await resolveVaStr(v);
                            if (!addr) return;
                            await window.xdis.call({ op: 'dbg_bp', va: addr, del: 0 });
                            renderMain(false);
                        });
                        return;
                    }
                    await window.xdis.call({ op: 'dbg_bp', va, del });
                    renderMain(false);
                },
                onCondBp: () => openPrompt(`Conditional BP: "<va> <expr>" or "<expr>" @ ${st.curVa}`, 'rax==0', async (v) => {
                    const s = (v || '').trim();
                    if (!s) return;
                    let va = st.curVa;
                    let cond = s;
                    const m = s.match(/^(0x[0-9a-f]+)\s+(.+)$/i);
                    if (m) { va = m[1]; cond = m[2].trim(); }
                    await window.xdis.call({ op: 'dbg_bp', va, del: 0, cond });
                    renderMain(false);
                }),
                onHwBp: () => openPrompt('Hardware BP (DR0..DR3): "<va> [exec|write|rw] [1|2|4|8]"', `${st.curVa} exec 1`, async (v) => {
                    const parts = (v || '').trim().split(/\s+/);
                    const va = await resolveVaStr(parts[0] || st.curVa);
                    if (!va) return;
                    const kStr = (parts[1] || 'exec').toLowerCase();
                    const kind = kStr === 'write' || kStr === 'w' ? 1 : (kStr === 'rw' ? 3 : (kStr === 'exec' || kStr === 'x' ? 0 : (parseInt(kStr, 10) || 0)));
                    const size = parseInt(parts[2] || '1', 10) || 1;
                    await window.xdis.call({ op: 'dbg_hwbp', va, kind, size, del: 0 });
                    renderMain(false);
                }),
                onMemBp: () => openPrompt('Memory Guard BP (PAGE_GUARD): "<va> [size]"', `${st.curVa} 4096`, async (v) => {
                    const parts = (v || '').trim().split(/\s+/);
                    const va = await resolveVaStr(parts[0] || st.curVa);
                    if (!va) return;
                    const size = parseInt(parts[1] || '4096', 10) || 4096;
                    await window.xdis.call({ op: 'dbg_membp', va, size, del: 0 });
                    renderMain(false);
                }),
                onDelHwBp: async (slot) => {
                    await window.xdis.call({ op: 'dbg_hwbp', slot, del: 1 });
                    renderMain(false);
                },
                onDelMemBp: async (va) => {
                    await window.xdis.call({ op: 'dbg_membp', va, del: 1 });
                    renderMain(false);
                },
                onSyncRip: () => {
                    const snap = st.dbgSt && st.dbgSt.snap ? st.dbgSt.snap : null;
                    if (st.info && snap && snap.rip) { st.mode = 'split'; gotoVa(snap.rip, true); }
                },
                onDumpPe: async () => {
                    const p = await window.xdis.saveFile({
                        title: 'Dump & Rebuild PE',
                        defaultName: 'rebuilt.exe',
                        filters: [{ name: 'PE Executables', extensions: ['exe', 'dll', 'bin'] }, { name: 'All files', extensions: ['*'] }]
                    });
                    if (!p) return;
                    const snap = st.dbgSt && st.dbgSt.snap ? st.dbgSt.snap : null;
                    const oep = (snap && snap.rip) ? snap.rip : 0;
                    const r = await window.xdis.call({ op: 'unp_rebuild', path: p, base: 0, oep });
                    $('console-drawer').classList.remove('hidden');
                    logLine(r && r.ok
                        ? `rebuilt PE -> ${p} (${r.nsec} sections, ${r.size} bytes)`
                        : `rebuild PE failed: ${(r && r.err) ? r.err : 'unknown error'}`);
                },
                onScrub: (idx) => {
                    st.dbgPrev = st.dbgSt && st.dbgSt.snap ? st.dbgSt.snap : null;
                    st.dbgSnapIdx = idx;
                    renderMain(false);
                },
                onDetach: async () => { st.dbgSnapIdx = -1; clearDbgCaches(); await window.xdis.call({ op: 'dbg_detach' }); renderMain(false); },
                onKill: async () => { st.dbgSnapIdx = -1; clearDbgCaches(); await window.xdis.call({ op: 'dbg_kill' }); renderMain(false); },
                onGdbDraft: (host, port) => { st.gdbHost = host; st.gdbPort = port; },
                onGdbConnect: async (host, port) => {
                    st.gdbHost = host || '127.0.0.1';
                    st.gdbPort = String(port || 1234);
                    st.gdbPrev = null;
                    st.gdbBps = [];
                    st.gdbSt = await window.xdis.call({ op: 'gdb_connect', host: st.gdbHost, port: Number(st.gdbPort), ms: 2500 });
                    logLine(st.gdbSt.connected ? `connected to GDB ${st.gdbHost}:${st.gdbPort}` : `GDB connect failed: ${st.gdbSt.err || ''}`);
                    renderMain(false);
                },
                onGdbStep: async () => {
                    st.gdbPrev = st.gdbSt;
                    st.gdbSt = await window.xdis.call({ op: 'gdb_step' });
                    renderMain(false);
                },
                onGdbCont: async () => {
                    st.gdbPrev = st.gdbSt;
                    st.gdbSt = await window.xdis.call({ op: 'gdb_cont', ms: 1500 });
                    renderMain(false);
                },
                onGdbBp: (hw) => {
                    const defVa = (st.gdbSt && st.gdbSt.rip && st.gdbSt.rip !== '0x0') ? st.gdbSt.rip : st.curVa;
                    openPrompt(`Remote GDB ${hw ? 'Hardware' : 'Software'} BP VA`, defVa, async (v) => {
                        const va = await resolveVaStr(v);
                        if (!va) return;
                        const r = await window.xdis.call({ op: 'gdb_bp', va, hw, del: 0 });
                        if (r.ok && !st.gdbBps.some((b) => b.va === va && b.hw === hw)) st.gdbBps.push({ va, hw });
                        logLine(r.ok ? `GDB ${hw ? 'HW' : 'SW'} BP set at ${va}` : 'GDB BP failed');
                        renderMain(false);
                    });
                },
                onGdbDelBp: async (idx) => {
                    const bp = st.gdbBps[idx];
                    if (!bp) return;
                    await window.xdis.call({ op: 'gdb_bp', va: bp.va, hw: bp.hw, del: 1 });
                    st.gdbBps.splice(idx, 1);
                    renderMain(false);
                },
                onGdbDisconnect: async () => {
                    st.gdbSt = await window.xdis.call({ op: 'gdb_disconnect' });
                    st.gdbPrev = null;
                    st.gdbBps = [];
                    renderMain(false);
                },
                onDmpOpen: async () => {
                    const p = await window.xdis.pickFile({
                        title: 'Open Windows Crash Dump (.dmp)',
                        filters: [{ name: 'Minidump', extensions: ['dmp', 'mdmp'] }, { name: 'All files', extensions: ['*'] }]
                    });
                    if (!p) return;
                    st.dmpSt = await window.xdis.call({ op: 'dmp_open', path: p });
                    st.dmpSelTid = null;
                    logLine(st.dmpSt.loaded ? `loaded minidump ${p} (${st.dmpSt.exc_code} @ ${st.dmpSt.exc_addr})` : `minidump failed: ${st.dmpSt.err || ''}`);
                    renderMain(false);
                },
                onDmpSelectThread: (tid) => { st.dmpSelTid = tid; renderMain(false); }
            });
        } else if (st.mode === 'deobf') {
            const sub = st.deobfSub || 'junk';
            const bundle = { mbaExpr: st.mbaExpr, mbaEval: st.mbaEval };
            if (sub === 'junk') {
                $('left-title').textContent = 'Protection Lab · Junk & Stack Strings';
                bundle.deobf = await window.xdis.call({ op: 'deobf', va: st.curVa });
                $('left-meta').textContent = bundle.deobf.ok
                    ? `${bundle.deobf.junk} junk / ${bundle.deobf.opaque} opaque / ${bundle.deobf.strs.length} stack strs` : '';
            } else if (sub === 'cff') {
                $('left-title').textContent = 'Protection Lab · CFF Unflattening';
                bundle.cff = await window.xdis.call({ op: 'cff', va: st.curVa });
                $('left-meta').textContent = bundle.cff.ok
                    ? (bundle.cff.detected ? `Flattened · ${bundle.cff.edges.length} edges · ${bundle.cff.cut} cut` : 'Not flattened') : '';
            } else if (sub === 'mba') {
                $('left-title').textContent = 'Protection Lab · MBA Simplifier';
                const calls = [window.xdis.call({ op: 'mba_scan', va: st.curVa })];
                if (!st.mbaEval && st.mbaExpr) calls.push(window.xdis.call({ op: 'mba_eval', expr: st.mbaExpr }));
                const [scanRes, evalRes] = await Promise.all(calls);
                bundle.mbaScan = scanRes;
                if (evalRes) { st.mbaEval = evalRes; bundle.mbaEval = evalRes; }
                $('left-meta').textContent = scanRes.ok ? `${scanRes.hits.length} MBA hits` : '';
            } else if (sub === 'vm') {
                $('left-title').textContent = 'Protection Lab · VM Lifter';
                bundle.vm = await window.xdis.call({ op: 'vm', va: st.curVa });
                $('left-meta').textContent = bundle.vm.ok
                    ? (bundle.vm.detected ? `${bundle.vm.style || 'VM'} · ${bundle.vm.handlers.length} handlers · ${bundle.vm.trace.length} trace` : 'Not virtualized') : '';
            } else {
                $('left-title').textContent = 'Protection Lab · Hashes & Strings';
                [bundle.hashes, bundle.strs] = await Promise.all([
                    window.xdis.call({ op: 'unp_hashes', apply: 0 }),
                    window.xdis.call({ op: 'unp_strs', va: st.curVa, apply: 0 })
                ]);
                const nh = bundle.hashes.ok ? bundle.hashes.hits.length : 0;
                const ns = bundle.strs.ok ? bundle.strs.hits.length : 0;
                $('left-meta').textContent = `${nh} hashes · ${ns} strings`;
            }

            window.proView.renderDeobfLab(leftBody, sub, bundle, st.curVa, {
                onSub: (next) => { st.deobfSub = next; renderMain(false); },
                onSelect: (va) => { st.curVa = va; refreshInspector(); updateStatus(); },
                onJump: (va) => { st.mode = 'split'; gotoVa(va, true); },
                onTrace: (va) => { st.mode = 'trace'; gotoVa(va, true); },
                onMbaDraft: (expr) => { st.mbaExpr = expr; },
                onMbaEval: async (expr) => {
                    st.mbaExpr = expr;
                    const r = await window.xdis.call({ op: 'mba_eval', expr });
                    st.mbaEval = r;
                    return r;
                },
                onApplyHashes: async () => {
                    const r = await window.xdis.call({ op: 'unp_hashes', apply: 1 });
                    const n = r.ok && r.hits ? r.hits.length : 0;
                    logLine(r.ok ? `annotated ${n} resolved API hashes` : 'failed to annotate API hashes');
                    await refreshAfterMutation();
                },
                onApplyStrs: async () => {
                    const r = await window.xdis.call({ op: 'unp_strs', va: st.curVa, apply: 1 });
                    const n = r.ok && r.hits ? r.hits.length : 0;
                    logLine(r.ok ? `annotated ${n} decrypted strings` : 'failed to annotate strings');
                    await refreshAfterMutation();
                }
            });
        } else if (st.mode === 'trace') {
            const sub = st.traceSub || 'emu';
            let emu = null;
            if (sub === 'emu') {
                $('left-title').textContent = 'Trace Lab · Micro-Emulator';
                emu = await window.xdis.call({ op: 'emu', va: st.curVa, n: st.emuSteps });
                $('left-meta').textContent = emu.ok ? `${emu.steps.length} steps (${emu.stop})` : '';
            } else if (sub === 'taint') {
                $('left-title').textContent = 'Trace Lab · Taint & API Shims';
                $('left-meta').textContent = st.taintRes && st.taintRes.ok
                    ? `${st.taintRes.nstep} steps · ${(st.taintRes.tainted_regs || []).length} regs · ${(st.taintRes.events || []).length} events`
                    : `${st.taintCfg.reg} · ${st.taintCfg.steps} steps`;
            } else {
                $('left-title').textContent = 'Trace Lab · Symbolic Path Solver';
                $('left-meta').textContent = st.symSt.res && st.symSt.res.ok
                    ? (st.symSt.res.reachable ? `Reachable · ${(st.symSt.res.constraints || []).length} constraints` : 'Unreachable')
                    : '';
            }
            window.proView.renderTraceLab(leftBody, sub, {
                emu,
                emuSteps: st.emuSteps,
                taintCfg: st.taintCfg,
                taintRes: st.taintRes,
                symSt: st.symSt
            }, st.curVa, {
                onSub: (next) => { st.traceSub = next; renderMain(false); },
                onEmuRerun: (n) => { st.emuSteps = n; renderMain(false); },
                onSelect: (va) => { st.curVa = va; refreshInspector(); updateStatus(); },
                onJump: (va) => { st.mode = 'split'; gotoVa(va, true); },
                onTaintCfg: (cfg) => { st.taintCfg = cfg; },
                onRunTaint: async (cfg) => {
                    st.taintCfg = cfg;
                    st.taintRes = await window.xdis.call({
                        op: 'taint',
                        va: st.curVa,
                        reg: cfg.reg,
                        buf_len: cfg.bufLen,
                        n: cfg.steps
                    });
                    renderMain(false);
                },
                onSymDraft: (from, to) => { st.symSt.from = from; st.symSt.to = to; },
                onSymSolve: async (fromQ, toQ) => {
                    const fva = await resolveVaStr(fromQ || st.curVa);
                    const tva = await resolveVaStr(toQ);
                    const res = (fva && tva)
                        ? await window.xdis.call({ op: 'sym_solve', from: fva, to: tva })
                        : { ok: false, err: 'Could not resolve From VA or To VA' };
                    st.symSt = { from: fromQ || st.curVa, to: toQ, res };
                    renderMain(false);
                }
            });
        } else if (st.mode === 'dis' || st.mode === 'split' || st.mode === 'dhex') {
            await renderDisPane(leftBody);
        } else if (st.mode === 'graph' || st.mode === 'gdec') {
            $('left-title').textContent = 'Control Flow Graph';
            const res = await window.xdis.call({ op: 'cfg', va: st.curVa });
            st.cfgData = res;
            $('left-meta').textContent = res.ok ? `${res.name || res.func_va} (${res.blks.length} blocks)` : '';
            window.cfgView.render(leftBody, res, st.curVa, {
                onSelect: (va) => { st.curVa = va; st.selVar = null; renderMain(false); },
                onJump: (va) => gotoVa(va, true),
                onPeek: (va, e) => schedulePeek(va, e),
                onHidePeek: hidePeek
            });
        } else if (st.mode === 'calls') {
            $('left-title').textContent = st.callsSub === 'xgraph' ? 'Xrefs Graph (2-hop)' : st.callsSub === 'path' ? 'Call Pathfinder' : 'Call Graph';
            const [cg, xg] = await Promise.all([
                st.callsSub === 'calls' ? window.xdis.call({ op: 'callgraph', va: st.curVa }) : Promise.resolve(null),
                st.callsSub === 'xgraph' ? window.xdis.call({ op: 'xgraph', va: st.curVa, depth: 2 }) : Promise.resolve(null)
            ]);
            $('left-meta').textContent = cg && cg.ok ? `${cg.callers.length} in / ${cg.callees.length} out`
                : (xg && xg.ok ? `${xg.nodes.length} nodes / ${xg.edges.length} edges` : '');
            window.proView.renderCallsHub(leftBody, st.callsSub, cg, xg, st.pathSt, st.curVa, {
                onSub: (s) => { st.callsSub = s; renderMain(false); },
                onPath: async (fromQ, toQ) => {
                    async function resVa(q) {
                        if (/^0x[0-9a-f]+$/i.test(q)) return q;
                        const r = await window.xdis.call({ op: 'resolve', q });
                        return r.ok ? r.va : null;
                    }
                    const fva = await resVa(fromQ || st.curVa);
                    const tva = await resVa(toQ);
                    const res = (fva && tva)
                        ? await window.xdis.call({ op: 'pathfind', from: fva, to: tva })
                        : { ok: false, err: 'Could not resolve source or target symbol/VA' };
                    st.pathSt = { from: fromQ, to: toQ, res };
                    renderMain(false);
                },
                onJump: (va) => gotoVa(va, true),
                onPeek: (va, e) => schedulePeek(va, e),
                onHidePeek: hidePeek
            });
        } else if (st.mode === 'dec') {
            await refreshDecompiler(leftBody, forceDec);
        } else if (st.mode === 'hex') {
            await renderHexPane(leftBody, 'left');
        }

        if (st.mode === 'split' || st.mode === 'gdec') {
            await refreshDecompiler(rightBody, forceDec);
        } else if (st.mode === 'dhex') {
            await renderHexPane(rightBody, 'right');
        }

        await refreshInspector();
        updateStatus();
    }

    async function renderHexPane(el, side) {
        const titleEl = side === 'left' ? $('left-title') : $('right-title');
        const metaEl = side === 'left' ? $('left-meta') : $('right-meta');
        const vsEl = side === 'left' ? $('left-vscroll') : $('right-vscroll');
        titleEl.textContent = 'Hex + ASCII (dbl-click byte to patch)';
        metaEl.textContent = st.curVa;
        const rowsWant = Math.max(28, Math.ceil((el.clientHeight || 600) / 21) + 4);
        const res = await window.xdis.call({ op: 'hex', va: st.topVa, n: rowsWant });
        window.vw.renderHex(el, res, st.curVa, {
            onSelect: (va) => { st.curVa = va; renderMain(false); },
            onPatch: (va) => {
                st.curVa = va;
                openPrompt('Patch byte (hex, COW)', '', async (v) => {
                    const bv = parseInt(v, 16);
                    if (Number.isNaN(bv)) return;
                    const r = await window.xdis.call({ op: 'patch', va, val: bv & 0xFF });
                    logLine(r.ok ? `patched ${va} -> 0x${(bv & 0xFF).toString(16)}` : 'patch failed');
                    await refreshAfterMutation();
                });
            }
        });
        window.vw.updateVScroll(vsEl, el, st.info, st.topVa, rowsWant * 16, true, true);
    }

    async function gotoVa(va, push) {
        if (!st.info || !va) return;
        if (push && st.curVa && st.curVa !== va) {
            st.hist = st.hist.slice(0, st.histPos);
            st.hist.push(st.curVa);
            st.histPos = st.hist.length;
        }
        st.curVa = va;
        st.topVa = va;
        st.selVar = null;
        await renderMain(true);
    }

    async function loadList(reset) {
        if (!st.info) return;
        const el = $('side-list');
        if (st.tab === 'patches') {
            const r = await window.xdis.call({ op: 'patches' });
            const items = (r.ok && r.items) ? r.items : [];
            $('list-count').textContent = String(items.length);
            if (!items.length) {
                el.innerHTML = '<div class="ins-empty" style="padding:10px">No active COW byte patches.</div>';
                return;
            }
            el.innerHTML = `<div style="padding:4px 8px;display:flex;gap:6px"><button class="tb-btn" id="pt-exp" style="flex:1">Export patched</button><button class="tb-btn" id="pt-rev">Revert all</button></div>`
                + items.map((p) =>
                    `<div class="side-item" data-va="${p.va}">`
                    + `<span class="s-nm">${p.va.slice(2)}: ${p.orig.toString(16).padStart(2,'0')} → ${p.val.toString(16).padStart(2,'0')}</span>`
                    + `<button class="mini-btn" data-unp="${p.va}">Undo</button></div>`
                ).join('');
            el.querySelector('#pt-exp').onclick = exportPatchedBin;
            el.querySelector('#pt-rev').onclick = async () => {
                await window.xdis.call({ op: 'unpatch', va: '0x0' });
                logLine('reverted all patches');
                await refreshAfterMutation();
            };
            el.querySelectorAll('[data-unp]').forEach((b) => {
                b.onclick = async (e) => {
                    e.stopPropagation();
                    await window.xdis.call({ op: 'unpatch', va: b.dataset.unp });
                    await refreshAfterMutation();
                };
            });
            el.querySelectorAll('.side-item').forEach((row) => {
                row.onclick = () => gotoVa(row.dataset.va, true);
            });
            return;
        }

        if (reset) { st.listOff = 0; st.listItems = []; }
        const q = $('filter-input').value.trim();
        const r = await window.xdis.call({ op: 'list', tab: st.tab, q, off: st.listOff, lim: 150 });
        if (!r.ok) return;
        st.listTotal = r.total;
        st.listItems = reset ? r.items : st.listItems.concat(r.items);
        st.listOff = st.listItems.length;
        $('list-count').textContent = String(r.total);

        el.innerHTML = st.listItems.map((it) => {
            const cls = st.tab === 'strs' ? ' is-str' : (st.tab === 'syms' && it.kind === 1 ? ' is-imp' : '');
            const act = it.va.toLowerCase() === st.curVa.toLowerCase() ? ' active' : '';
            return `<div class="side-item${cls}${act}" data-va="${it.va}">`
                + `<span class="s-nm">${window.vw.esc(it.name)}</span>`
                + `<span class="s-va">${it.va.slice(2)}</span></div>`;
        }).join('');

        el.querySelectorAll('.side-item').forEach((row) => {
            row.addEventListener('click', () => {
                if (st.mode === 'overview') st.mode = 'split';
                gotoVa(row.dataset.va, true);
            });
            row.addEventListener('mouseenter', (e) => schedulePeek(row.dataset.va, e));
            row.addEventListener('mouseleave', hidePeek);
        });
    }

    async function exportCurrentC() {
        if (!st.info) return;
        const d = await window.xdis.call({ op: 'dec', va: st.curVa });
        if (!d.ok) return logLine('nothing decompiled to export');
        const p = await window.xdis.saveFile({ title: 'Export C pseudocode', defaultName: (d.name || 'func') + '.c', filters: [{ name: 'C source', extensions: ['c'] }] });
        if (!p) return;
        const r = await window.xdis.writeText(p, d.lines.map((l) => l.text).join('\n') + '\n');
        logLine(r.ok ? 'exported C -> ' + p : 'export failed');
    }

    async function exportCurrentAsm() {
        if (!st.info) return;
        const d = await window.xdis.call({ op: 'dis', va: st.topVa, n: 200 });
        if (!d.ok) return;
        const p = await window.xdis.saveFile({ title: 'Export disassembly', defaultName: 'disasm.asm', filters: [{ name: 'Assembly', extensions: ['asm', 'txt'] }] });
        if (!p) return;
        const lines = d.rows.map((r) => `${r.sym ? '\n' + r.sym + ':\n' : ''}  ${window.vw.padVa(r.va)}  ${r.mnem.padEnd(10)} ${r.ops}${r.cmt ? ' ; ' + r.cmt : ''}`);
        const r = await window.xdis.writeText(p, lines.join('\n') + '\n');
        logLine(r.ok ? 'exported ASM -> ' + p : 'export failed');
    }

    async function exportPatchedBin() {
        if (!st.info) return;
        const base = st.info.path.split(/[\\/]/).pop();
        const p = await window.xdis.saveFile({ title: 'Export patched binary', defaultName: 'patched_' + base });
        if (!p) return;
        const r = await window.xdis.call({ op: 'export_bin', path: p });
        logLine(r.ok ? 'exported patched binary -> ' + p : 'export failed');
    }

    async function loadPdbDialog() {
        if (!st.info) return;
        const p = await window.xdis.pickFile({ title: 'Load PDB or MAP symbols', filters: [{ name: 'Symbols', extensions: ['pdb', 'map'] }, { name: 'All files', extensions: ['*'] }] });
        if (!p) return;
        const r = await window.xdis.call({ op: 'pdb_load', path: p });
        logLine(r.ok ? `loaded ${r.added} symbols from ${p}` : 'symbol load failed');
        await refreshAfterMutation();
    }

    async function saveSigDialog() {
        if (!st.info) return;
        const base = st.info.path.split(/[\\/]/).pop();
        const p = await window.xdis.saveFile({ title: 'Save .xsig function signatures', defaultName: base + '.xsig', filters: [{ name: 'xdis Signatures', extensions: ['xsig'] }] });
        if (!p) return;
        const r = await window.xdis.call({ op: 'sig_save', path: p });
        logLine(r.ok ? 'saved .xsig signatures -> ' + p : 'sig save failed');
    }

    async function applySigDialog() {
        if (!st.info) return;
        const p = await window.xdis.pickFile({ title: 'Apply .xsig function signatures', filters: [{ name: 'xdis Signatures', extensions: ['xsig'] }, { name: 'All files', extensions: ['*'] }] });
        if (!p) return;
        const r = await window.xdis.call({ op: 'sig_apply', path: p });
        logLine(r.ok ? `matched ${r.matched} functions from ${p}` : 'sig apply failed');
        await refreshAfterMutation();
    }

    async function exportReportDialog(fmt) {
        if (!st.info) return;
        const base = st.info.path.split(/[\\/]/).pop();
        const ext = fmt === 'md' ? 'md' : 'html';
        const p = await window.xdis.saveFile({ title: `Export ${ext.toUpperCase()} report`, defaultName: `${base}_report.${ext}`, filters: [{ name: ext.toUpperCase(), extensions: [ext] }] });
        if (!p) return;
        const r = await window.xdis.exportReport(p, ext);
        logLine(r.ok ? `exported ${ext.toUpperCase()} report -> ${p}` : 'report export failed: ' + (r.err || ''));
    }

    async function openBinary(filePath) {
        if (!filePath) return;
        logLine('loading ' + filePath + '...');
        const r = await window.xdis.call({ op: 'open', path: filePath });
        if (!r.ok) { logLine('open failed: ' + (r.err || '')); return; }
        st.info = r;
        st.curVa = r.entry;
        st.topVa = r.entry;
        st.irSub = 'mlir';
        st.deobfSub = 'junk';
        st.traceSub = 'emu';
        st.taintRes = null;
        st.symSt = { from: '', to: '', res: null };
        st.mbaExpr = '(x ^ y) + 2 * (x & y)';
        st.mbaEval = null;
        st.lang = null;
        st.dotnet = null;
        st.structOverlay = null;
        st.diffSt = { otherPath: '', data: null, filter: 'all', sel: null, codeA: [], codeB: [], pdiff: null, view: 'diff' };
        st.auditSub = 'vuln';
        st.auditSt = {
            vuln: null,
            vulnLoaded: false,
            yaraRules: '',
            yaraDefaultsLoaded: false,
            yaraRes: null,
            carve: null,
            iocs: null,
            iocFilter: '',
            hilbertOrder: 6,
            hilbert: null,
            sugs: null,
            sugDraft: { va: r.entry, kind: 'rename', val: '', reason: '', conf: '85' }
        };
        st.lastCollabVa = '';
        st.undoN = r.undo_n || 0;
        st.redoN = r.redo_n || 0;
        st.hist = [];
        st.histPos = 0;
        st.selVar = null;
        st.tabs = [{ va: r.entry, topVa: r.entry, mode: st.mode, label: '_start' }];
        st.activeTab = 0;
        window.cfgView.reset();
        window.vw.clearNumFormats();

        const base = filePath.split(/[\\/]/).pop();
        $('file-label').textContent = `${base} (${r.fmt} ${r.arch})`;
        renderStatusStats();
        updateActionButtons();
        logLine(`opened ${base}: ${r.fmt} ${r.arch} ${(r.size / 1048576).toFixed(2)} MB in ${r.ana_ms.toFixed(1)} ms`);

        [st.entMap, st.triage, st.crypto, st.vtables, st.lang, st.dotnet] = await Promise.all([
            window.xdis.call({ op: 'entropy_map' }),
            window.xdis.call({ op: 'triage' }),
            window.xdis.call({ op: 'crypto' }),
            window.xdis.call({ op: 'vtables' }),
            window.xdis.call({ op: 'lang' }),
            r.has_clr ? window.xdis.call({ op: 'dotnet' }) : Promise.resolve(null)
        ]);
        st.mode = 'split';
        st.tabs = [{ va: r.entry, topVa: r.entry, mode: 'split', label: '_start' }];
        renderTabs();
        await loadList(true);
        await renderMain(true);
    }

    async function openDialog() {
        const p = await window.xdis.pickFile();
        if (p) openBinary(p);
    }

    function closeModal() {
        $('modal-bg').classList.add('hidden');
        $('modal-body').innerHTML = '';
    }

    function openPrompt(title, prefill, onOk) {
        $('modal-title').textContent = title;
        $('modal-body').innerHTML = `<input id="m-in" class="modal-input" value="${window.vw.esc(prefill || '')}" spellcheck="false">`;
        $('modal-bg').classList.remove('hidden');
        const inp = $('m-in');
        inp.focus();
        inp.select();
        inp.onkeydown = (e) => {
            if (e.key === 'Enter') { const v = inp.value.trim(); closeModal(); onOk(v); }
            else if (e.key === 'Escape') closeModal();
        };
    }

    async function openXrefs() {
        if (!st.info) return;
        const r = await window.xdis.call({ op: 'xrefs', va: st.curVa });
        if (!r.ok) return;
        $('modal-title').textContent = `Xrefs to ${st.curVa} (${r.total})`;
        $('modal-body').innerHTML = `<div class="modal-split"><div class="modal-list" id="xr-list"></div><div class="modal-preview" id="xr-prev">Hover or select an xref to preview.</div></div>`;
        $('modal-bg').classList.remove('hidden');

        const list = $('xr-list');
        const prev = $('xr-prev');
        if (!r.items.length) { list.innerHTML = '<div class="m-item">No cross-references found.</div>'; return; }
        const tags = ['', 'CALL', 'JMP', 'DATA'];
        list.innerHTML = r.items.map((x, i) =>
            `<div class="m-item${i === 0 ? ' sel' : ''}" data-va="${x.from}"><span>${tags[x.type] || 'REF'} ${x.from}</span><span style="color:var(--tok-sym)">${window.vw.esc(x.fn || '-')}</span></div>`
        ).join('');

        async function previewVa(va) {
            const p = await window.xdis.call({ op: 'peek', va });
            prev.innerHTML = p.ok ? window.vw.renderPeekHtml(p) : '';
        }
        previewVa(r.items[0].from);

        list.querySelectorAll('.m-item').forEach((el) => {
            el.onmouseenter = () => previewVa(el.dataset.va);
            el.onclick = () => { closeModal(); gotoVa(el.dataset.va, true); };
        });
    }

    function openSearch() {
        if (!st.info) return;
        const simd = st.info.avx2 ? 'AVX2' : 'SSE2';
        $('modal-title').textContent = `${simd} Search (hex pattern "48 89 ?? 24" or ASCII text)`;
        $('modal-body').innerHTML = `
          <input id="sr-in" class="modal-input" placeholder="48 89 5C 24 ?? or string..." spellcheck="false">
          <div class="modal-split">
            <div class="modal-list" id="sr-list"></div>
            <div class="modal-preview" id="sr-prev">Press Enter to search across full binary.</div>
          </div>`;
        $('modal-bg').classList.remove('hidden');
        const inp = $('sr-in'), list = $('sr-list'), prev = $('sr-prev');
        inp.focus();

        inp.onkeydown = async (e) => {
            if (e.key === 'Escape') return closeModal();
            if (e.key !== 'Enter') return;
            const q = inp.value.trim();
            if (!q) return;
            const r = await window.xdis.call({ op: 'find', q });
            if (!r.ok || !r.hits.length) {
                list.innerHTML = '<div class="m-item">No matches found.</div>';
                return;
            }
            list.innerHTML = r.hits.map((h) =>
                `<div class="m-item" data-va="${h.va}"><span>${h.va !== '0x0' ? h.va : 'off 0x' + h.off.toString(16)}</span><span style="color:var(--tok-sym)">${window.vw.esc(h.fn || '')}</span></div>`
            ).join('');
            list.querySelectorAll('.m-item').forEach((el) => {
                el.onmouseenter = async () => {
                    if (el.dataset.va === '0x0') return;
                    const p = await window.xdis.call({ op: 'peek', va: el.dataset.va });
                    if (p.ok) prev.innerHTML = window.vw.renderPeekHtml(p);
                };
                el.onclick = () => { if (el.dataset.va !== '0x0') { closeModal(); gotoVa(el.dataset.va, true); } };
            });
        };
    }

    function openQuickJump() {
        if (!st.info) return;
        $('modal-title').textContent = 'Quick Jump (function, symbol, string, or hex VA)';
        $('modal-body').innerHTML = `
          <input id="qj-in" class="modal-input" placeholder="Type function name, API, string, or 0x..." spellcheck="false">
          <div class="modal-split">
            <div class="modal-list" id="qj-list"></div>
            <div class="modal-preview" id="qj-prev">Type to filter across functions &amp; strings.</div>
          </div>`;
        $('modal-bg').classList.remove('hidden');
        const inp = $('qj-in'), list = $('qj-list'), prev = $('qj-prev');
        inp.focus();

        async function refresh() {
            const q = inp.value.trim();
            const [fn, stR] = await Promise.all([
                window.xdis.call({ op: 'list', tab: 'funcs', q, off: 0, lim: 40 }),
                q.length >= 2 ? window.xdis.call({ op: 'list', tab: 'strs', q, off: 0, lim: 25 }) : Promise.resolve({ items: [] })
            ]);
            const rows = [
                ...(fn.items || []).map((x) => ({ va: x.va, tag: 'FN ', name: x.name })),
                ...(stR.items || []).map((x) => ({ va: x.va, tag: 'STR', name: '"' + x.name + '"' }))
            ];
            list.innerHTML = rows.map((r) =>
                `<div class="m-item" data-va="${r.va}"><span><b style="color:var(--accent)">${r.tag}</b> ${window.vw.esc(r.name)}</span><span style="color:var(--fg-muted)">${r.va.slice(2)}</span></div>`
            ).join('') || '<div class="m-item">No matches (press Enter to jump to hex VA).</div>';
            list.querySelectorAll('.m-item[data-va]').forEach((el) => {
                el.onmouseenter = async () => {
                    const p = await window.xdis.call({ op: 'peek', va: el.dataset.va });
                    if (p.ok) prev.innerHTML = window.vw.renderPeekHtml(p);
                };
                el.onclick = () => { closeModal(); if (st.mode === 'overview') st.mode = 'split'; gotoVa(el.dataset.va, true); };
            });
        }
        refresh();
        inp.oninput = refresh;
        inp.onkeydown = (e) => {
            if (e.key === 'Escape') closeModal();
            else if (e.key === 'Enter') {
                const first = list.querySelector('.m-item[data-va]');
                const q = inp.value.trim();
                closeModal();
                if (st.mode === 'overview') st.mode = 'split';
                if (/^0x[0-9a-f]+$/i.test(q)) gotoVa(q, true);
                else if (first) gotoVa(first.dataset.va, true);
                else resolveAndJump(q);
            }
        };
    }

    function openScripts() {
        window.studio.openScriptModal($('modal-title'), $('modal-body'), $('modal-bg'), st.curVa, {
            onMutated: refreshAfterMutation,
            onJump: (va) => { closeModal(); gotoVa(va, true); }
        });
    }

    async function runCommand(raw) {
        const parts = raw.trim().replace(/^:/, '').split(/\s+/);
        const cmd = (parts[0] || '').toLowerCase();
        const rest = raw.trim().replace(/^:?\S+\s*/, '');
        if (!cmd) return;

        if (cmd === 'goto' || cmd === 'g') return resolveAndJump(rest);
        if (cmd === 'undo') return doUndo();
        if (cmd === 'redo') return doRedo();
        if (cmd === 'rename' || cmd === 'n') {
            if (!rest) return;
            await window.xdis.call({ op: 'rename', va: st.curVa, name: rest });
            if (st.collabSt.active) {
                window.xdisPro.broadcastCollab({ type: 'rename', va: st.curVa, name: rest });
                pushCollabLog({ kind: 'act', from: st.collabSt.nick, text: `renamed -> ${rest}`, va: st.curVa });
            }
            await refreshAfterMutation();
            return logLine(`renamed ${st.curVa} -> ${rest}`);
        }
        if (cmd === 'cmt') {
            await window.xdis.call({ op: 'cmt', va: st.curVa, text: rest });
            if (st.collabSt.active) {
                window.xdisPro.broadcastCollab({ type: 'cmt', va: st.curVa, text: rest });
                pushCollabLog({ kind: 'act', from: st.collabSt.nick, text: `comment: ${rest}`, va: st.curVa });
            }
            await refreshInfoStats();
            return renderMain(false);
        }
        if (cmd === 'mark' || cmd === 'bm') {
            await window.xdis.call({ op: 'mark', va: st.curVa, label: rest || 'mark' });
            await refreshInfoStats();
            if (st.tab === 'marks') await loadList(true);
            return logLine('bookmark added at ' + st.curVa);
        }
        if (cmd === 'theme') {
            const keys = Object.keys(window.studio.THEMES);
            const p = prefs();
            p.theme = window.studio.THEMES[rest] ? rest : keys[(keys.indexOf(p.theme) + 1) % keys.length];
            p.colors = {};
            window.studio.applyPrefs();
            window.studio.persist();
            updateStatus();
            if (st.mode === 'audit' && st.auditSub === 'hilbert') renderMain(false);
            return;
        }
        if (cmd === 'save') {
            if (!st.info) return logLine('no binary loaded');
            const r = await window.xdis.call({ op: 'save' });
            return logLine(r.ok ? 'saved .xdb database' : 'save failed');
        }
        if (cmd === 'patch') {
            const r = await window.xdis.call({ op: 'patch_bytes', va: st.curVa, hex: rest });
            logLine(r.ok ? `patched ${r.n} bytes (COW)` : 'patch failed');
            return refreshAfterMutation();
        }
        const r = await window.xdis.call({ op: 'cmd', name: cmd, args: rest });
        if (r.ok) {
            $('console-drawer').classList.remove('hidden');
            logLine(r.out || `${cmd}: ok`);
        } else {
            logLine(`unknown command: ${cmd}`);
        }
    }

    function openCustomizer() {
        const dr = $('prefs-drawer');
        dr.classList.toggle('hidden');
        if (dr.classList.contains('hidden')) return;
        window.studio.renderCustomizer($('prefs-body'), async (ev) => {
            if (ev === 'upper') await window.xdis.call({ op: 'opt', upper: prefs().upper ? 1 : 0 });
            if (ev === 'peek' && !prefs().peekEnabled) hidePeek();
            if (ev === 'tool:entropy') { dr.classList.add('hidden'); return runCommand('entropy'); }
            if (ev === 'tool:script') { dr.classList.add('hidden'); return openScripts(); }
            if (ev === 'tool:pdb') { dr.classList.add('hidden'); return loadPdbDialog(); }
            if (ev === 'tool:sig_save') { dr.classList.add('hidden'); return saveSigDialog(); }
            if (ev === 'tool:sig_apply') { dr.classList.add('hidden'); return applySigDialog(); }
            if (ev === 'tool:rep_html') { dr.classList.add('hidden'); return exportReportDialog('html'); }
            if (ev === 'tool:rep_md') { dr.classList.add('hidden'); return exportReportDialog('md'); }
            if (ev === 'tool:save') return runCommand('save');
            if (ev === 'tool:export_c') return exportCurrentC();
            if (ev === 'tool:export_asm') return exportCurrentAsm();
            if (ev === 'tool:export_bin') return exportPatchedBin();
            updateStatus();
            renderMain(false);
        });
    }

    function matchBind(e, act) {
        const k = (prefs().keys[act] || window.studio.DEFAULT_KEYS[act] || '').toLowerCase();
        const ek = (e.key === ' ' ? 'space' : e.key).toLowerCase();
        return k && ek === k;
    }

    function wireSplitters() {
        function bind(el, onDrag) {
            el.onmousedown = (e) => {
                e.preventDefault();
                const move = (ev) => onDrag(ev);
                const up = () => { window.removeEventListener('mousemove', move); window.removeEventListener('mouseup', up); };
                window.addEventListener('mousemove', move);
                window.addEventListener('mouseup', up);
            };
        }
        bind($('split-side'), (e) => {
            $('sidebar').style.width = Math.min(500, Math.max(170, e.clientX)) + 'px';
        });
        bind($('split-mid'), (e) => {
            const lp = $('pane-left').getBoundingClientRect();
            const rp = $('pane-right').getBoundingClientRect();
            const tot = (rp.right - lp.left) || 1;
            const frac = Math.min(0.8, Math.max(0.2, (e.clientX - lp.left) / tot));
            $('pane-left').style.flex = String(frac);
            $('pane-right').style.flex = String(1 - frac);
        });
        bind($('split-ins'), (e) => {
            const w = Math.min(360, Math.max(190, window.innerWidth - e.clientX));
            $('inspector').style.width = w + 'px';
        });
    }

    function closeMenus() {
        document.querySelectorAll('.menu-pop').forEach((p) => p.classList.add('hidden'));
        document.querySelectorAll('.menu-trigger').forEach((t) => {
            t.classList.remove('open');
            t.setAttribute('aria-expanded', 'false');
        });
    }

    function openCommandPalette() {
        closeMenus();
        const cmds = [
            { ic: 'split', cat: 'View', name: 'IDA View + Pseudocode (Split)', key: 'F5', run: () => { st.mode = 'split'; renderMain(true); } },
            { ic: 'graph', cat: 'View', name: 'Control Flow Graph', key: 'Space', run: () => { st.mode = 'graph'; renderMain(true); } },
            { ic: 'gdec', cat: 'View', name: 'Graph + Pseudocode', key: '', run: () => { st.mode = 'gdec'; renderMain(true); } },
            { ic: 'hex', cat: 'View', name: 'Hex View & Patcher', key: 'H', run: () => { st.mode = 'hex'; renderMain(true); } },
            { ic: 'overview', cat: 'View', name: 'Binary Overview & Triage', key: 'O', run: () => { st.mode = 'overview'; renderMain(false); } },
            { ic: 'calls', cat: 'View', name: 'Call Graph, Xrefs & Pathfinder', key: 'C', run: () => { st.mode = 'calls'; renderMain(true); } },
            { ic: 'ir', cat: 'Analysis', name: 'SSA IR, Auto-Structs & C++ Classes', key: 'U', run: () => { st.mode = 'ir'; renderMain(false); } },
            { ic: 'types', cat: 'Analysis', name: 'Local Types, PDB/DWARF & Live Struct Overlay', key: 'K', run: () => { st.mode = 'types'; renderMain(false); } },
            { ic: 'deobf', cat: 'Analysis', name: 'Deobfuscation Lab (CFF, MBA, VM, Hashes)', key: 'D', run: () => { st.mode = 'deobf'; renderMain(false); } },
            { ic: 'trace', cat: 'Analysis', name: 'Micro-Emulator, Taint & Path Solver', key: 'E', run: () => { st.mode = 'trace'; renderMain(false); } },
            { ic: 'diff', cat: 'Analysis', name: 'Binary Diff & Security Patch Triage', key: 'B', run: () => { st.mode = 'diff'; renderMain(false); } },
            { ic: 'audit', cat: 'Audit', name: 'Vulnerability Slicer', key: 'A', run: () => { st.mode = 'audit'; st.auditSub = 'vuln'; renderMain(false); } },
            { ic: 'audit', cat: 'Audit', name: 'YARA Scanner', key: '', run: () => { st.mode = 'audit'; st.auditSub = 'yara'; renderMain(false); } },
            { ic: 'audit', cat: 'Audit', name: 'File Carver & IOC Extractor', key: '', run: () => { st.mode = 'audit'; st.auditSub = 'carve'; renderMain(false); } },
            { ic: 'audit', cat: 'Audit', name: '2D Hilbert Entropy Map', key: '', run: () => { st.mode = 'audit'; st.auditSub = 'hilbert'; renderMain(false); } },
            { ic: 'live', cat: 'Audit', name: 'AI Suggestion Queue & xdis Live Collab', key: '', run: () => { st.mode = 'audit'; st.auditSub = 'queue'; renderMain(false); } },
            { ic: 'debug', cat: 'Debug', name: 'Debugger (Win32 / TTD / GDB / Minidump)', key: 'F9', run: () => { st.mode = 'debug'; renderMain(false); } },
            { ic: 'goto', cat: 'Nav', name: 'Go to Address or Symbol…', key: 'G', run: () => openPrompt('Go to address or symbol', '', resolveAndJump) },
            { ic: 'search', cat: 'Nav', name: 'Search Bytes / Text…', key: 'Ctrl+F', run: openSearch },
            { ic: 'xrefs', cat: 'Nav', name: 'Cross-References (Xrefs)', key: 'X', run: openXrefs },
            { ic: 'script', cat: 'Tools', name: 'Script Studio (Python / JS)', key: 'Ctrl+J', run: openScripts },
            { ic: 'open', cat: 'File', name: 'Open Binary…', key: 'Ctrl+O', run: openDialog },
            { ic: 'snap', cat: 'File', name: 'Project Snapshots (.xdb v3)…', key: '', run: openSnapshots },
            { ic: 'pdb', cat: 'File', name: 'Load PDB / MAP Symbols…', key: '', run: loadPdbDialog },
            { ic: 'export', cat: 'File', name: 'Export Pseudocode (.c)…', key: '', run: exportCurrentC },
            { ic: 'undo', cat: 'Edit', name: 'Undo', key: 'Ctrl+Z', run: doUndo },
            { ic: 'redo', cat: 'Edit', name: 'Redo', key: 'Ctrl+Y', run: doRedo },
            { ic: 'palette', cat: 'Theme', name: 'Switch Theme: IDA Dark', key: '', run: () => runCommand('theme ida') },
            { ic: 'palette', cat: 'Theme', name: 'Switch Theme: IDA Classic (Light)', key: '', run: () => runCommand('theme idalight') },
            { ic: 'palette', cat: 'Theme', name: 'Theme & Preferences…', key: '', run: openCustomizer },
            { ic: 'inspector', cat: 'View', name: 'Toggle Inspector Panel', key: 'I', run: () => { prefs().showInspector = !prefs().showInspector; window.studio.persist(); refreshInspector(); updateStatus(); } },
            { ic: 'console', cat: 'View', name: 'Toggle Output Console', key: '`', run: () => $('console-drawer').classList.toggle('hidden') }
        ];

        $('modal-title').textContent = 'Command Palette';
        const body = $('modal-body');
        body.innerHTML = `<input id="cmd-in" class="modal-input" placeholder="Type a view, tool, or action…" spellcheck="false"><div id="cmd-list" class="cmd-list"></div>`;
        $('modal-bg').classList.remove('hidden');

        const inp = $('cmd-in');
        const listEl = $('cmd-list');
        let sel = 0;
        let filtered = cmds;

        function paint() {
            const q = inp.value.trim().toLowerCase();
            filtered = q ? cmds.filter((c) => (c.cat + ' ' + c.name + ' ' + c.key).toLowerCase().includes(q)) : cmds;
            if (sel >= filtered.length) sel = Math.max(0, filtered.length - 1);
            listEl.innerHTML = filtered.map((c, idx) =>
                `<button class="cmd-row${idx === sel ? ' sel' : ''}" data-ci="${idx}">`
                + `<span class="cmd-l">${window.xdisIcons ? window.xdisIcons.svg(c.ic || 'cmd', 'ic') : ''}<span class="cmd-cat">${window.vw.esc(c.cat)}</span>${window.vw.esc(c.name)}</span>`
                + `<kbd>${window.vw.esc(c.key)}</kbd></button>`
            ).join('') || '<div class="ins-empty" style="padding:10px">No matching commands.</div>';
            listEl.querySelectorAll('.cmd-row').forEach((btn) => {
                btn.addEventListener('click', () => {
                    const item = filtered[Number(btn.dataset.ci)];
                    closeModal();
                    if (item) item.run();
                });
            });
        }

        inp.addEventListener('input', () => { sel = 0; paint(); });
        inp.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowDown') { e.preventDefault(); sel = Math.min(filtered.length - 1, sel + 1); paint(); }
            else if (e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(0, sel - 1); paint(); }
            else if (e.key === 'Enter') {
                e.preventDefault();
                const item = filtered[sel];
                closeModal();
                if (item) item.run();
            } else if (e.key === 'Escape') {
                closeModal();
            }
        });
        paint();
        inp.focus();
    }

    function wireMenus() {
        const bar = $('menubar');
        if (!bar) return;
        let openMenu = null;

        function showMenu(name) {
            closeMenus();
            openMenu = name;
            if (!name) return;
            const trig = bar.querySelector(`.menu-trigger[data-menu="${name}"]`);
            const pop = bar.querySelector(`.menu-pop[data-pop="${name}"]`);
            if (trig && pop) {
                trig.classList.add('open');
                trig.setAttribute('aria-expanded', 'true');
                pop.classList.remove('hidden');
            }
        }

        bar.querySelectorAll('.menu-trigger').forEach((btn) => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                showMenu(openMenu === btn.dataset.menu ? null : btn.dataset.menu);
            });
            btn.addEventListener('mouseenter', () => {
                if (openMenu && openMenu !== btn.dataset.menu) showMenu(btn.dataset.menu);
            });
        });

        bar.querySelectorAll('.mi[data-mode]').forEach((item) => {
            item.addEventListener('click', () => {
                showMenu(null);
                st.mode = item.dataset.mode;
                renderMain(true);
            });
        });

        const acts = {
            open: openDialog,
            save: () => runCommand('save'),
            snaps: openSnapshots,
            pdb: loadPdbDialog,
            export_c: exportCurrentC,
            export_asm: exportCurrentAsm,
            export_bin: exportPatchedBin,
            undo: doUndo,
            redo: doRedo,
            back: () => { if (st.histPos > 0) gotoVa(st.hist[--st.histPos], false); },
            goto: () => openPrompt('Go to address or symbol', '', resolveAndJump),
            find: openSearch,
            xrefs: openXrefs,
            inspector: () => { prefs().showInspector = !prefs().showInspector; window.studio.persist(); refreshInspector(); updateStatus(); },
            console: () => $('console-drawer').classList.toggle('hidden'),
            explain: () => { prefs().explain = !prefs().explain; window.studio.persist(); renderMain(false); },
            navmode: () => { prefs().navMode = prefs().navMode === 'entropy' ? 'sections' : 'entropy'; window.studio.persist(); updateStatus(); },
            prefs: openCustomizer,
            trace_emu: () => { st.mode = 'trace'; st.traceSub = 'emu'; renderMain(false); },
            script: openScripts,
            cmd: openCommandPalette,
            guide: () => window.triView.openGuide($('modal-title'), $('modal-body'), $('modal-bg'))
        };

        bar.querySelectorAll('.mi[data-act]').forEach((item) => {
            item.addEventListener('click', () => {
                showMenu(null);
                const fn = acts[item.dataset.act];
                if (fn) fn();
            });
        });

        const ib = $('iconbar');
        if (ib) {
            ib.querySelectorAll('.ib-btn[data-ib-mode]').forEach((btn) => {
                btn.addEventListener('click', () => {
                    showMenu(null);
                    st.mode = btn.dataset.ibMode;
                    renderMain(true);
                });
            });
            ib.querySelectorAll('.ib-btn[data-ib-act]').forEach((btn) => {
                btn.addEventListener('click', () => {
                    showMenu(null);
                    const fn = acts[btn.dataset.ibAct];
                    if (fn) fn();
                });
            });
        }

        document.addEventListener('click', () => { if (openMenu) showMenu(null); });
        document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && openMenu) showMenu(null); });
    }

    function wireEvents() {
        wireMenus();
        const btnCmd = $('btn-cmd');
        if (btnCmd) btnCmd.addEventListener('click', openCommandPalette);
        const btnCopyC = $('btn-copy-c');
        if (btnCopyC) {
            btnCopyC.addEventListener('click', () => {
                if (!st.decData || !st.decData.lines) return;
                navigator.clipboard.writeText(st.decData.lines.map((l) => l.text).join('\n') + '\n');
                logLine('copied pseudocode to clipboard');
            });
        }
        const toolX = $('tool-tab-close');
        if (toolX) {
            toolX.addEventListener('click', (e) => {
                e.stopPropagation();
                st.mode = 'split';
                renderMain(true);
            });
        }
        const stTheme = $('st-theme');
        if (stTheme) stTheme.addEventListener('click', () => runCommand('theme'));
        $('prefs-close').onclick = () => $('prefs-drawer').classList.add('hidden');
        $('modal-close').onclick = closeModal;
        $('modal-bg').onclick = (e) => { if (e.target.id === 'modal-bg') closeModal(); };
        $('btn-console').onclick = () => $('console-drawer').classList.toggle('hidden');
        const stCollab = $('st-collab');
        if (stCollab) {
            stCollab.addEventListener('click', () => {
                if (!st.info) return;
                st.mode = 'audit';
                st.auditSub = 'queue';
                renderMain(false);
            });
        }
        $('btn-pin').onclick = pinTab;
        $('btn-renvar').onclick = () => promptRenameVar(st.selVar);
        $('btn-retype').onclick = () => promptRetypeVar(st.selVar);
        $('btn-navmode').onclick = () => {
            prefs().navMode = prefs().navMode === 'entropy' ? 'sections' : 'entropy';
            window.studio.persist();
            updateStatus();
        };

        $('console-in').onkeydown = (e) => {
            if (e.key === 'Enter') {
                const v = e.target.value;
                e.target.value = '';
                runCommand(v);
            }
        };

        document.querySelectorAll('.m-btn').forEach((b) => {
            b.onclick = () => { st.mode = b.dataset.mode; renderMain(true); };
        });
        document.querySelectorAll('.s-tab').forEach((b) => {
            b.onclick = () => {
                st.tab = b.dataset.tab;
                document.querySelectorAll('.s-tab').forEach((x) => x.classList.toggle('active', x === b));
                loadList(true);
            };
        });

        let fltTimer = null;
        $('filter-input').oninput = () => {
            clearTimeout(fltTimer);
            fltTimer = setTimeout(() => loadList(true), 120);
        };
        $('side-list').onscroll = (e) => {
            const el = e.target;
            if (st.tab !== 'patches' && st.listOff < st.listTotal && el.scrollTop + el.clientHeight >= el.scrollHeight - 80) loadList(false);
        };

        let wheelSteps = 0;
        let wheelRaf = 0;
        let wheelBusy = false;
        let wheelHex = false;

        async function flushWheel() {
            wheelRaf = 0;
            if (wheelBusy || !wheelSteps || !st.info) return;
            const steps = wheelSteps;
            wheelSteps = 0;
            wheelBusy = true;
            try {
                if (wheelHex) {
                    let next = BigInt(st.topVa) + BigInt(steps) * 16n;
                    const minVa = BigInt(st.info.min_va);
                    const maxVa = BigInt(st.info.max_va);
                    if (next < minVa) next = minVa;
                    if (next >= maxVa) next = maxVa > 16n ? (maxVa - 16n) : minVa;
                    st.topVa = '0x' + (next & ~15n).toString(16);
                } else {
                    const dir = steps > 0 ? 'next' : 'prev';
                    const r = await window.xdis.call({ op: 'step', va: st.topVa, dir, n: Math.min(64, Math.abs(steps)) });
                    if (r.ok) st.topVa = r.va;
                }
                await renderViewportFast();
            } finally {
                wheelBusy = false;
                if (wheelSteps && !wheelRaf) wheelRaf = requestAnimationFrame(flushWheel);
            }
        }

        function scheduleWheel(deltaY, isHex) {
            const mag = Math.max(1, Math.min(8, Math.round(Math.abs(deltaY) / 28) || 3));
            wheelSteps = Math.max(-48, Math.min(48, wheelSteps + (deltaY > 0 ? mag : -mag)));
            wheelHex = isHex;
            // coalesce burst wheel ticks to single in-flight rpc per frame
            if (!wheelRaf && !wheelBusy) wheelRaf = requestAnimationFrame(flushWheel);
        }

        let seekVa = null;
        let seekRaf = 0;
        let seekBusy = false;

        async function flushSeek() {
            seekRaf = 0;
            if (seekBusy || !seekVa || !st.info) return;
            const target = seekVa;
            seekVa = null;
            seekBusy = true;
            try {
                st.topVa = target;
                await renderViewportFast();
            } finally {
                seekBusy = false;
                if (seekVa && !seekRaf) seekRaf = requestAnimationFrame(flushSeek);
            }
        }

        function scheduleSeek(va) {
            seekVa = va;
            if (!seekRaf && !seekBusy) seekRaf = requestAnimationFrame(flushSeek);
        }

        window.vw.bindVScroll($('left-vscroll'), scheduleSeek);
        window.vw.bindVScroll($('right-vscroll'), scheduleSeek);

        $('left-body').addEventListener('wheel', (e) => {
            if (!st.info || (st.mode !== 'dis' && st.mode !== 'split' && st.mode !== 'dhex' && st.mode !== 'hex')) return;
            e.preventDefault();
            hidePeek();
            scheduleWheel(e.deltaY, st.mode === 'hex');
        }, { passive: false });

        $('right-body').addEventListener('wheel', (e) => {
            if (!st.info || st.mode !== 'dhex') return;
            e.preventDefault();
            hidePeek();
            scheduleWheel(e.deltaY, true);
        }, { passive: false });

        const nav = $('navstrip');
        function navVaAt(e) {
            if (!st.info) return null;
            const r = nav.getBoundingClientRect();
            const f = Math.min(1, Math.max(0, (e.clientX - r.left) / r.width));
            const min = BigInt(st.info.min_va), max = BigInt(st.info.max_va);
            return '0x' + (min + BigInt(Math.floor(f * Number(max - min)))).toString(16);
        }
        nav.onclick = (e) => { const va = navVaAt(e); if (va) gotoVa(va, true); };
        nav.oncontextmenu = (e) => {
            e.preventDefault();
            prefs().navMode = prefs().navMode === 'entropy' ? 'sections' : 'entropy';
            window.studio.persist();
            updateStatus();
        };
        nav.onmousemove = (e) => { const va = navVaAt(e); if (va) schedulePeek(va, e); };
        nav.onmouseleave = hidePeek;

        window.addEventListener('dragover', (e) => e.preventDefault());
        window.addEventListener('drop', (e) => {
            e.preventDefault();
            if (e.dataTransfer.files.length) {
                const p = window.xdis.filePath(e.dataTransfer.files[0]);
                if (p) openBinary(p);
            }
        });

        window.addEventListener('keydown', async (e) => {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;
            if (!$('modal-bg').classList.contains('hidden')) {
                if (e.key === 'Escape') closeModal();
                return;
            }
            if (e.ctrlKey) {
                const k = e.key.toLowerCase();
                if (k === 'o') { e.preventDefault(); openDialog(); }
                else if (k === 'f') { e.preventDefault(); openSearch(); }
                else if (k === 'p') { e.preventDefault(); openQuickJump(); }
                else if (k === 'k') { e.preventDefault(); openCommandPalette(); }
                else if (k === 's') { e.preventDefault(); runCommand('save'); }
                else if (k === 't') { e.preventDefault(); runCommand('theme'); }
                else if (k === 'j') { e.preventDefault(); openScripts(); }
                else if (k === 'z') { e.preventDefault(); doUndo(); }
                else if (k === 'y') { e.preventDefault(); doRedo(); }
                return;
            }

            if (e.key === 'F1') { e.preventDefault(); window.triView.openGuide($('modal-title'), $('modal-body'), $('modal-bg')); return; }
            if (st.mode === 'debug' && st.dbgTab === 'local') {
                const attached = !!(st.dbgSt && st.dbgSt.attached);
                const canBack = attached || !!(st.dbgSt && (st.dbgSt.nttd > 0 || st.dbgSt.nsnap > 1));
                if (e.key === 'F7' && e.shiftKey && canBack) { e.preventDefault(); dbgTtdBack(); return; }
                if (e.key === 'F7' && !e.shiftKey && attached) { e.preventDefault(); dbgStepCmd('dbg_step'); return; }
                if (e.key === 'F8' && e.shiftKey && attached) { e.preventDefault(); dbgStepCmd('dbg_step_out'); return; }
                if (e.key === 'F8' && !e.shiftKey && attached) { e.preventDefault(); dbgStepCmd('dbg_step_over'); return; }
                if (e.key === 'F9' && !e.shiftKey && attached) { e.preventDefault(); dbgStepCmd('dbg_cont', { ms: 1500 }); return; }
            }
            if (matchBind(e, 'overview')) { st.mode = st.mode === 'overview' ? 'split' : 'overview'; renderMain(false); }
            else if (matchBind(e, 'graph')) { e.preventDefault(); st.mode = st.mode === 'graph' ? 'split' : 'graph'; renderMain(true); }
            else if (matchBind(e, 'split')) { e.preventDefault(); st.mode = st.mode === 'split' ? 'gdec' : 'split'; renderMain(true); }
            else if (matchBind(e, 'calls')) { st.mode = st.mode === 'calls' ? 'split' : 'calls'; renderMain(true); }
            else if (matchBind(e, 'deobf')) { st.mode = st.mode === 'deobf' ? 'split' : 'deobf'; renderMain(false); }
            else if (matchBind(e, 'trace')) { st.mode = st.mode === 'trace' ? 'split' : 'trace'; renderMain(false); }
            else if (matchBind(e, 'ir')) { st.mode = st.mode === 'ir' ? 'split' : 'ir'; renderMain(false); }
            else if (matchBind(e, 'diff')) { st.mode = st.mode === 'diff' ? 'split' : 'diff'; renderMain(false); }
            else if (matchBind(e, 'audit') || (!prefs().keys.audit && e.key.toLowerCase() === 'a')) { st.mode = st.mode === 'audit' ? 'split' : 'audit'; renderMain(false); }
            else if (matchBind(e, 'types')) { st.mode = st.mode === 'types' ? 'split' : 'types'; renderMain(false); }
            else if (matchBind(e, 'debug')) { e.preventDefault(); st.mode = st.mode === 'debug' ? 'split' : 'debug'; renderMain(false); }
            else if (matchBind(e, 'hex')) { st.mode = st.mode === 'hex' ? 'dhex' : st.mode === 'dhex' ? 'split' : 'hex'; renderMain(true); }
            else if (matchBind(e, 'goto')) openPrompt('Go to address or symbol', '', resolveAndJump);
            else if (matchBind(e, 'rename')) {
                if (st.selVar) promptRenameVar(st.selVar);
                else openPrompt('Rename symbol at ' + st.curVa, '', (v) => runCommand('rename ' + v));
            }
            else if (matchBind(e, 'retype')) { if (st.selVar) promptRetypeVar(st.selVar); }
            else if (matchBind(e, 'comment')) openPrompt('Comment at ' + st.curVa, '', (v) => runCommand('cmt ' + v));
            else if (matchBind(e, 'bookmark')) openPrompt('Bookmark label', '', (v) => runCommand('mark ' + v));
            else if (matchBind(e, 'xrefs')) openXrefs();
            else if (matchBind(e, 'inspector')) { prefs().showInspector = !prefs().showInspector; window.studio.persist(); refreshInspector(); updateStatus(); }
            else if (e.key === '`') { e.preventDefault(); $('console-drawer').classList.toggle('hidden'); }
            else if (matchBind(e, 'pin')) pinTab();
            else if (matchBind(e, 'script')) openScripts();
            else if (e.key === ':') openPrompt('Command', '', runCommand);
            else if (e.key === '/') { e.preventDefault(); $('filter-input').focus(); }
            else if (e.key === 'Escape' && st.histPos > 0) gotoVa(st.hist[--st.histPos], false);
            else if (e.key === 'ArrowDown' && st.info) {
                e.preventDefault();
                const r = await window.xdis.call({ op: 'step', va: st.curVa, dir: 'next', n: 1 });
                if (r.ok) syncSelectVa(r.va);
            } else if (e.key === 'ArrowUp' && st.info) {
                e.preventDefault();
                const r = await window.xdis.call({ op: 'step', va: st.curVa, dir: 'prev', n: 1 });
                if (r.ok) syncSelectVa(r.va);
            }
        });
    }

    async function boot() {
        await window.studio.load();
        wireSplitters();
        wireEvents();
        if (window.xdis && window.xdis.onCollabEvent) {
            window.xdis.onCollabEvent(handleCollabEvent);
        }
        if (window.xdis && window.xdis.collabStatus) {
            try {
                const cs = await window.xdis.collabStatus();
                if (cs && cs.active) {
                    st.collabSt.active = true;
                    st.collabSt.role = cs.role || '';
                    st.collabSt.host = cs.host || '127.0.0.1';
                    st.collabSt.port = String(cs.port || 4545);
                    st.collabSt.nick = cs.nick || 'analyst';
                    st.collabSt.peers = Array.isArray(cs.peers) ? cs.peers : [];
                    updateCollabIndicator();
                }
            } catch (_) {}
        }
        if (prefs().upper) await window.xdis.call({ op: 'opt', upper: 1 });
        const init = await window.xdis.initialFile();
        if (init) openBinary(init);
        else renderMain(false);
    }

    boot();
})();
