window.studio = (() => {
    const THEMES = {
        ida:      { name: 'IDA Dark',    bg: '#252526', fg: '#b8bcc4' },
        idalight: { name: 'IDA Classic', bg: '#ececec', fg: '#333333' },
        slate:    { name: 'Slate Dusk',  bg: '#131518', fg: '#8b94a5' },
        nord:     { name: 'Dusk Nord',   bg: '#1c2028', fg: '#9ea8b8' },
        moss:     { name: 'Warm Moss',   bg: '#131512', fg: '#9fa396' },
        paper:    { name: 'Ash Paper',   bg: '#dedad0', fg: '#535a66' }
    };

    const COLOR_TOKENS = [
        ['--bg', 'Canvas'],
        ['--bg-rail', 'Sidebar'],
        ['--bg-elev', 'Elevated'],
        ['--fg', 'Text'],
        ['--accent', 'Accent'],
        ['--tok-mnem', 'Mnemonic'],
        ['--tok-call', 'Call'],
        ['--tok-jmp', 'Jump'],
        ['--tok-ret', 'Return'],
        ['--tok-reg', 'Register'],
        ['--tok-num', 'Number'],
        ['--tok-str', 'String'],
        ['--tok-sym', 'Symbol'],
        ['--tok-kw', 'Keyword'],
        ['--tok-type', 'C Type']
    ];

    const DEFAULT_KEYS = {
        overview: 'o',
        graph: 'Space',
        split: 'F5',
        calls: 'c',
        deobf: 'd',
        trace: 'e',
        ir: 'u',
        diff: 'b',
        types: 'k',
        debug: 'F9',
        hex: 'h',
        goto: 'g',
        rename: 'n',
        retype: 'y',
        comment: ';',
        xrefs: 'x',
        bookmark: 'm',
        inspector: 'i',
        pin: 't',
        script: 'j'
    };

    const RECIPES = {
        crypto: `// scan for common crypto constants via SSE2
const sigs = [
  ['AES S-Box', '63 7c 77 7b f2 6b 6f c5'],
  ['SHA-256 K', '98 2f 8a 42 91 44 37 71'],
  ['ChaCha20',  'expand 32-byte k'],
  ['MD5 init',  '01 23 45 67 89 ab cd ef']
];
for (const [name, pat] of sigs) {
  const r = await xdis.find(pat);
  print(name + ':', r.hits.length, 'hits', r.hits.slice(0, 3).map(h => h.va));
}`,
        largest: `// list top 15 largest functions
const r = await xdis.funcs('', 200);
const top = [...r.items].sort((a, b) => b.size - a.size).slice(0, 15);
for (const f of top) print(f.va.padEnd(14), String(f.size).padStart(7) + 'B', f.name);`,
        entropy: `// section entropy breakdown
const r = await xdis.entropy();
for (const s of r.secs) {
  const tag = s.ent >= 7.1 ? ' [PACKED/ENCRYPTED]' : s.ent >= 5.8 ? ' [DENSE]' : '';
  print(s.name.padEnd(10), s.va, 'H=' + s.ent.toFixed(2) + tag);
}`,
        decompile: `// decompile current function and print C
const d = await xdis.dec(xdis.curVa);
if (!d.ok) print('not executable');
else print(d.lines.map(l => l.text).join('\\n'));`
    };

    const PY_RECIPES = {
        crypto: `# xdis Python SDK — triage, crypto & vtables audit
import xdis

with xdis.connect() as db:
    info = db.info
    print(f"{info['fmt']} {info['arch']} | {info['nfunc']} funcs | {info['nxref']} xrefs")
    for c in db.crypto():
        print(f"CRYPTO {c['algo']:12s} @ {c['va']} ({c['detail']})")
    for v in db.vtables()[:10]:
        print(f"VTABLE {v['va']} ({v['n']} entries) {v['cls']}")`,
        largest: `# xdis Python SDK — top 15 largest functions
import xdis

with xdis.connect() as db:
    funcs = sorted(db.functions(limit=200), key=lambda f: f.size, reverse=True)[:15]
    for f in funcs:
        print(f"{hex(f.va):14s} {f.size:7d}B  {f.name}")`,
        ir: `# xdis Python SDK — lift microcode IR & auto-recovered structs
import os, xdis

with xdis.connect() as db:
    va = os.environ.get("XDIS_CUR_VA") or hex(db.entry)
    ir = db.microcode(va)
    print(f"IR @ {ir.get('func_va')}: {len(ir.get('ops', []))} ops, {ir.get('nconst')} folded, {ir.get('ndce')} dce")
    for op in ir.get("ops", [])[:35]:
        print(f"  {op['va']}  {op['text']}")
    for st in ir.get("structs", []):
        print("AUTO STRUCT:", st["name"], len(st["fields"]), "fields")`,
        decompile: `# xdis Python SDK — decompile current function
import os, xdis

with xdis.connect() as db:
    va = os.environ.get("XDIS_CUR_VA") or hex(db.entry)
    print(db.decompile(va))`
    };

    const DEFAULTS = {
        uiRev: 2,
        theme: 'ida',
        font: '"Cascadia Mono", "JetBrains Mono", Consolas, monospace',
        fontSize: 13,
        lineHeight: 1.52,
        density: 'normal',
        showBytes: true,
        upper: false,
        peekEnabled: true,
        explain: false,
        navMode: 'sections',
        showInspector: false,
        colors: {},
        keys: { ...DEFAULT_KEYS }
    };

    let prefs = { ...DEFAULTS, colors: {}, keys: { ...DEFAULT_KEYS } };
    let scriptLang = 'py';
    let lastScriptJs = RECIPES.crypto;
    let lastScriptPy = PY_RECIPES.crypto;

    function getPrefs() { return prefs; }

    function applyPrefs() {
        const root = document.documentElement;
        root.dataset.theme = prefs.theme;
        root.dataset.density = prefs.density;
        root.style.setProperty('--font-mono', prefs.font);
        root.style.setProperty('--code-size', prefs.fontSize + 'px');
        root.style.setProperty('--code-lh', String(prefs.lineHeight));

        for (const [tok] of COLOR_TOKENS) root.style.removeProperty(tok);
        for (const [tok, val] of Object.entries(prefs.colors || {})) {
            if (val) root.style.setProperty(tok, val);
        }

        const th = THEMES[prefs.theme] || THEMES.ida;
        const railBg = prefs.colors['--bg-rail'] || th.bg;
        window.xdis.setTitleColors(railBg, th.fg);
    }

    async function load() {
        const saved = await window.xdis.loadPrefs();
        if (saved && typeof saved === 'object') {
            prefs = {
                ...DEFAULTS,
                ...saved,
                colors: { ...(saved.colors || {}) },
                keys: { ...DEFAULT_KEYS, ...(saved.keys || {}) }
            };
            if (!saved.uiRev || saved.uiRev < 2) {
                prefs.uiRev = 2;
                prefs.theme = 'ida';
                prefs.showInspector = false;
                prefs.lineHeight = 1.52;
                persist();
            }
        }
        applyPrefs();
        return prefs;
    }

    function persist() {
        window.xdis.savePrefs(prefs);
    }

    function rgbToHex(rgb) {
        if (!rgb) return '#17191d';
        if (rgb.startsWith('#')) return rgb.length === 7 ? rgb : '#17191d';
        const m = rgb.match(/\d+/g);
        if (!m || m.length < 3) return '#17191d';
        return '#' + m.slice(0, 3).map((x) => Number(x).toString(16).padStart(2, '0')).join('');
    }

    function renderCustomizer(container, onChange) {
        const cs = getComputedStyle(document.documentElement);
        const colorInputs = COLOR_TOKENS.map(([tok, label]) => {
            const hex = rgbToHex(cs.getPropertyValue(tok).trim());
            return `<label class="col-item"><span>${label}</span><input type="color" data-tok="${tok}" value="${hex}"></label>`;
        }).join('');

        const keyRows = Object.entries(DEFAULT_KEYS).map(([act]) => {
            const k = prefs.keys[act] || DEFAULT_KEYS[act];
            return `<div class="kb-row"><span>${act}</span><button class="kb-btn" data-act="${act}">${k}</button></div>`;
        }).join('');

        container.innerHTML = `
          <div class="drawer-tabs">
            <button class="dt-btn active" data-dtab="look">Theme</button>
            <button class="dt-btn" data-dtab="colors">Colors</button>
            <button class="dt-btn" data-dtab="keys">Keys</button>
            <button class="dt-btn" data-dtab="tools">Tools</button>
          </div>

          <div class="dtab-pane" data-dpane="look">
            <div class="drawer-sec">
              <div class="drawer-lbl">Muted palette</div>
              <div class="theme-grid">
                <button data-theme="slate" class="th-chip${prefs.theme === 'slate' ? ' active' : ''}"><i style="background:#17191d;border-color:#8faece"></i>Slate Dusk</button>
                <button data-theme="moss" class="th-chip${prefs.theme === 'moss' ? ' active' : ''}"><i style="background:#191a17;border-color:#9eb989"></i>Warm Moss</button>
                <button data-theme="nord" class="th-chip${prefs.theme === 'nord' ? ' active' : ''}"><i style="background:#22262e;border-color:#88a9be"></i>Dusk Nord</button>
                <button data-theme="paper" class="th-chip${prefs.theme === 'paper' ? ' active' : ''}"><i style="background:#e7e4dc;border-color:#4b6780"></i>Ash Paper</button>
              </div>
            </div>
            <div class="drawer-sec">
              <div class="drawer-lbl">Code font</div>
              <select id="p-font" class="sel-in">
                <option value='"Cascadia Mono", Consolas, monospace'>Cascadia Mono</option>
                <option value='"JetBrains Mono", Consolas, monospace'>JetBrains Mono</option>
                <option value='Consolas, monospace'>Consolas</option>
                <option value='"Fira Code", Consolas, monospace'>Fira Code</option>
                <option value='"IBM Plex Mono", Consolas, monospace'>IBM Plex Mono</option>
              </select>
            </div>
            <div class="drawer-sec">
              <div class="drawer-lbl">Font size <span id="p-fsz-v">${prefs.fontSize}px</span></div>
              <input id="p-fsz" type="range" min="11" max="18" value="${prefs.fontSize}">
            </div>
            <div class="drawer-sec">
              <div class="drawer-lbl">Line height <span id="p-lh-v">${prefs.lineHeight}</span></div>
              <input id="p-lh" type="range" min="135" max="195" value="${Math.round(prefs.lineHeight * 100)}">
            </div>
            <div class="drawer-sec">
              <div class="drawer-lbl">Density &amp; nav strip</div>
              <div class="seg-row">
                <button class="tb-btn${prefs.density === 'compact' ? ' hi' : ''}" data-dens="compact">Compact</button>
                <button class="tb-btn${prefs.density === 'normal' ? ' hi' : ''}" data-dens="normal">Normal</button>
                <button class="tb-btn${prefs.density === 'airy' ? ' hi' : ''}" data-dens="airy">Airy</button>
              </div>
            </div>
            <div class="drawer-sec toggles">
              <label><input id="p-bytes" type="checkbox"${prefs.showBytes ? ' checked' : ''}> Show opcode bytes</label>
              <label><input id="p-upper" type="checkbox"${prefs.upper ? ' checked' : ''}> Uppercase mnemonics</label>
              <label><input id="p-peek" type="checkbox"${prefs.peekEnabled ? ' checked' : ''}> Hover target previews</label>
              <label><input id="p-explain" type="checkbox"${prefs.explain ? ' checked' : ''}> Plain-language instruction hints</label>
              <label><input id="p-entnav" type="checkbox"${prefs.navMode === 'entropy' ? ' checked' : ''}> Entropy heatmap in nav bar</label>
            </div>
          </div>

          <div class="dtab-pane hidden" data-dpane="colors">
            <div class="col-grid">${colorInputs}</div>
            <div class="drawer-btns" style="margin-top:8px">
              <button class="tb-btn" id="p-col-reset">Reset custom colors</button>
              <button class="tb-btn" id="p-export-th">Export style JSON…</button>
              <button class="tb-btn" id="p-import-th">Import style JSON…</button>
            </div>
          </div>

          <div class="dtab-pane hidden" data-dpane="keys">
            <div class="drawer-lbl">Click a key, then press new binding</div>
            <div class="kb-list">${keyRows}</div>
            <button class="tb-btn" id="p-kb-reset" style="margin-top:8px;width:100%">Reset default keys</button>
          </div>

          <div class="dtab-pane hidden" data-dpane="tools">
            <div class="drawer-btns">
              <button class="tb-btn" data-tool="entropy">Run entropy plugin</button>
              <button class="tb-btn" data-tool="script">Open Python / JS Studio</button>
              <button class="tb-btn" data-tool="pdb">Load PDB / MAP symbols…</button>
              <button class="tb-btn" data-tool="sig_save">Save .xsig signatures…</button>
              <button class="tb-btn" data-tool="sig_apply">Apply .xsig signatures…</button>
              <button class="tb-btn" data-tool="save">Save .xdb + .xtypes</button>
              <button class="tb-btn" data-tool="rep_html">Export HTML report…</button>
              <button class="tb-btn" data-tool="rep_md">Export Markdown report…</button>
              <button class="tb-btn" data-tool="export_c">Export decompiled .c…</button>
              <button class="tb-btn" data-tool="export_asm">Export disassembly .asm…</button>
              <button class="tb-btn" data-tool="export_bin">Export patched binary…</button>
            </div>
          </div>`;

        container.querySelector('#p-font').value = prefs.font;

        container.querySelectorAll('.dt-btn').forEach((b) => {
            b.onclick = () => {
                container.querySelectorAll('.dt-btn').forEach((x) => x.classList.toggle('active', x === b));
                container.querySelectorAll('.dtab-pane').forEach((p) => p.classList.toggle('hidden', p.dataset.dpane !== b.dataset.dtab));
            };
        });

        container.querySelectorAll('.th-chip').forEach((b) => {
            b.onclick = () => {
                prefs.theme = b.dataset.theme;
                prefs.colors = {};
                applyPrefs(); persist();
                renderCustomizer(container, onChange);
                onChange('theme');
            };
        });

        container.querySelector('#p-font').onchange = (e) => { prefs.font = e.target.value; applyPrefs(); persist(); };
        container.querySelector('#p-fsz').oninput = (e) => {
            prefs.fontSize = Number(e.target.value);
            container.querySelector('#p-fsz-v').textContent = prefs.fontSize + 'px';
            applyPrefs(); persist();
        };
        container.querySelector('#p-lh').oninput = (e) => {
            prefs.lineHeight = Number((Number(e.target.value) / 100).toFixed(2));
            container.querySelector('#p-lh-v').textContent = String(prefs.lineHeight);
            applyPrefs(); persist();
        };
        container.querySelectorAll('[data-dens]').forEach((b) => {
            b.onclick = () => {
                prefs.density = b.dataset.dens;
                applyPrefs(); persist();
                renderCustomizer(container, onChange);
            };
        });
        container.querySelector('#p-bytes').onchange = (e) => { prefs.showBytes = e.target.checked; persist(); onChange('render'); };
        container.querySelector('#p-upper').onchange = (e) => { prefs.upper = e.target.checked; persist(); onChange('upper'); };
        container.querySelector('#p-peek').onchange = (e) => { prefs.peekEnabled = e.target.checked; persist(); onChange('peek'); };
        container.querySelector('#p-explain').onchange = (e) => { prefs.explain = e.target.checked; persist(); onChange('render'); };
        container.querySelector('#p-entnav').onchange = (e) => { prefs.navMode = e.target.checked ? 'entropy' : 'sections'; persist(); onChange('nav'); };

        container.querySelectorAll('input[data-tok]').forEach((inp) => {
            inp.oninput = () => {
                prefs.colors[inp.dataset.tok] = inp.value;
                applyPrefs(); persist();
            };
        });
        container.querySelector('#p-col-reset').onclick = () => {
            prefs.colors = {};
            applyPrefs(); persist();
            renderCustomizer(container, onChange);
        };
        container.querySelector('#p-export-th').onclick = async () => {
            const p = await window.xdis.saveFile({ title: 'Export style', defaultName: 'xdis-style.json', filters: [{ name: 'JSON', extensions: ['json'] }] });
            if (p) await window.xdis.writeText(p, JSON.stringify(prefs, null, 2));
        };
        container.querySelector('#p-import-th').onclick = async () => {
            const r = await window.xdis.readText();
            if (!r.ok) return;
            try {
                const parsed = JSON.parse(r.text);
                prefs = { ...DEFAULTS, ...parsed, colors: { ...(parsed.colors || {}) }, keys: { ...DEFAULT_KEYS, ...(parsed.keys || {}) } };
                applyPrefs(); persist();
                renderCustomizer(container, onChange);
                onChange('theme');
            } catch (_) {}
        };

        container.querySelectorAll('.kb-btn').forEach((btn) => {
            btn.onclick = () => {
                btn.textContent = 'Press key…';
                const cap = (ev) => {
                    ev.preventDefault(); ev.stopPropagation();
                    const k = ev.key === ' ' ? 'Space' : ev.key;
                    prefs.keys[btn.dataset.act] = k;
                    persist();
                    btn.textContent = k;
                    window.removeEventListener('keydown', cap, true);
                };
                window.addEventListener('keydown', cap, true);
            };
        });
        container.querySelector('#p-kb-reset').onclick = () => {
            prefs.keys = { ...DEFAULT_KEYS };
            persist();
            renderCustomizer(container, onChange);
        };

        container.querySelectorAll('[data-tool]').forEach((b) => {
            b.onclick = () => onChange('tool:' + b.dataset.tool);
        });
    }

    function openScriptModal(modalTitle, modalBody, modalBg, curVa, hooks) {
        modalTitle.textContent = 'Script Studio (Python xdis SDK + JS -> live C11 engine)';
        modalBody.innerHTML = `
          <div class="sc-bar">
            <button class="tb-btn${scriptLang === 'py' ? ' hi' : ''}" data-lang="py">Python (xdis SDK)</button>
            <button class="tb-btn${scriptLang === 'js' ? ' hi' : ''}" data-lang="js">JavaScript</button>
            <span style="width:6px"></span>
            <button class="tb-btn" data-rec="crypto">Crypto/Vtables</button>
            <button class="tb-btn" data-rec="largest">Largest funcs</button>
            <button class="tb-btn" data-rec="ir">IR / Entropy</button>
            <button class="tb-btn" data-rec="decompile">Dump C</button>
            <span style="flex:1"></span>
            <button class="tb-btn hi" id="sc-run">Run (Ctrl+Enter)</button>
          </div>
          <div class="sc-split">
            <textarea id="sc-code" class="sc-code" spellcheck="false"></textarea>
            <pre id="sc-out" class="sc-out">Ready. Python: import xdis; db = xdis.connect() | JS: await xdis.{info,funcs,dec,ir,crypto,vtables,diff,asm,rename,patch,...}</pre>
          </div>`;
        modalBg.classList.remove('hidden');

        const ed = modalBody.querySelector('#sc-code');
        const out = modalBody.querySelector('#sc-out');
        ed.value = scriptLang === 'py' ? lastScriptPy : lastScriptJs;
        ed.focus();

        function syncLang(nl) {
            if (scriptLang === 'py') lastScriptPy = ed.value;
            else lastScriptJs = ed.value;
            scriptLang = nl;
            modalBody.querySelectorAll('[data-lang]').forEach((b) => b.classList.toggle('hi', b.dataset.lang === nl));
            ed.value = nl === 'py' ? lastScriptPy : lastScriptJs;
        }

        async function exec() {
            if (scriptLang === 'py') lastScriptPy = ed.value;
            else lastScriptJs = ed.value;
            out.textContent = scriptLang === 'py' ? 'Running Python xdis SDK…' : 'Running JS…';
            const r = scriptLang === 'py'
                ? await window.xdis.runPython(ed.value, curVa)
                : await window.xdis.runScript(ed.value, curVa);
            const lines = (r.logs || []).slice();
            if (!r.ok && r.err) lines.push('ERROR: ' + r.err);
            out.textContent = lines.length ? lines.join('\n') : '(done, no output)';
            if (r.mutated) hooks.onMutated();
            if (r.jumpTo) hooks.onJump(r.jumpTo);
        }

        modalBody.querySelector('#sc-run').onclick = exec;
        modalBody.querySelectorAll('[data-lang]').forEach((b) => { b.onclick = () => syncLang(b.dataset.lang); });
        ed.onkeydown = (e) => {
            if (e.ctrlKey && e.key === 'Enter') { e.preventDefault(); exec(); }
            if (e.key === 'Tab') {
                e.preventDefault();
                const s = ed.selectionStart;
                ed.value = ed.value.slice(0, s) + '  ' + ed.value.slice(ed.selectionEnd);
                ed.selectionStart = ed.selectionEnd = s + 2;
            }
        };
        modalBody.querySelectorAll('[data-rec]').forEach((b) => {
            b.onclick = () => {
                const k = b.dataset.rec;
                if (scriptLang === 'py') {
                    ed.value = PY_RECIPES[k] || PY_RECIPES.crypto;
                    lastScriptPy = ed.value;
                } else {
                    ed.value = RECIPES[k === 'ir' ? 'entropy' : k] || RECIPES.crypto;
                    lastScriptJs = ed.value;
                }
            };
        });
    }

    return { THEMES, DEFAULT_KEYS, getPrefs, load, applyPrefs, persist, renderCustomizer, openScriptModal };
})();
