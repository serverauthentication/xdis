window.triView = (() => {
    const GLOSS = {
        mov: 'copy value', movabs: 'load 64-bit constant', movzx: 'copy & zero-extend', movsx: 'copy & sign-extend', movsxd: 'copy 32->64 signed',
        lea: 'compute address (no read)', push: 'save on stack', pop: 'restore from stack', xchg: 'swap values',
        add: 'add values', sub: 'subtract values', inc: 'add 1', dec: 'subtract 1', imul: 'signed multiply', mul: 'unsigned multiply',
        idiv: 'signed divide', div: 'unsigned divide', neg: 'negate sign', not: 'invert all bits',
        and: 'bitwise AND', or: 'bitwise OR', xor: 'bitwise XOR (same reg = 0)', shl: 'shift left (* 2^n)', shr: 'logical shift right', sar: 'signed shift right',
        rol: 'rotate bits left', ror: 'rotate bits right', bswap: 'reverse byte order',
        cmp: 'compare values (sets flags)', test: 'bitwise AND check (sets flags)',
        jmp: 'jump unconditionally', call: 'run function & return here', ret: 'return to caller', leave: 'tear down stack frame',
        je: 'jump if equal / zero', jne: 'jump if not equal / nonzero', jl: 'jump if less (signed)', jle: 'jump if <= (signed)',
        jg: 'jump if greater (signed)', jge: 'jump if >= (signed)', jb: 'jump if below (unsigned)', jbe: 'jump if <= (unsigned)',
        ja: 'jump if above (unsigned)', jae: 'jump if >= (unsigned)', js: 'jump if negative', jns: 'jump if non-negative',
        nop: 'do nothing (alignment)', int3: 'debug breakpoint / padding', int1: 'single-step trap (anti-debug)',
        ud2: 'intentional crash trap', syscall: 'invoke OS kernel', cpuid: 'query CPU info (VM check)',
        rdtsc: 'read CPU cycle counter (timing)', rdtscp: 'serialized CPU cycle counter', pushfq: 'save CPU flags', popfq: 'restore CPU flags',
        cmove: 'copy if equal', cmovne: 'copy if not equal', sete: 'set 1 if equal', setne: 'set 1 if not equal',
        xorps: 'zero/XOR vector reg', pxor: 'zero/XOR SIMD reg', movups: 'unaligned vector copy', movaps: 'aligned vector copy',
        aesenc: 'AES encrypt round', aesdec: 'AES decrypt round', rdrand: 'hardware random number',
        b: 'ARM64 jump', bl: 'ARM64 call function', br: 'ARM64 indirect jump', blr: 'ARM64 indirect call',
        adrp: 'load 4KB page address', stp: 'store register pair', ldp: 'load register pair', str: 'store to memory', ldr: 'load from memory',
        cbz: 'branch if zero', cbnz: 'branch if nonzero', svc: 'ARM64 kernel syscall'
    };

    const SEC_ROLE = {
        '.text': 'Executable program code',
        'code': 'Executable program code',
        '.rdata': 'Read-only constants & text strings',
        '.rodata': 'Read-only constants & text strings',
        '.data': 'Writable global variables',
        '.bss': 'Zero-initialized global variables',
        '.pdata': 'Windows x64 function boundary table',
        '.idata': 'Imported system API table',
        '.edata': 'Exported functions table',
        '.rsrc': 'Icons, dialogs, version & resources',
        '.reloc': 'Base relocation fixups',
        '.tls': 'Thread-local storage init'
    };

    function esc(s) {
        return window.vw.esc(s);
    }

    function explain(mnem) {
        if (!mnem) return '';
        const k = mnem.toLowerCase().replace(/^(lock|rep|repne)\s+/, '');
        if (GLOSS[k]) return GLOSS[k];
        if (k.startsWith('cmov')) return 'conditional copy (' + k.slice(4) + ')';
        if (k.startsWith('set')) return 'set byte if ' + k.slice(3);
        if (k.startsWith('b.')) return 'ARM64 branch if ' + k.slice(2);
        if (k.startsWith('v')) return 'AVX vector op';
        return '';
    }

    function secDesc(name, perm, ent) {
        const lo = (name || '').toLowerCase();
        if (SEC_ROLE[lo]) return SEC_ROLE[lo];
        if ((perm & 2) && (perm & 4)) return 'Writable + executable (unpacker / JIT)';
        if (ent >= 7.0) return 'High-entropy data (compressed / encrypted)';
        if (perm & 4) return 'Custom executable code section';
        return 'Custom data section';
    }

    function scoreTone(sc) {
        if (sc >= 55) return 'tone-hi';
        if (sc >= 25) return 'tone-mid';
        return 'tone-ok';
    }

    function renderOverview(container, info, tri, entMap, extras, hooks) {
        if (!info || !tri || !tri.ok) {
            container.innerHTML = '<div class="welcome"><p>Open a binary to generate triage overview.</p></div>';
            return;
        }
        const base = info.path.split(/[\\/]/).pop();
        const mb = (info.size / 1048576).toFixed(2);
        const entByVa = {};
        if (entMap && entMap.secs) entMap.secs.forEach((s) => { entByVa[s.va] = s.ent; });
        const cryptoItems = (extras && extras.crypto && extras.crypto.items) ? extras.crypto.items : [];
        const vtCount = (extras && extras.vtables && extras.vtables.items) ? extras.vtables.items.length : 0;
        const lang = (extras && extras.lang && extras.lang.ok) ? extras.lang : null;
        const clsCount = (lang && lang.classes) ? lang.classes.length : 0;
        const goCount = (lang && lang.go_funcs) ? lang.go_funcs.length : 0;
        const rustCount = (lang && lang.rust_srcs) ? lang.rust_srcs.length : 0;

        const metaPills = [];
        if (info.has_clr) {
            metaPills.push('<button class="cap-pill clr-pill" data-act="lang" title="Inspect .NET CLR metadata (TypeDef, MethodDef, #US strings)">.NET CLR</button>');
        }
        if (lang && lang.runtime) {
            metaPills.push(`<button class="cap-pill" data-act="lang" title="Open IR → Classes / Lang view">Runtime: ${esc(lang.runtime)}</button>`);
        }
        if (clsCount) metaPills.push(`<button class="cap-pill" data-act="lang" title="Inspect C++ RTTI / ObjC classes">Classes: ${clsCount}</button>`);
        if (goCount) metaPills.push(`<button class="cap-pill" data-act="lang" title="Inspect Go .gopclntab functions">Go funcs: ${goCount}</button>`);
        if (rustCount) metaPills.push(`<button class="cap-pill" data-act="lang" title="Inspect Rust .rs source files">Rust files: ${rustCount}</button>`);
        if (info.pdb) metaPills.push(`<span class="meta-chip">PDB: ${esc(info.pdb.split(/[\\/]/).pop())}</span>`);
        if (info.nreloc) metaPills.push(`<span class="meta-chip">Relocs: ${info.nreloc}</span>`);
        if (info.nrsrc) metaPills.push(`<span class="meta-chip">Resources: ${info.nrsrc}</span>`);
        if (info.guard) metaPills.push(`<span class="meta-chip">Guard: 0x${info.guard.toString(16)}</span>`);
        if (vtCount) metaPills.push(`<button class="cap-pill" data-act="ir">Vtables: ${vtCount}</button>`);
        if (info.tls && info.tls.length) {
            info.tls.forEach((va, i) => metaPills.push(`<button class="cap-pill" data-va="${va}">TLS_${i} @ ${va.slice(-6)}</button>`));
        }
        const metaRow = metaPills.length ? `<div class="ov-pills" style="margin-top:4px">${metaPills.join('')}</div>` : '';

        const cryptoBlock = cryptoItems.length ? `
            <div class="ov-block">
              <div class="ov-h">Cryptographic constants detected (${cryptoItems.length})</div>
              <div class="ov-pills">${cryptoItems.map((c) =>
                  `<button class="cap-pill" data-va="${c.va}" title="${esc(c.detail)}">${esc(c.algo)} @ ${c.va.slice(-8)}</button>`
              ).join('')}</div>
            </div>` : '';

        const capCards = (tri.caps || []).filter((c) => c.items.length > 0).map((c) => {
            const pills = c.items.map((it) =>
                `<button class="cap-pill" data-va="${it.va}" title="Jump to ${esc(it.name)}">${esc(it.name)}</button>`
            ).join('');
            return `<div class="ov-cap"><div class="ov-cap-h"><span>${esc(c.group)}</span><b>${c.items.length}</b></div><div class="ov-pills">${pills}</div></div>`;
        }).join('') || '<div class="ins-empty">No standard OS API imports categorized (statically linked, stripped, or packed).</div>';

        const spotRows = (tri.spots || []).slice(0, 20).map((s) =>
            `<div class="ov-row" data-va="${s.va}">`
            + `<span class="badge b-${esc(s.kind.toLowerCase())}">${esc(s.kind)}</span>`
            + `<span class="ov-nm mono">${esc(s.name || s.va)}</span>`
            + `<span class="ov-rsn">${esc(s.reason)}</span>`
            + `<span class="ov-acts">`
            + `<button class="mini-btn" data-go="${s.va}">Open</button>`
            + `<button class="mini-btn" data-dob="${s.va}">Deobf</button>`
            + `<button class="mini-btn" data-emu="${s.va}">Trace</button>`
            + `</span></div>`
        ).join('') || '<div class="ins-empty">No obvious VM dispatchers, packed stubs, or opaque predicates flagged.</div>';

        const secRows = (info.secs || []).map((s) => {
            const h = entByVa[s.va] || 0;
            const perm = `${s.perm & 1 ? 'r' : '-'}${s.perm & 2 ? 'w' : '-'}${s.perm & 4 ? 'x' : '-'}`;
            const pct = Math.min(100, Math.round((h / 8) * 100));
            const hcls = h >= 7.0 ? 'var(--tok-ret)' : h >= 5.8 ? 'var(--tok-call)' : 'var(--tok-mnem)';
            return `<div class="ov-sec-row" data-va="${s.va}">`
                + `<span class="mono t-sym" style="width:90px">${esc(s.name)}</span>`
                + `<span class="mono" style="width:42px;color:var(--fg-muted)">${perm}</span>`
                + `<span class="mono" style="width:120px;color:var(--tok-addr)">${s.va}</span>`
                + `<span class="mono" style="width:74px;color:var(--fg-soft)">${(s.fsize / 1024).toFixed(1)} KB</span>`
                + `<span style="width:110px;display:flex;align-items:center;gap:6px"><span class="ent-bar" style="flex:1"><span class="ent-fill" style="width:${pct}%;background:${hcls}"></span></span><span class="mono" style="font-size:11px">${h.toFixed(1)}</span></span>`
                + `<span style="flex:1;color:var(--fg-soft)">${esc(secDesc(s.name, s.perm, h))}</span>`
                + `</div>`;
        }).join('');

        const notes = (tri.notes || []).map((n) => `<li>${esc(n)}</li>`).join('');

        container.innerHTML = `
          <div class="ov-wrap">
            <div class="ov-hero">
              <div class="ov-hero-l">
                <div class="ov-verdict ${scoreTone(Math.max(tri.pack_score, tri.obf_score))}">${esc(tri.verdict)}</div>
                <h2>${esc(base)}</h2>
                <div class="ov-sub">${esc(info.fmt)} · ${esc(info.arch)} (${info.bits}-bit) · ${mb} MB · Compiler: ${esc(tri.compiler)} · Packer: ${esc(tri.packer)}</div>
                ${metaRow}
                <div class="ov-start">
                  <button class="tb-btn hi" data-act="entry">Start at entry (${info.entry})</button>
                  <button class="tb-btn" data-act="gdec">Graph + Decompiler</button>
                  <button class="tb-btn" data-act="deobf">Deobfuscate</button>
                  <button class="tb-btn" data-act="trace">Safe trace</button>
                  <button class="tb-btn" data-act="pdb">Load PDB/MAP…</button>
                  <button class="tb-btn" data-act="sig_apply">Apply .xsig…</button>
                  <button class="tb-btn" data-act="rep_html">Report HTML</button>
                  <button class="tb-btn" data-act="rep_md">Report MD</button>
                  <button class="tb-btn" data-act="guide">Guide (?)</button>
                </div>
              </div>
              <div class="ov-meters">
                <div class="ov-m"><span>Packing risk</span><b class="mono">${tri.pack_score}/100</b><div class="ent-bar"><div class="ent-fill" style="width:${tri.pack_score}%;background:${tri.pack_score >= 55 ? 'var(--tok-ret)' : tri.pack_score >= 25 ? 'var(--tok-call)' : 'var(--tok-str)'}"></div></div></div>
                <div class="ov-m"><span>Obfuscation / VM</span><b class="mono">${tri.obf_score}/100</b><div class="ent-bar"><div class="ent-fill" style="width:${tri.obf_score}%;background:${tri.obf_score >= 55 ? 'var(--tok-ret)' : tri.obf_score >= 25 ? 'var(--tok-call)' : 'var(--tok-mnem)'}"></div></div></div>
                <div class="ov-m"><span>Max entropy</span><b class="mono">${tri.max_ent.toFixed(2)} / 8.0</b><div class="ent-bar"><div class="ent-fill" style="width:${Math.round(tri.max_ent / 8 * 100)}%;background:${tri.max_ent >= 7 ? 'var(--tok-ret)' : 'var(--tok-call)'}"></div></div></div>
              </div>
            </div>

            <div class="ov-block">
              <div class="ov-h">Key findings</div>
              <ul class="ov-notes">${notes}</ul>
            </div>
            ${cryptoBlock}

            <div class="ov-block">
              <div class="ov-h">What this binary interacts with (API capabilities)</div>
              <div class="ov-caps">${capCards}</div>
            </div>

            <div class="ov-block">
              <div class="ov-h">Obfuscation, VM &amp; packing hotspots (${tri.spots.length})</div>
              <div class="ov-table">${spotRows}</div>
            </div>

            <div class="ov-block">
              <div class="ov-h">Sections explained</div>
              <div class="ov-table">${secRows}</div>
            </div>
          </div>`;

        container.querySelectorAll('[data-act]').forEach((b) => { b.onclick = () => hooks.onAction(b.dataset.act); });
        container.querySelectorAll('.cap-pill[data-va]').forEach((b) => {
            b.onclick = () => hooks.onJump(b.dataset.va);
            b.onmouseenter = (e) => hooks.onPeek(b.dataset.va, e);
            b.onmouseleave = hooks.onHidePeek;
        });
        container.querySelectorAll('[data-go]').forEach((b) => { b.onclick = (e) => { e.stopPropagation(); hooks.onJump(b.dataset.go); }; });
        container.querySelectorAll('[data-dob]').forEach((b) => { b.onclick = (e) => { e.stopPropagation(); hooks.onDeobf(b.dataset.dob); }; });
        container.querySelectorAll('[data-emu]').forEach((b) => { b.onclick = (e) => { e.stopPropagation(); hooks.onTrace(b.dataset.emu); }; });
        container.querySelectorAll('.ov-sec-row').forEach((r) => { r.onclick = () => hooks.onJump(r.dataset.va); });
    }

    function renderDeobf(container, d, curVa, hooks) {
        if (!d || !d.ok) {
            container.innerHTML = '<div class="welcome"><p>Select an executable function to run static deobfuscation.</p></div>';
            return;
        }
        const strs = (d.strs || []).length
            ? `<div class="dob-strs"><span>Recovered stack strings:</span>${d.strs.map((s) =>
                `<button class="cap-pill" data-va="${s.va}">"${esc(s.text)}" @ ${s.va.slice(-6)}</button>`
              ).join('')}</div>`
            : '';

        const rows = (d.rows || []).map((r) => {
            const cls = r.tag === 2 ? ' dob-op' : r.tag === 3 ? ' dob-ind' : r.tag === 1 ? ' dob-fold' : '';
            const cur = r.va.toLowerCase() === (curVa || '').toLowerCase() ? ' cur' : '';
            return `<div class="dis-row${cur}${cls}" data-va="${r.va}">`
                + `<span class="c-addr">${window.vw.padVa(r.va)}</span>`
                + `<span class="c-mnem f-norm">${esc(r.mnem)}</span>`
                + `<span class="c-ops">${esc(r.ops)}</span>`
                + (r.note ? `<span class="c-cmt is-sym">; ${esc(r.note)}</span>` : '')
                + `</div>`;
        }).join('');

        container.innerHTML = `
          <div class="dob-bar">
            <span>Insns: <b>${d.orig}</b> → <b>${d.clean}</b></span>
            <span>Junk removed: <b>${d.junk}</b></span>
            <span>Opaque folded: <b>${d.opaque}</b></span>
            <span>Constants: <b>${d.folded}</b></span>
            <span>Indirect resolved: <b>${d.ind}</b></span>
            <span style="flex:1"></span>
            <button class="tb-btn" id="dob-trace">Run safe trace</button>
          </div>
          ${strs}
          <div class="dis-wrap">${rows}</div>`;

        container.querySelector('#dob-trace').onclick = () => hooks.onTrace(d.func_va);
        container.querySelectorAll('[data-va]').forEach((el) => {
            el.onclick = () => hooks.onSelect(el.dataset.va);
        });
    }

    function renderTrace(container, emu, steps, hooks) {
        if (!emu || !emu.ok) {
            container.innerHTML = '<div class="welcome"><p>Select executable code to trace safely in the static sandbox.</p></div>';
            return;
        }
        const regRows = Object.entries(emu.regs || {}).map(([k, v]) =>
            `<div class="ins-kv"><span class="mono">${k}</span><b class="mono">${v}</b></div>`
        ).join('');

        const stepRows = (emu.steps || []).map((s, i) =>
            `<div class="dis-row" data-va="${s.va}">`
            + `<span class="dec-ln">${i + 1}</span>`
            + `<span class="c-addr" style="width:12ch">${s.va.slice(-10)}</span>`
            + `<span class="c-ops" style="min-width:28ch">${esc(s.text)}</span>`
            + `<span class="c-cmt is-str">${esc(s.eff)}</span>`
            + `</div>`
        ).join('');

        container.innerHTML = `
          <div class="dob-bar">
            <span>Sandbox stop: <b>${esc(emu.stop)}</b></span>
            <span>Flags: <b>ZF=${emu.zf} SF=${emu.sf} CF=${emu.cf}</b></span>
            <span style="flex:1"></span>
            <button class="tb-btn${steps === 16 ? ' hi' : ''}" data-st="16">16 steps</button>
            <button class="tb-btn${steps === 48 ? ' hi' : ''}" data-st="48">48 steps</button>
            <button class="tb-btn${steps === 128 ? ' hi' : ''}" data-st="128">128 steps</button>
            <button class="tb-btn${steps === 256 ? ' hi' : ''}" data-st="256">256 steps</button>
          </div>
          <div class="emu-grid">
            <div class="emu-steps dis-wrap">${stepRows}</div>
            <div class="emu-regs">
              <div class="ins-title">Final registers (sandbox)</div>
              <div class="ins-kv"><span class="mono">rip</span><b class="mono t-sym">${emu.rip}</b></div>
              ${regRows}
              <div class="ins-title" style="margin-top:10px">Decoded stack ASCII</div>
              <div class="mono t-str" style="font-size:11.5px;word-break:break-all">${esc(emu.stack_str || '(none)')}</div>
            </div>
          </div>`;

        container.querySelectorAll('[data-st]').forEach((b) => {
            b.onclick = () => hooks.onRerun(Number(b.dataset.st));
        });
        container.querySelectorAll('.dis-row[data-va]').forEach((r) => {
            r.onclick = () => hooks.onSelect(r.dataset.va);
        });
    }

    function openGuide(modalTitle, modalBody, modalBg) {
        modalTitle.textContent = 'Quick guide — reading any binary in 60 seconds';
        modalBody.innerHTML = `
          <div class="guide-grid">
            <div class="g-card"><h4>1. Start in Overview</h4><p>See immediately if a file is normal, packed (UPX/VMProtect/high entropy), or obfuscated, what OS features it uses, and click any hotspot to jump right in.</p></div>
            <div class="g-card"><h4>2. Read C in Split / Graph+C</h4><p>Don't read raw assembly alone. Use <b>Split</b> or <b>Graph+C</b> to see readable C pseudocode synced line-by-line with instructions and flowcharts. Click any variable and press <b>N</b> to rename or <b>Y</b> to set its type.</p></div>
            <div class="g-card"><h4>3. Turn on Explain mode</h4><p>Toggle <b>Explain</b> (in Customize or top bar) to get plain-English hints next to instructions like <code>lea</code>, <code>test</code>, <code>je</code>, <code>rdtsc</code>, or ARM64 ops.</p></div>
            <div class="g-card"><h4>4. Beat Obfuscation &amp; Packing</h4><p>Right-click the top nav strip for an <b>Entropy Heatmap</b> (red/amber = packed/encrypted). Use <b>Deobf</b> to strip junk, fold constants &amp; recover stack strings, and <b>Trace</b> to safely emulate handlers without executing the binary.</p></div>
          </div>
          <div class="g-keys mono">
            Space: Graph · F5: Split/Graph+C · U: SSA IR / Classes · C: Call Graph · O: Overview · D: Deobf · E: Safe Trace · H: Hex · G: Goto · N/Y: Rename/Type · X: Xrefs · Ctrl+Z/Y: Undo/Redo · Ctrl+F: SIMD Search · Ctrl+J: Script Studio · Ctrl+P: Quick Jump
          </div>`;
        modalBg.classList.remove('hidden');
    }

    return { explain, renderOverview, renderDeobf, renderTrace, openGuide };
})();
