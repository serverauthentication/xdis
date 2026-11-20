window.proView = (() => {
    function esc(s) { return window.vw.esc(s); }

    function exportSvgMarkup(svgEl, defaultName) {
        if (!svgEl) return;
        const clone = svgEl.cloneNode(true);
        clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
        const cs = getComputedStyle(document.documentElement);
        const vars = ['--bg','--bg-rail','--bg-elev','--bg-sel','--fg','--fg-soft','--fg-muted','--border','--border-hi','--accent','--tok-addr','--tok-mnem','--tok-call','--tok-jmp','--tok-ret','--tok-sym','--edge-t','--edge-f','--edge-u'];
        let css = ':root{' + vars.map((v) => `${v}:${cs.getPropertyValue(v).trim()}`).join(';') + '}';
        css += 'svg{background:var(--bg);font-family:Consolas,monospace;font-size:12px}.blk-box{fill:var(--bg-elev);stroke:var(--border-hi)}.blk-hdr{fill:var(--bg-rail)}.cfg-edge{fill:none;stroke-width:1.4}.cfg-edge.back{stroke-dasharray:5 4;opacity:0.85}.e-t{stroke:var(--edge-t)}.e-f{stroke:var(--edge-f)}.e-u{stroke:var(--edge-u)}.cg-node rect{fill:var(--bg-elev);stroke:var(--border-hi)}.cg-node.cg-center rect{stroke:var(--accent);fill:var(--bg-sel)}.cg-node text{fill:var(--fg)}';
        const style = document.createElementNS('http://www.w3.org/2000/svg', 'style');
        style.textContent = css;
        clone.insertBefore(style, clone.firstChild);
        const text = '<?xml version="1.0" encoding="UTF-8"?>\n' + clone.outerHTML;
        window.xdis.saveFile({ title: 'Export SVG graph', defaultName: defaultName || 'graph.svg', filters: [{ name: 'SVG', extensions: ['svg'] }] }).then((p) => {
            if (p) window.xdis.writeText(p, text);
        });
    }

    function structToC(st) {
        const lines = [`struct ${st.name} {`];
        for (const f of (st.fields || [])) lines.push(`  ${f.type} ${f.name}; // +0x${f.off.toString(16)}`);
        lines.push('};');
        return lines.join('\n');
    }

    function renderStructsHtml(ir) {
        return (ir && ir.ok && ir.structs && ir.structs.length)
            ? ir.structs.map((s, idx) =>
                `<div class="pro-card"><div class="pro-ch"><span>${esc(s.name)}</span><button class="mini-btn" data-addst="${idx}">+ Types</button></div>`
                + `<pre class="pro-code">${esc(structToC(s))}</pre></div>`
            ).join('')
            : '<div class="ins-empty">No base-pointer struct accesses recovered in this function.</div>';
    }

    function renderSwitchesHtml(sws) {
        return (sws && sws.ok && sws.items && sws.items.length)
            ? sws.items.map((w) =>
                `<div class="pro-row" data-va="${w.va}"><span class="mono t-sym">${w.va.slice(-8)} → tbl ${w.table.slice(-8)}</span><b class="mono">${w.cases} cases</b></div>`
            ).join('')
            : '<div class="ins-empty">No indirect switch jump tables in this function.</div>';
    }

    function renderSsaOpsHtml(ssa, curLo, sub) {
        if (!ssa || !ssa.ok || !ssa.ops || !ssa.ops.length) {
            return `<div class="ins-empty" style="padding:12px">Select an executable function to lift SSA ${sub.toUpperCase()}.</div>`;
        }
        const blks = ssa.blks || [];
        const byBlk = new Map();
        ssa.ops.forEach((o, idx) => {
            const b = typeof o.blk === 'number' ? o.blk : 0;
            if (!byBlk.has(b)) byBlk.set(b, []);
            byBlk.get(b).push({ o, idx });
        });

        const renderOp = ({ o, idx }) => {
            const hasVa = o.va && o.va !== '0x0';
            const cur = hasVa && o.va.toLowerCase() === curLo ? ' cur' : '';
            const phiCls = o.phi ? ' ssa-phi' : '';
            const deadCls = o.dead ? ' ssa-dead' : '';
            const phiTag = o.phi ? '<span class="ssa-tag ssa-tag-phi">phi</span>' : '';
            const typTag = o.type ? `<span class="ssa-tag ssa-tag-type">${esc(o.type)}</span>` : '';
            return `<div class="dis-row${cur}${phiCls}${deadCls}"${hasVa ? ` data-va="${o.va}"` : ''}>`
                + `<span class="dec-ln">${idx + 1}</span>`
                + `<span class="c-addr" style="width:12ch">${hasVa ? o.va.slice(-10) : ''}</span>`
                + phiTag + typTag
                + `<span class="c-ops">${esc(o.text)}</span></div>`;
        };

        const out = [];
        if (blks.length) {
            blks.forEach((b, bi) => {
                out.push(
                    `<div class="ssa-blk-hdr" data-va="${b.start}">`
                    + `<span class="ssa-blk-id">B${bi}</span>`
                    + `<span class="mono">${b.start}</span>`
                    + `<span class="hdr-meta">(idom ${b.idom})</span>`
                    + `</div>`
                );
                const list = byBlk.get(bi) || [];
                for (const item of list) out.push(renderOp(item));
                byBlk.delete(bi);
            });
        }
        for (const list of byBlk.values()) {
            for (const item of list) out.push(renderOp(item));
        }
        return out.join('');
    }

    function renderDotnetBlock(dotnet) {
        if (!dotnet || !dotnet.ok) return '';
        const types = Array.isArray(dotnet.types) ? dotnet.types : [];
        const methods = Array.isArray(dotnet.methods) ? dotnet.methods : [];
        const strings = Array.isArray(dotnet.strings) ? dotnet.strings : [];

        const tdHtml = types.length
            ? `<div class="ov-table clr-scroll">${types.map((t) => {
                const full = t.ns
                    ? `<span class="clr-ns">${esc(t.ns)}.</span><span class="t-sym">${esc(t.name)}</span>`
                    : `<span class="t-sym">${esc(t.name)}</span>`;
                return `<div class="lang-cls-row">`
                    + `<span class="lang-cls-sig mono">${full}</span>`
                    + `<span class="lang-cls-meta"><span class="meta-chip">0x${Number(t.flags || 0).toString(16).padStart(8, '0')}</span></span>`
                    + `</div>`;
            }).join('')}</div>`
            : '<div class="ins-empty">No TypeDef entries parsed.</div>';

        const mdHtml = methods.length
            ? `<div class="ov-table clr-scroll">${methods.map((m) => {
                const hasVa = m.va && m.va !== '0x0';
                const vaEl = hasVa
                    ? `<button class="cap-pill" data-jump="${esc(m.va)}" title="Jump to method ${esc(m.va)}">${esc(m.va)}</button>`
                    : '<span class="mono prot-muted">—</span>';
                return `<div class="lang-cls-row"${hasVa ? ` data-jump="${esc(m.va)}"` : ''}>`
                    + `<span class="lang-cls-sig mono t-fn">${esc(m.name)}</span>`
                    + `<span class="lang-cls-meta">`
                    + `<span class="mono prot-muted">rva ${esc(m.rva || '0x0')}</span>`
                    + `<span class="meta-chip">0x${Number(m.flags || 0).toString(16).padStart(4, '0')}</span>`
                    + `${vaEl}`
                    + `</span></div>`;
            }).join('')}</div>`
            : '<div class="ins-empty">No MethodDef entries parsed.</div>';

        const usHtml = strings.length
            ? `<div class="lang-rust-list clr-scroll">${strings.map((s, i) =>
                `<div class="clr-str-row"><span class="prot-muted mono">#${i}</span><span class="mono t-str">"${esc(s)}"</span></div>`
            ).join('')}</div>`
            : '<div class="ins-empty">No #US managed user strings found.</div>';

        return `
          <div class="ov-block clr-section">
            <div class="ov-h">.NET CLR Metadata</div>
            <div class="clr-chips">
              <span class="prot-pill tone-ok">Runtime ${esc(dotnet.ver || 'CLR')}</span>
              <span class="meta-chip">Entry Token: <b>${esc(dotnet.entry_token || '0x00000000')}</b></span>
              <span class="meta-chip">TypeDef: <b>${types.length}</b></span>
              <span class="meta-chip">MethodDef: <b>${methods.length}</b></span>
              <span class="meta-chip">#US Strings: <b>${strings.length}</b></span>
            </div>
            <div class="clr-sub-h">TypeDef Classes (${types.length})</div>
            ${tdHtml}
            <div class="clr-sub-h">MethodDef Methods (${methods.length})</div>
            ${mdHtml}
            <div class="clr-sub-h">#US Managed Strings (${strings.length})</div>
            ${usHtml}
          </div>`;
    }

    function renderLangHtml(lang, dotnet) {
        const hasLang = !!(lang && lang.ok);
        const hasClr = !!(dotnet && dotnet.ok);
        if (!hasLang && !hasClr) {
            return '<div class="ins-empty" style="padding:14px">No runtime or class metadata available.</div>';
        }
        const classes = (hasLang && lang.classes) ? lang.classes : [];
        const goFuncs = (hasLang && lang.go_funcs) ? lang.go_funcs : [];
        const rustSrcs = (hasLang && lang.rust_srcs) ? lang.rust_srcs : [];
        const rtName = hasClr && (!hasLang || !lang.runtime || lang.runtime === 'C/Native')
            ? ('.NET CLR ' + (dotnet.ver || '')).trim()
            : ((hasLang && lang.runtime) ? lang.runtime : 'C/Native');

        const clsHtml = classes.length
            ? `<div class="ov-table">${classes.map((c) => {
                const bases = c.bases ? ` <span style="color:var(--fg-muted)">:</span> <span class="lang-bases">${esc(c.bases)}</span>` : '';
                const tag = c.lang ? `<span class="meta-chip">${esc(c.lang)}</span>` : '';
                const vaBtn = c.va && c.va !== '0x0'
                    ? `<button class="cap-pill" data-jump="${c.va}" title="Jump to vtable ${c.va}">${c.va}</button>`
                    : '';
                return `<div class="lang-cls-row">`
                    + `<span class="lang-cls-sig mono"><span class="t-sym">${esc(c.name)}</span>${bases}</span>`
                    + `<span class="lang-cls-meta">${tag}<span class="mono" style="color:var(--fg-muted)">${c.n} fn</span>${vaBtn}</span>`
                    + `</div>`;
            }).join('')}</div>`
            : '<div class="ins-empty">No C++ RTTI / ObjC class hierarchies recovered.</div>';

        const goHtml = goFuncs.length
            ? `<div class="ov-table">${goFuncs.map((f) =>
                `<div class="ov-row" data-jump="${f.va}">`
                + `<span class="mono t-sym" style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(f.name)}</span>`
                + `<span class="mono" style="color:var(--tok-addr)">${f.va}</span>`
                + `</div>`
            ).join('')}</div>`
            : '<div class="ins-empty">No Go .gopclntab functions detected.</div>';

        const rustHtml = rustSrcs.length
            ? `<div class="lang-rust-list">${rustSrcs.map((p) => `<div class="lang-rust-row">${esc(p)}</div>`).join('')}</div>`
            : '<div class="ins-empty">No Rust .rs source paths recovered.</div>';

        const clrSub = hasClr
            ? ` · CLR ${(dotnet.types || []).length} types / ${(dotnet.methods || []).length} methods / ${(dotnet.strings || []).length} #US strs`
            : '';

        return `
          <div class="lang-scroll">
            <div class="ov-wrap">
              <div class="ov-hero">
                <div class="ov-hero-l">
                  <div class="ov-verdict tone-ok">Runtime: ${esc(rtName)}</div>
                  <div class="ov-sub">${classes.length} classes · ${goFuncs.length} Go funcs · ${rustSrcs.length} Rust source files${clrSub}</div>
                </div>
              </div>
              ${renderDotnetBlock(dotnet)}
              <div class="ov-block">
                <div class="ov-h">C++ RTTI / ObjC Class Inheritance Hierarchy (${classes.length})</div>
                ${clsHtml}
              </div>
              <div class="ov-block">
                <div class="ov-h">Go .gopclntab Functions (${goFuncs.length})</div>
                ${goHtml}
              </div>
              <div class="ov-block">
                <div class="ov-h">Rust .rs Source Files (${rustSrcs.length})</div>
                ${rustHtml}
              </div>
            </div>
          </div>`;
    }

    function renderIR(container, sub, bundle, curVa, hooks) {
        const mode = sub || 'mlir';
        const { ssa, ir, vts, sws, lang, dotnet } = bundle || {};
        const curLo = (curVa || '').toLowerCase();

        const tabsHtml = `
          <button class="tb-btn${mode === 'mlir' ? ' hi' : ''}" data-irsub="mlir">MLIR (SSA)</button>
          <button class="tb-btn${mode === 'llir' ? ' hi' : ''}" data-irsub="llir">LLIR</button>
          <button class="tb-btn${mode === 'ir' ? ' hi' : ''}" data-irsub="ir">Legacy IR</button>
          <button class="tb-btn${mode === 'lang' ? ' hi' : ''}" data-irsub="lang">Classes / Lang</button>
          <span style="flex:1"></span>`;

        let metricsHtml = '';
        let bodyHtml = '';

        if (mode === 'mlir' || mode === 'llir') {
            const ok = !!(ssa && ssa.ok);
            metricsHtml = `
              <span class="meta-chip">Blocks: <b>${ok ? ssa.nblk : 0}</b></span>
              <span class="meta-chip">Phi: <b>${ok ? ssa.nphi : 0}</b></span>
              <span class="meta-chip">SCCP: <b>${ok ? ssa.nsccp : 0}</b></span>
              <span class="meta-chip">GVN: <b>${ok ? ssa.ngvn : 0}</b></span>
              <span class="meta-chip">DCE: <b>${ok ? ssa.ndce : 0}</b></span>`;

            const protoHtml = (ok && ssa.proto)
                ? `<div class="ssa-proto mono">${esc(ssa.proto)}</div>`
                : '';

            const vars = (ok && ssa.vars) ? ssa.vars : [];
            const varsHtml = vars.length
                ? `<div class="ssa-var-tbl">${vars.map((v) =>
                    `<div class="ssa-var-row">`
                    + `<span class="ssa-var-l"><span class="t-reg">${esc(v.name)}</span>${v.arg ? '<span class="ssa-arg-pill">arg</span>' : ''}</span>`
                    + `<span><span class="t-type">${esc(v.type)}</span>${v.is_const ? ` <span class="t-num">= ${esc(v.cval)}</span>` : ''}</span>`
                    + `</div>`
                ).join('')}</div>`
                : '<div class="ins-empty">No SSA variables inferred.</div>';

            bodyHtml = `
              ${protoHtml}
              <div class="pro-split">
                <div class="pro-main dis-wrap">${renderSsaOpsHtml(ssa, curLo, mode)}</div>
                <div class="pro-side">
                  <div class="ins-title">Inferred SSA Variables &amp; Types (${vars.length})</div>
                  ${varsHtml}
                  <div class="ins-title" style="margin-top:12px">Auto-Recovered Structs</div>
                  ${renderStructsHtml(ir)}
                  <div class="ins-title" style="margin-top:12px">Switch Tables</div>
                  ${renderSwitchesHtml(sws)}
                </div>
              </div>`;
        } else if (mode === 'ir') {
            const vtItems = (vts && vts.ok && vts.items) ? vts.items : [];
            metricsHtml = `
              <span>Ops: <b>${ir && ir.ok ? ir.ops.length : 0}</b></span>
              <span>Const: <b>${ir && ir.ok ? ir.nconst : 0}</b></span>
              <span>DCE: <b>${ir && ir.ok ? ir.ndce : 0}</b></span>
              <span>Structs: <b>${ir && ir.ok ? ir.structs.length : 0}</b></span>
              <span>Vtables: <b>${vtItems.length}</b></span>`;

            const opsHtml = (ir && ir.ok && ir.ops && ir.ops.length)
                ? ir.ops.map((o, i) => {
                    const cur = o.va && o.va.toLowerCase() === curLo ? ' cur' : '';
                    return `<div class="dis-row${cur}" data-va="${o.va}">`
                        + `<span class="dec-ln">${i + 1}</span>`
                        + `<span class="c-addr" style="width:12ch">${o.va.slice(-10)}</span>`
                        + `<span class="c-ops">${esc(o.text)}</span></div>`;
                }).join('')
                : '<div class="ins-empty" style="padding:12px">Select an executable function to lift Microcode IR.</div>';

            const vtHtml = vtItems.length
                ? vtItems.slice(0, 40).map((v) =>
                    `<div class="pro-row" data-va="${v.va}"><span class="mono t-sym">${esc(v.cls || ('vt_' + v.va.slice(-6)))}</span><span class="mono" style="color:var(--fg-muted)">${v.n} fn · ${v.va.slice(-8)}</span></div>`
                ).join('')
                : '<div class="ins-empty">No C++ vtables / RTTI detected.</div>';

            bodyHtml = `
              <div class="pro-split">
                <div class="pro-main dis-wrap">${opsHtml}</div>
                <div class="pro-side">
                  <div class="ins-title">Auto-recovered C structs</div>
                  ${renderStructsHtml(ir)}
                  <div class="ins-title" style="margin-top:12px">Switch jump tables</div>
                  ${renderSwitchesHtml(sws)}
                  <div class="ins-title" style="margin-top:12px">C++ Vtables &amp; RTTI (${vtItems.length})</div>
                  <div class="pro-list">${vtHtml}</div>
                </div>
              </div>`;
        } else {
            const ok = !!(lang && lang.ok);
            const hasClr = !!(dotnet && dotnet.ok);
            metricsHtml = `
              <span class="meta-chip">Runtime: <b>${esc(ok ? lang.runtime : (hasClr ? '.NET CLR' : '—'))}</b></span>
              ${hasClr ? `<span class="meta-chip">.NET CLR: <b>${esc(dotnet.ver || 'CLR')}</b> (${(dotnet.types || []).length}T/${(dotnet.methods || []).length}M)</span>` : ''}
              <span class="meta-chip">Classes: <b>${ok && lang.classes ? lang.classes.length : 0}</b></span>
              <span class="meta-chip">Go: <b>${ok && lang.go_funcs ? lang.go_funcs.length : 0}</b></span>
              <span class="meta-chip">Rust: <b>${ok && lang.rust_srcs ? lang.rust_srcs.length : 0}</b></span>`;
            bodyHtml = renderLangHtml(lang, dotnet);
        }

        container.innerHTML = `
          <div class="ir-wrap">
            <div class="dob-bar">${tabsHtml}${metricsHtml}</div>
            ${bodyHtml}
          </div>`;

        container.querySelectorAll('[data-irsub]').forEach((b) => {
            b.onclick = () => hooks.onSub(b.dataset.irsub);
        });
        container.querySelectorAll('.dis-row[data-va], .pro-row[data-va], .ssa-blk-hdr[data-va]').forEach((el) => {
            el.onclick = () => hooks.onSelect(el.dataset.va);
            el.ondblclick = () => hooks.onJump(el.dataset.va);
        });
        container.querySelectorAll('[data-jump]').forEach((el) => {
            el.onclick = (e) => { e.stopPropagation(); hooks.onJump(el.dataset.jump); };
        });
        container.querySelectorAll('[data-addst]').forEach((b) => {
            b.onclick = () => {
                const s = ir && ir.structs ? ir.structs[Number(b.dataset.addst)] : null;
                if (s) hooks.onAddStruct(structToC(s));
            };
        });
    }

    function renderSnapshotsModal(modalTitle, modalBody, modalBg, items, hooks) {
        const list = Array.isArray(items) ? items : [];
        modalTitle.textContent = `Project Snapshots (.xdb v3 · ${list.length} saved)`;
        const rowsHtml = list.length
            ? list.map((s) =>
                `<div class="snap-row">`
                + `<div><div class="mono t-sym">${esc(s.name)}</div>`
                + `<div class="snap-meta">${s.nsym} syms · ${s.ncmt} cmts · ${s.npatch} patches · ${s.nlvar} lvars</div></div>`
                + `<button class="mini-btn" data-snap-load="${esc(s.name)}">Restore</button>`
                + `</div>`
            ).join('')
            : '<div class="ins-empty" style="padding:12px">No snapshots saved yet in this .xdb database.</div>';

        modalBody.innerHTML = `
          <div class="snap-bar">
            <input id="snap-name" class="modal-input" placeholder="Save Snapshot… (name, e.g. baseline or pre-patch)" maxlength="47" spellcheck="false">
            <button id="snap-save" class="tb-btn hi">Save</button>
          </div>
          <div class="modal-list" style="max-height:46vh">${rowsHtml}</div>`;
        modalBg.classList.remove('hidden');

        const inp = modalBody.querySelector('#snap-name');
        const submit = () => {
            const nm = inp.value.trim() || ('snap_' + (list.length + 1));
            hooks.onSave(nm);
        };
        modalBody.querySelector('#snap-save').onclick = submit;
        inp.onkeydown = (e) => {
            if (e.key === 'Enter') submit();
            else if (e.key === 'Escape') hooks.onClose();
        };
        modalBody.querySelectorAll('[data-snap-load]').forEach((b) => {
            b.onclick = () => hooks.onLoad(b.dataset.snapLoad);
        });
        inp.focus();
    }

    function renderSigModal(modalTitle, modalBody, modalBg, sr, hooks) {
        const hits = Number(sr && sr.hits ? sr.hits : 0);
        const isUniq = hits === 1;
        const badgeCls = isUniq ? 'sig-badge sig-uniq' : 'sig-badge sig-multi';
        const badgeTxt = isUniq ? 'UNIQUE (1 hit)' : `${hits} hits`;
        const vaStr = (sr && sr.va) ? sr.va : '0x0';
        const lenNum = Number(sr && sr.len ? sr.len : 0);

        modalTitle.textContent = `Auto-Sig · ${vaStr}`;
        modalBody.innerHTML = `
          <div class="sig-head">
            <span class="${badgeCls}">${esc(badgeTxt)}</span>
            <span class="meta-chip">Length: <b>${lenNum} B</b></span>
            <span class="meta-chip">VA: <b>${esc(vaStr)}</b></span>
          </div>
          <div class="sig-field">
            <label class="sig-lbl" for="sig-ida">IDA Pattern</label>
            <div class="sig-row">
              <input id="sig-ida" class="modal-input sig-in mono" readonly value="${esc(sr.ida || '')}" spellcheck="false">
              <button class="tb-btn" data-sig-copy="sig-ida">Copy</button>
            </div>
          </div>
          <div class="sig-field">
            <label class="sig-lbl" for="sig-cbytes">C Pattern (bytes)</label>
            <div class="sig-row">
              <input id="sig-cbytes" class="modal-input sig-in mono" readonly value="${esc(sr.c_bytes || '')}" spellcheck="false">
              <button class="tb-btn" data-sig-copy="sig-cbytes">Copy</button>
            </div>
          </div>
          <div class="sig-field">
            <label class="sig-lbl" for="sig-cmask">C Mask</label>
            <div class="sig-row">
              <input id="sig-cmask" class="modal-input sig-in mono" readonly value="${esc(sr.c_mask || '')}" spellcheck="false">
              <button class="tb-btn" data-sig-copy="sig-cmask">Copy</button>
            </div>
          </div>`;
        modalBg.classList.remove('hidden');

        modalBody.querySelectorAll('.sig-in').forEach((inp) => {
            inp.onclick = () => inp.select();
            inp.onkeydown = (e) => {
                if (e.key === 'Escape' && hooks && hooks.onClose) hooks.onClose();
            };
        });
        modalBody.querySelectorAll('[data-sig-copy]').forEach((btn) => {
            btn.onclick = async () => {
                const inp = modalBody.querySelector('#' + btn.dataset.sigCopy);
                if (!inp) return;
                const val = inp.value;
                try {
                    await navigator.clipboard.writeText(val);
                } catch (_) {
                    inp.select();
                    document.execCommand('copy');
                }
                btn.textContent = 'Copied';
                btn.classList.add('hi');
                if (hooks && hooks.onCopy) hooks.onCopy(val);
                setTimeout(() => {
                    btn.textContent = 'Copy';
                    btn.classList.remove('hi');
                }, 1200);
            };
        });
        const first = modalBody.querySelector('#sig-ida');
        if (first) { first.focus(); first.select(); }
    }

    function diffCodeLines(linesA, linesB) {
        const setA = new Set(linesA);
        const setB = new Set(linesB);
        const htmlA = linesA.map((l, i) =>
            `<div class="dec-row${!setB.has(l) ? ' df-del' : ''}"><span class="dec-ln">${i + 1}</span><span>${esc(l)}</span></div>`
        ).join('') || '<div class="ins-empty" style="padding:10px">(not present in Binary A)</div>';
        const htmlB = linesB.map((l, i) =>
            `<div class="dec-row${!setA.has(l) ? ' df-add' : ''}"><span class="dec-ln">${i + 1}</span><span>${esc(l)}</span></div>`
        ).join('') || '<div class="ins-empty" style="padding:10px">(not present in Binary B)</div>';
        return { htmlA, htmlB };
    }

    function fmtSignedDelta(n) {
        const v = Number(n || 0);
        if (v > 0) return `<span class="df-delta-pos">+${v}</span>`;
        if (v < 0) return `<span class="df-delta-neg">${v}</span>`;
        return '0';
    }

    function scoreToneCls(score) {
        const s = Number(score || 0);
        if (s >= 70) return 'tone-hi';
        if (s >= 40) return 'tone-mid';
        return 'tone-ok';
    }

    function renderDiff(container, dst, hooks) {
        const tags = ['SAME', 'MOD', 'ADD', 'DEL'];
        const cls = ['b-same', 'b-mod', 'b-add', 'b-del'];
        const res = dst.data;
        const hasDiff = !!(res && res.ok);
        const view = dst.view === 'triage' && hasDiff ? 'triage' : 'diff';
        const flt = dst.filter || 'all';
        const items = hasDiff && res.items
            ? res.items.filter((it) => flt === 'all' || tags[it.kind].toLowerCase() === flt)
            : [];
        const pdiffItems = (dst.pdiff && dst.pdiff.ok && Array.isArray(dst.pdiff.items)) ? dst.pdiff.items : [];

        let listHtml = '';
        if (view === 'triage') {
            if (!dst.pdiff) {
                listHtml = '<div class="ins-empty" style="padding:12px">Running security patch triage…</div>';
            } else if (!dst.pdiff.ok) {
                listHtml = `<div class="dbg-err">${esc(dst.pdiff.err || 'Security patch triage failed.')}</div>`;
            } else if (!pdiffItems.length) {
                listHtml = '<div class="ins-empty" style="padding:12px">No security-relevant modified functions ranked between Binary A and Binary B.</div>';
            } else {
                const trRows = pdiffItems.map((it, idx) => {
                    const sel = dst.sel && dst.sel.va_a === it.va_a && dst.sel.va_b === it.va_b ? ' cur' : '';
                    return `<tr class="${sel.trim()}" data-pdi="${idx}">`
                        + `<td><span class="df-score ${scoreToneCls(it.score)}">${Number(it.score || 0)}</span></td>`
                        + `<td class="mono t-sym">${esc(it.name || it.va_a)}</td>`
                        + `<td class="mono prot-muted">${esc(it.va_a)}</td>`
                        + `<td class="df-delta">${fmtSignedDelta(it.delta_cmp)}</td>`
                        + `<td class="df-delta">${fmtSignedDelta(it.delta_jcc)}</td>`
                        + `<td class="df-reason">${esc(it.reason || '')}</td>`
                        + `</tr>`;
                }).join('');
                listHtml = `
                  <table class="df-triage-tbl">
                    <thead>
                      <tr><th>Score</th><th>Function</th><th>VA (A)</th><th style="text-align:right">dCmp</th><th style="text-align:right">dJcc</th><th>Security Patch Reason</th></tr>
                    </thead>
                    <tbody>${trRows}</tbody>
                  </table>`;
            }
        } else {
            listHtml = items.map((it, idx) => {
                const sel = dst.sel && dst.sel.va_a === it.va_a && dst.sel.va_b === it.va_b ? ' cur' : '';
                return `<div class="ov-row${sel}" data-di="${idx}">`
                    + `<span class="badge ${cls[it.kind] || ''}">${tags[it.kind] || '?'}</span>`
                    + `<span class="ov-nm mono">${esc(it.name || it.va_a)}</span>`
                    + `<span class="mono" style="width:52px;color:var(--fg-soft)">${it.sim}%</span>`
                    + `<span class="mono" style="color:var(--fg-muted)">${it.sa}B → ${it.sb}B</span></div>`;
            }).join('') || '<div class="ins-empty" style="padding:12px">Pick a second binary to compare function DNA and decompiled C.</div>';
        }

        const dc = diffCodeLines(dst.codeA || [], dst.codeB || []);
        const baseB = dst.otherPath ? dst.otherPath.split(/[\\/]/).pop() : 'None';

        container.innerHTML = `
          <div class="dob-bar">
            <button class="tb-btn hi" id="df-pick">Compare binary…</button>
            <span>Target B: <b>${esc(baseB)}</b></span>
            ${hasDiff ? `
              <button class="mini-btn${view === 'diff' && flt === 'all' ? ' hi' : ''}" data-df="all">All (${res.items.length})</button>
              <button class="mini-btn${view === 'diff' && flt === 'mod' ? ' hi' : ''}" data-df="mod">MOD ${res.mod}</button>
              <button class="mini-btn${view === 'diff' && flt === 'add' ? ' hi' : ''}" data-df="add">ADD ${res.add}</button>
              <button class="mini-btn${view === 'diff' && flt === 'del' ? ' hi' : ''}" data-df="del">DEL ${res.del}</button>
              <button class="mini-btn${view === 'diff' && flt === 'same' ? ' hi' : ''}" data-df="same">SAME ${res.same}</button>
            ` : ''}
            <span style="flex:1"></span>
            <button class="tb-btn${view === 'triage' ? ' hi' : ''}" id="df-triage"${hasDiff ? '' : ' disabled'}>Security Triage${dst.pdiff && dst.pdiff.ok ? ` (${pdiffItems.length})` : ''}</button>
          </div>
          <div class="df-layout">
            <div class="df-list">${listHtml}</div>
            <div class="df-panes">
              <div class="df-col"><div class="pane-head"><span>Binary A (current)</span><span class="pane-meta">${dst.sel ? esc(dst.sel.va_a) : ''}</span></div><div class="df-code">${dc.htmlA}</div></div>
              <div class="df-col"><div class="pane-head"><span>Binary B (${esc(baseB)})</span><span class="pane-meta">${dst.sel ? esc(dst.sel.va_b) : ''}</span></div><div class="df-code">${dc.htmlB}</div></div>
            </div>
          </div>`;

        container.querySelector('#df-pick').addEventListener('click', hooks.onPick);
        const triageBtn = container.querySelector('#df-triage');
        if (triageBtn && hooks.onTriage) triageBtn.addEventListener('click', hooks.onTriage);
        container.querySelectorAll('[data-df]').forEach((b) => {
            b.addEventListener('click', () => hooks.onFilter(b.dataset.df));
        });
        container.querySelectorAll('[data-di]').forEach((r) => {
            r.addEventListener('click', () => hooks.onSelect(items[Number(r.dataset.di)]));
            r.addEventListener('dblclick', () => {
                const it = items[Number(r.dataset.di)];
                if (it && it.va_a !== '0x0') hooks.onJumpA(it.va_a);
            });
        });
        container.querySelectorAll('[data-pdi]').forEach((r) => {
            r.addEventListener('click', () => hooks.onSelect(pdiffItems[Number(r.dataset.pdi)]));
            r.addEventListener('dblclick', () => {
                const it = pdiffItems[Number(r.dataset.pdi)];
                if (it && it.va_a && it.va_a !== '0x0') hooks.onJumpA(it.va_a);
            });
        });
    }

    const TYPE_PRESETS = {
        node: 'struct ListNode {\n  void *next;\n  void *prev;\n  uint32_t key;\n  uint32_t flags;\n};',
        pe: 'struct DosHdr {\n  uint16_t e_magic;\n  uint16_t e_cblp;\n  uint32_t e_lfanew;\n};',
        enum: 'enum Status {\n  ST_OK = 0,\n  ST_ERR = 1,\n  ST_DENIED = 5\n};'
    };

    function safeBigInt(val) {
        try { return BigInt(val || '0x0'); } catch (_) { return 0n; }
    }

    function fmtHexBytes(hex) {
        const s = String(hex || '').trim();
        return s ? s.replace(/(..)/g, '$1 ').trim() : '—';
    }

    function renderOverlayHtml(overlay, curVa) {
        if (!overlay) return '';
        if (!overlay.ok) {
            return `
              <div class="pro-overlay">
                <div class="ovl-head">
                  <span class="mono t-sym">Struct Overlay</span>
                  <span style="flex:1"></span>
                  <button class="mini-btn" id="ovl-close" title="Close overlay">×</button>
                </div>
                <div class="dbg-err">${esc(overlay.err || 'Failed to apply struct overlay.')}</div>
              </div>`;
        }
        const fields = Array.isArray(overlay.fields) ? overlay.fields : [];
        const liveCls = overlay.live ? 'ovl-mode-live' : 'ovl-mode-stat';
        const liveLbl = overlay.live ? 'LIVE' : 'STATIC';
        const rowsHtml = fields.length
            ? fields.map((f) => {
                const offStr = '+0x' + Number(f.off || 0).toString(16).padStart(2, '0');
                const valStr = f.val || '0x0';
                const vBig = safeBigInt(valStr);
                const isPtrType = String(f.type || '').includes('*')
                    || /^(LPVOID|PVOID|LPCSTR|LPSTR|LPCWSTR|LPWSTR|HANDLE|HMODULE|uintptr_t|intptr_t)$/i.test(String(f.type || '').trim());
                const isPtr = isPtrType && vBig >= 0x10000n;
                const valHtml = isPtr
                    ? `<span class="mono ovl-ptr" data-ovl-follow="${esc(valStr)}" title="Double-click to re-apply ${esc(overlay.name)} @ ${esc(valStr)} (Shift+dblclick to jump)">${esc(valStr)}</span>`
                    : `<span class="mono t-num">${esc(valStr)}</span>`;
                let prevHtml = '<span class="prot-muted">—</span>';
                if (f.preview && isPtr) {
                    prevHtml = `<button class="cap-pill ovl-prev-btn" data-ovl-jump="${esc(valStr)}" title="Jump to ${esc(valStr)}">"${esc(f.preview)}"</button>`;
                } else if (f.preview) {
                    prevHtml = `<span class="mono t-str">"${esc(f.preview)}"</span>`;
                } else if (isPtr) {
                    prevHtml = `<button class="cap-pill ovl-prev-btn" data-ovl-jump="${esc(valStr)}" title="Jump to ${esc(valStr)}">→ ${esc(valStr)}</button>`;
                }
                return `<tr>`
                    + `<td class="mono ovl-off">${offStr}</td>`
                    + `<td class="mono t-type">${esc(f.type)}</td>`
                    + `<td class="mono ovl-nm">${esc(f.name)}</td>`
                    + `<td>${valHtml}</td>`
                    + `<td class="mono ovl-hex">${esc(fmtHexBytes(f.hex))}</td>`
                    + `<td class="ovl-prev">${prevHtml}</td>`
                    + `</tr>`;
            }).join('')
            : '<tr><td colspan="6" class="ins-empty" style="padding:10px">Struct has no fields to decode.</td></tr>';

        return `
          <div class="pro-overlay">
            <div class="ovl-head">
              <span class="ovl-title">
                <b class="mono t-sym">${esc(overlay.name)}</b>
                <span class="prot-muted">@</span>
                <span class="mono">${esc(overlay.va)}</span>
                <span class="prot-muted">(${overlay.size}B · <b class="${liveCls}">${liveLbl}</b>)</span>
              </span>
              <span style="flex:1"></span>
              <input id="ovl-va" class="dbg-in" style="width:152px" value="${esc(overlay.va || curVa || '0x0')}" placeholder="0x... or symbol" spellcheck="false">
              <button class="mini-btn hi" id="ovl-ref">Refresh</button>
              <button class="mini-btn" id="ovl-close" title="Close overlay">×</button>
            </div>
            <div class="ovl-scroll">
              <table class="ovl-tbl">
                <thead>
                  <tr><th>Offset</th><th>Type</th><th>Name</th><th>Value</th><th>Hex</th><th>Preview</th></tr>
                </thead>
                <tbody>${rowsHtml}</tbody>
              </table>
            </div>
          </div>`;
    }

    function renderTypes(container, data, draft, overlay, curVa, hooks) {
        const items = (data && data.ok && data.items) ? data.items : [];
        const kinds = ['struct', 'enum', 'typedef', 'union'];
        const activeName = (overlay && overlay.ok) ? overlay.name : '';
        const listHtml = items.length ? items.map((t) => {
            const mems = (t.mems || []).map((m) =>
                `<div class="ins-kv"><span class="mono">+0x${m.off.toString(16)} ${esc(m.type)} <b>${esc(m.name)}</b></span><span class="mono" style="color:var(--fg-muted)">${m.size}B</span></div>`
            ).join('');
            const canApply = t.size > 0 && t.kind !== 1 && t.kind !== 2;
            const applyBtn = canApply
                ? `<button class="mini-btn" data-apply-st="${esc(t.name)}" title="Apply ${esc(t.name)} overlay @ ${esc(curVa || '0x0')}">Apply @ VA</button>`
                : '';
            const actCls = activeName && activeName === t.name ? ' tp-active' : '';
            return `<div class="pro-card${actCls}"><div class="pro-ch"><span>${kinds[t.kind] || 'type'} ${esc(t.name)}</span><span class="tp-card-acts"><span class="mono prot-muted">${t.size}B</span>${applyBtn}</span></div>${mems}</div>`;
        }).join('') : '<div class="ins-empty" style="padding:12px">No local C types yet. Paste a struct/enum/typedef on the left, load a .h header, or import a .xtil pack.</div>';

        const edStyle = overlay ? 'flex:0.72;min-height:110px' : 'flex:1';

        container.innerHTML = `
          <div class="ir-wrap">
            <div class="dob-bar tp-bar">
              <span>Types (<b>${items.length}</b> · <code>.xtypes</code>)</span>
              <span class="dbg-sep"></span>
              <button class="tb-btn" id="tp-hdr" title="Parse C/C++ header (.h / .hpp)">Load .h…</button>
              <button class="tb-btn" data-stdlib="win32" title="Load Win32 .xtil standard types">+ Win32 .xtil</button>
              <button class="tb-btn" data-stdlib="posix" title="Load POSIX .xtil standard types">+ POSIX .xtil</button>
              <button class="tb-btn" id="tp-pdb" title="Load native MSF PDB symbols &amp; types">PDB (MSF)…</button>
              <button class="tb-btn" id="tp-dwarf" title="Scan embedded DWARF debug info">Scan DWARF</button>
              <span style="flex:1"></span>
              <button class="mini-btn" data-tp="node">ListNode</button>
              <button class="mini-btn" data-tp="pe">DosHdr</button>
              <button class="mini-btn" data-tp="enum">Enum</button>
              <button class="tb-btn hi" id="tp-add">Parse &amp; Add</button>
            </div>
            <div class="pro-split">
              <div class="pro-main tp-left">
                <textarea id="tp-ed" class="sc-code" style="${edStyle}" spellcheck="false" placeholder="struct Packet { uint32_t magic; uint32_t len; uint8_t *buf; };">${esc(draft || TYPE_PRESETS.node)}</textarea>
                ${renderOverlayHtml(overlay, curVa)}
              </div>
              <div class="pro-side">${listHtml}</div>
            </div>
          </div>`;

        const ed = container.querySelector('#tp-ed');
        container.querySelectorAll('[data-tp]').forEach((b) => {
            b.onclick = () => { ed.value = TYPE_PRESETS[b.dataset.tp] || ''; hooks.onDraft(ed.value); };
        });
        ed.oninput = () => hooks.onDraft(ed.value);
        container.querySelector('#tp-add').onclick = () => hooks.onAdd(ed.value);
        container.querySelector('#tp-hdr').onclick = () => hooks.onLoadHeader();
        container.querySelectorAll('[data-stdlib]').forEach((b) => {
            b.onclick = () => hooks.onLoadStdlib(b.dataset.stdlib);
        });
        container.querySelector('#tp-pdb').onclick = () => hooks.onLoadPdbMsf();
        container.querySelector('#tp-dwarf').onclick = () => hooks.onLoadDwarf();
        container.querySelectorAll('[data-apply-st]').forEach((b) => {
            b.onclick = () => hooks.onApplyStruct(b.dataset.applySt, curVa);
        });

        const ovClose = container.querySelector('#ovl-close');
        if (ovClose) ovClose.onclick = () => hooks.onCloseOverlay();
        const ovVa = container.querySelector('#ovl-va');
        const ovRef = container.querySelector('#ovl-ref');
        if (ovVa && ovRef && overlay && overlay.ok) {
            const doRef = () => hooks.onApplyStruct(overlay.name, ovVa.value.trim() || curVa);
            ovRef.onclick = doRef;
            ovVa.onkeydown = (e) => { if (e.key === 'Enter') doRef(); };
        }
        container.querySelectorAll('[data-ovl-follow]').forEach((el) => {
            el.ondblclick = (e) => {
                e.stopPropagation();
                if (e.shiftKey) hooks.onJump(el.dataset.ovlFollow);
                else if (overlay && overlay.ok) hooks.onApplyStruct(overlay.name, el.dataset.ovlFollow);
            };
        });
        container.querySelectorAll('[data-ovl-jump]').forEach((el) => {
            el.onclick = (e) => { e.stopPropagation(); hooks.onJump(el.dataset.ovlJump); };
        });
    }

    function fmtSize(n) {
        const v = Number(n || 0);
        if (v >= 1048576) return (v / 1048576).toFixed(1) + ' MB';
        if (v >= 1024) return (v / 1024).toFixed(0) + ' KB';
        return v + ' B';
    }

    function permBadge(perm) {
        const p = Number(perm || 0);
        const s = `${p & 1 ? 'R' : '-'}${p & 2 ? 'W' : '-'}${p & 4 ? 'X' : '-'}`;
        const cls = (p & 6) === 6 ? ' dbg-perm-rwx' : (p & 4) ? ' dbg-perm-x' : '';
        return `<span class="dbg-perm${cls}">${s}</span>`;
    }

    function hwbpKindLabel(k) {
        if (k === 0) return 'EXEC';
        if (k === 1) return 'WRITE';
        if (k === 3) return 'R/W';
        return 'K' + k;
    }

    function dmpArchLabel(a) {
        if (a === 9) return 'x86-64';
        if (a === 0) return 'x86';
        if (a === 12) return 'ARM64';
        return 'arch ' + a;
    }

    function excCodeHint(code) {
        const lo = String(code || '').toLowerCase();
        if (lo === '0xc0000005') return 'ACCESS_VIOLATION';
        if (lo === '0xc0000094') return 'INT_DIVIDE_BY_ZERO';
        if (lo === '0xc000001d') return 'ILLEGAL_INSTRUCTION';
        if (lo === '0xc00000fd') return 'STACK_OVERFLOW';
        if (lo === '0xc0000409') return 'STACK_BUFFER_OVERRUN';
        if (lo === '0x80000003') return 'BREAKPOINT';
        if (lo === '0x80000004') return 'SINGLE_STEP';
        return '';
    }

    function renderDebugLocal(bundle, curVa, hooks) {
        const dbg = bundle.dbg;
        const prevSnap = bundle.prevSnap;
        const mods = bundle.mods;
        const threads = bundle.threads;
        const bt = bundle.bt;
        const mmap = bundle.mmap;
        const who = bundle.who;
        const sideTab = bundle.sideTab || 'stack';
        const attached = !!(dbg && dbg.attached);
        const sn = dbg && dbg.snap ? dbg.snap : null;
        const nsnap = (dbg && dbg.nsnap) ? dbg.nsnap : 0;
        const curIdx = (dbg && typeof dbg.cur === 'number') ? dbg.cur : Math.max(0, nsnap - 1);
        const nttd = (dbg && dbg.nttd) ? dbg.nttd : 0;
        const ttdCur = (dbg && typeof dbg.ttd_cur === 'number') ? dbg.ttd_cur : 0;
        const canBack = attached || nttd > 0 || nsnap > 1;
        const canWho = attached || nttd > 0;
        const canSync = !!(sn && sn.rip && hooks.hasBinary);
        const canDump = attached || !!hooks.canDump;

        const regHtml = sn && sn.regs ? Object.entries(sn.regs).map(([k, v]) => {
            const chg = prevSnap && prevSnap.regs && prevSnap.regs[k] !== v ? ' dbg-chg' : '';
            return `<div class="ins-kv${chg}"><span class="mono">${esc(k)}</span><b class="mono dbg-reg-val" data-reg-edit="${esc(k)}" data-reg-val="${esc(v)}" title="Click or double-click to edit ${esc(k)}" style="cursor:pointer">${esc(v)}</b></div>`;
        }).join('') : '<div class="ins-empty">Not paused on a process yet. Click Launch or Attach.</div>';

        const bps = (dbg && dbg.bps) ? dbg.bps : [];
        const bpHtml = bps.length
            ? bps.map((b) =>
                `<div class="dbg-bp-row">`
                + `<span class="dbg-bp-l"><span class="mono t-sym" data-jump="${esc(b.va)}">${esc(b.va)}</span>`
                + (b.cond ? `<span class="dbg-cond-pill" title="${esc(b.cond)}">${esc(b.cond)}</span>` : '')
                + `</span><button class="mini-btn" data-dbp="${esc(b.va)}">Del</button></div>`
            ).join('')
            : '<div class="ins-empty">No software breakpoints.</div>';

        const activeHw = (dbg && dbg.hwbps) ? dbg.hwbps.filter((h) => h.active) : [];
        const hwHtml = activeHw.length
            ? activeHw.map((h) =>
                `<div class="dbg-bp-row">`
                + `<span class="dbg-bp-l"><span class="meta-chip">DR${h.slot}</span>`
                + `<span class="mono t-sym" data-jump="${esc(h.va)}">${esc(h.va)}</span>`
                + `<span class="prot-badge pk-ctl">${hwbpKindLabel(h.kind)} ${h.size}B</span></span>`
                + `<button class="mini-btn" data-dhwbp="${h.slot}">Del</button></div>`
            ).join('')
            : '<div class="ins-empty">No hardware breakpoints (DR0..DR3).</div>';

        const activeMem = (dbg && dbg.membps) ? dbg.membps.filter((m) => m.active) : [];
        const memHtml = activeMem.length
            ? activeMem.map((m) =>
                `<div class="dbg-bp-row">`
                + `<span class="dbg-bp-l"><span class="mono t-sym" data-jump="${esc(m.va)}">${esc(m.va)}</span>`
                + `<span class="meta-chip">GUARD ${fmtSize(m.size)}</span></span>`
                + `<button class="mini-btn" data-dmembp="${esc(m.va)}">Del</button></div>`
            ).join('')
            : '<div class="ins-empty">No PAGE_GUARD memory breakpoints.</div>';

        const btItems = (bt && bt.ok && bt.items) ? bt.items : [];
        const mmItems = (mmap && mmap.ok && mmap.items) ? mmap.items : [];
        const modItems = (mods && mods.ok && mods.items) ? mods.items : [];
        const thItems = (threads && threads.ok && threads.items) ? threads.items : [];

        let sideHtml = '';
        if (sideTab === 'stack') {
            let stackHtml = '';
            if (sn && sn.stack) {
                const hex = sn.stack;
                for (let off = 0; off < hex.length; off += 16) {
                    const chunk = hex.slice(off, off + 16);
                    let asc = '';
                    for (let i = 0; i < chunk.length; i += 2) {
                        const b = parseInt(chunk.slice(i, i + 2), 16);
                        asc += (b >= 0x20 && b <= 0x7E) ? esc(String.fromCharCode(b)) : '.';
                    }
                    stackHtml += `<div class="ins-kv"><span class="mono">+0x${(off / 2).toString(16).padStart(2, '0')}</span><b class="mono">${chunk.replace(/(..)/g, '$1 ').trim()}</b><span class="mono t-str">${asc}</span></div>`;
                }
            }
            const thHtml = thItems.length
                ? thItems.map((t) =>
                    `<div class="dbg-tbl-row"><span class="mono">TID ${t.tid}</span>`
                    + `<button class="cap-pill" data-jump="${esc(t.start)}">${esc(t.start)}</button></div>`
                ).join('')
                : '<div class="ins-empty">No active threads.</div>';
            sideHtml = `
              <div class="ins-title">Stack snapshot (64B @ RSP)</div>
              ${stackHtml || '<div class="ins-empty">No stack frame captured.</div>'}
              <div class="ins-title" style="margin-top:10px">Threads (${thItems.length})</div>
              <div class="ov-table">${thHtml}</div>`;
        } else if (sideTab === 'bt') {
            sideHtml = btItems.length
                ? `<div class="ov-table">${btItems.map((f, i) =>
                    `<div class="dbg-tbl-row">`
                    + `<span class="mono prot-muted" style="width:28px">#${i}</span>`
                    + `<button class="cap-pill" data-jump="${esc(f.rip)}" title="Jump to frame RIP">${esc(f.rip)}</button>`
                    + `<span class="mono prot-muted">sp ${esc(f.sp)}</span>`
                    + `<span class="mono t-sym prot-push">${esc(f.mod || '—')}</span></div>`
                ).join('')}</div>`
                : '<div class="ins-empty">No call stack frames captured. Pause on a target to unwind stack.</div>';
        } else if (sideTab === 'mmap') {
            sideHtml = mmItems.length
                ? `<div class="ov-table">${mmItems.map((r) =>
                    `<div class="dbg-tbl-row">`
                    + `<button class="cap-pill" data-jump="${esc(r.base)}">${esc(r.base)}</button>`
                    + `<span class="mono" style="width:70px;text-align:right;color:var(--fg-soft)">${fmtSize(r.size)}</span>`
                    + permBadge(r.perm)
                    + `<span class="meta-chip">${esc(r.type || 'MEM')}</span>`
                    + `<span class="mono t-sym prot-push" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.mod || '')}</span></div>`
                ).join('')}</div>`
                : '<div class="ins-empty">No committed memory regions enumerated.</div>';
        } else {
            sideHtml = modItems.length
                ? `<div class="ov-table">${modItems.map((m) =>
                    `<div class="dbg-tbl-row">`
                    + `<span class="mono t-sym" style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(m.name)}</span>`
                    + `<button class="cap-pill" data-jump="${esc(m.base)}">${esc(m.base)}</button>`
                    + `<span class="mono prot-muted" style="width:68px;text-align:right">${fmtSize(m.size)}</span></div>`
                ).join('')}</div>`
                : '<div class="ins-empty">No live modules enumerated.</div>';
        }

        let whoHtml = '';
        if (who && who.res) {
            whoHtml = who.res.ok
                ? `<span class="meta-chip">Who Wrote (<b>${esc(who.query)}</b>): #${who.res.idx} @ <button class="cap-pill" data-jump="${esc(who.res.rip)}">${esc(who.res.rip)}</button> <span class="mono">${esc(who.res.old)} → ${esc(who.res.new)}</span></span>`
                : `<span class="meta-chip" style="color:var(--tok-ret)">Who Wrote (<b>${esc(who.query)}</b>): no write in TTD</span>`;
        }

        const ttdBanner = (nsnap > 0 || nttd > 0 || whoHtml) ? `
          <div class="dbg-ttd-bar">
            ${nsnap > 0 ? `<span>Snap <b>${curIdx + 1}/${nsnap}</b></span><input id="dbg-scrub" type="range" min="0" max="${Math.max(0, nsnap - 1)}" value="${curIdx}" style="flex:1;min-width:110px;max-width:240px">` : ''}
            <span class="meta-chip">TTD: <b>${nttd}</b> steps${nttd > 0 ? ` (#${ttdCur})` : ''}</span>
            ${sn ? `<span class="mono">${esc(sn.event || '')}</span><button class="cap-pill" data-jump="${esc(sn.rip)}">${esc(sn.rip)}</button>` : ''}
            ${whoHtml}
          </div>` : '';

        return `
          <div class="dbg-bar">
            <button class="tb-btn hi" id="dbg-launch">Launch</button>
            <button class="tb-btn" id="dbg-attach">Attach</button>
            <span class="dbg-sep"></span>
            <button class="tb-btn" id="dbg-step"${attached ? '' : ' disabled'}>Step (F7)</button>
            <button class="tb-btn" id="dbg-over"${attached ? '' : ' disabled'}>Over (F8)</button>
            <button class="tb-btn" id="dbg-out"${attached ? '' : ' disabled'} title="Step Out (Shift+F8)">Out</button>
            <button class="tb-btn" id="dbg-cont"${attached ? '' : ' disabled'}>Cont (F9)</button>
            <button class="tb-btn" id="dbg-pause"${attached ? '' : ' disabled'} title="Pause running process">Pause</button>
            <span class="dbg-sep"></span>
            <button class="tb-btn" id="dbg-ttd-rec"${attached ? '' : ' disabled'} title="Record delta time-travel steps">TTD Rec</button>
            <button class="tb-btn" id="dbg-ttd-back"${canBack ? '' : ' disabled'}>Back (Shift+F7)</button>
            <button class="tb-btn" id="dbg-ttd-who"${canWho ? '' : ' disabled'}>Who Wrote?</button>
            <span class="dbg-sep"></span>
            <button class="tb-btn" id="dbg-bp" title="Software BP @ ${esc(curVa)}">BP</button>
            <button class="tb-btn" id="dbg-condbp" title="Conditional Software BP">Cond BP</button>
            <button class="tb-btn" id="dbg-hwbp" title="Hardware BP (DR0..DR3)">HW BP</button>
            <button class="tb-btn" id="dbg-membp" title="Memory Guard BP (PAGE_GUARD)">Mem BP</button>
            <span class="dbg-sep"></span>
            <button class="tb-btn" id="dbg-sync"${canSync ? '' : ' disabled'}>Sync @ RIP</button>
            <button class="tb-btn" id="dbg-dump"${canDump ? '' : ' disabled'} title="Dump and rebuild PE image">Dump PE…</button>
            <button class="tb-btn" id="dbg-detach"${attached ? '' : ' disabled'}>Detach</button>
            <button class="tb-btn" id="dbg-kill"${attached ? '' : ' disabled'}>Kill</button>
          </div>
          ${ttdBanner}
          ${dbg && dbg.err ? `<div class="dbg-err">${esc(dbg.err)}</div>` : ''}
          <div class="dbg-local-grid">
            <div class="dbg-col">
              <div class="ins-title"><span>Registers</span>${sn ? `<span class="mono dbg-reg-val" data-reg-edit="rflags" data-reg-val="${esc(sn.rflags)}" title="Click or double-click to edit rflags" style="cursor:pointer">RFLAGS ${esc(sn.rflags)}</span>` : '<span class="mono"></span>'}</div>
              ${sn ? `<div class="ins-kv"><span class="mono">rip</span><span style="display:flex;gap:4px;align-items:center"><button class="cap-pill" data-jump="${esc(sn.rip)}">${esc(sn.rip)}</button><button class="mini-btn" data-reg-edit="rip" data-reg-val="${esc(sn.rip)}" title="Modify RIP register">Edit</button></span></div>` : ''}
              ${regHtml}
              <div class="ins-title" style="margin-top:10px">Software BPs (${bps.length})</div>
              ${bpHtml}
              <div class="ins-title" style="margin-top:10px">Hardware BPs (${activeHw.length}/4)</div>
              ${hwHtml}
              <div class="ins-title" style="margin-top:10px">Memory BPs (${activeMem.length})</div>
              ${memHtml}
            </div>
            <div class="dbg-side-pane">
              <div class="dbg-subtabs">
                <button class="mini-btn${sideTab === 'stack' ? ' hi' : ''}" data-dbgside="stack">Stack</button>
                <button class="mini-btn${sideTab === 'bt' ? ' hi' : ''}" data-dbgside="bt">Backtrace (${btItems.length})</button>
                <button class="mini-btn${sideTab === 'mmap' ? ' hi' : ''}" data-dbgside="mmap">Memory Map (${mmItems.length})</button>
                <button class="mini-btn${sideTab === 'mods' ? ' hi' : ''}" data-dbgside="mods">Modules (${modItems.length})</button>
                <span style="flex:1"></span>
                <button class="mini-btn" id="dbg-side-ref"${attached ? '' : ' disabled'}>Refresh</button>
              </div>
              <div class="dbg-subbody">${sideHtml}</div>
            </div>
          </div>`;
    }

    function renderDebugGdb(bundle) {
        const gdb = bundle.gdb;
        const prev = bundle.gdbPrev;
        const connected = !!(gdb && gdb.connected);
        const host = bundle.gdbHost || '127.0.0.1';
        const port = bundle.gdbPort || '1234';
        const gdbBps = bundle.gdbBps || [];

        const regCards = (gdb && gdb.regs && connected)
            ? Object.entries(gdb.regs).map(([k, v]) => {
                const chg = prev && prev.regs && prev.regs[k] !== v ? ' dbg-chg' : '';
                return `<div class="gdb-reg-card${chg}"><span class="t-reg">${k}</span><b>${esc(v)}</b></div>`;
            }).join('')
            : '<div class="ins-empty" style="padding:12px">Connect to a GDB RSP stub (qemu -s, gdbserver, OpenOCD, or WinDbg stub) to inspect live registers.</div>';

        const bpRows = gdbBps.length
            ? gdbBps.map((b, idx) =>
                `<div class="dbg-bp-row">`
                + `<span class="dbg-bp-l"><span class="prot-badge ${b.hw ? 'pk-ctl' : 'pk-mem'}">${b.hw ? 'HW' : 'SW'}</span>`
                + `<span class="mono t-sym" data-jump="${esc(b.va)}">${esc(b.va)}</span></span>`
                + `<button class="mini-btn" data-gdbdel="${idx}">Del</button></div>`
            ).join('')
            : '<div class="ins-empty">No remote breakpoints set in this session.</div>';

        return `
          <div class="dbg-bar">
            <span>Host</span>
            <input id="gdb-host" class="dbg-in" style="width:132px" value="${esc(host)}" placeholder="127.0.0.1" spellcheck="false">
            <span>Port</span>
            <input id="gdb-port" class="dbg-in" style="width:70px" value="${esc(port)}" placeholder="1234" spellcheck="false">
            <button class="tb-btn hi" id="gdb-connect">Connect</button>
            <span class="dbg-sep"></span>
            <button class="tb-btn" id="gdb-step"${connected ? '' : ' disabled'}>Step</button>
            <button class="tb-btn" id="gdb-cont"${connected ? '' : ' disabled'}>Continue</button>
            <button class="tb-btn" id="gdb-swbp"${connected ? '' : ' disabled'}>SW BP</button>
            <button class="tb-btn" id="gdb-hwbp"${connected ? '' : ' disabled'}>HW BP</button>
            <span class="dbg-sep"></span>
            <button class="tb-btn" id="gdb-disc"${connected ? '' : ' disabled'}>Disconnect</button>
          </div>
          ${gdb && gdb.err ? `<div class="dbg-err">${esc(gdb.err)}</div>` : ''}
          <div class="prot-chips">
            <span class="prot-pill ${connected ? 'tone-ok' : 'pk-def'}">${connected ? 'CONNECTED' : 'DISCONNECTED'}</span>
            <span class="meta-chip">RIP: ${connected && gdb.rip ? `<button class="cap-pill" data-jump="${esc(gdb.rip)}">${esc(gdb.rip)}</button>` : '<b>—</b>'}</span>
            <span class="meta-chip">RFLAGS: <b>${connected ? esc(gdb.rflags) : '—'}</b></span>
            <span class="meta-chip">Stop: <b>${connected && gdb.stop ? esc(gdb.stop) : '—'}</b></span>
          </div>
          <div class="gdb-grid">
            <div style="overflow-y:auto"><div class="gdb-regs">${regCards}</div></div>
            <div class="dbg-col">
              <div class="ins-title">Remote Breakpoints (${gdbBps.length})</div>
              ${bpRows}
            </div>
          </div>`;
    }

    function renderDebugDmp(bundle) {
        const dmp = bundle.dmp;
        const loaded = !!(dmp && dmp.loaded);
        const baseName = (loaded && dmp.path) ? dmp.path.split(/[\\/]/).pop() : '';
        const threads = (loaded && dmp.threads) ? dmp.threads : [];
        const mods = (loaded && dmp.mods) ? dmp.mods : [];
        const selTid = bundle.dmpSelTid !== null && bundle.dmpSelTid !== undefined
            ? bundle.dmpSelTid
            : (loaded && threads.length ? (threads.find((t) => t.tid === dmp.exc_tid) || threads[0]).tid : null);
        const selTh = threads.find((t) => t.tid === selTid) || threads[0] || null;
        const hint = loaded ? excCodeHint(dmp.exc_code) : '';

        let bodyHtml = '<div class="welcome"><p>Open a Windows crash dump (.dmp) to inspect OS info, faulting exception address, thread contexts, and loaded modules.</p></div>';
        if (loaded) {
            const thHtml = threads.length
                ? threads.map((t) => {
                    const isFault = t.tid === dmp.exc_tid;
                    const cur = selTh && t.tid === selTh.tid ? ' cur' : '';
                    return `<div class="dmp-th-row${cur}" data-dmptid="${t.tid}">`
                        + `<span class="mono">TID ${t.tid}${isFault ? ' <span class="dmp-fault">FAULT</span>' : ''}</span>`
                        + `<span class="mono prot-muted">${esc(t.rip)}</span></div>`;
                }).join('')
                : '<div class="ins-empty" style="padding:10px">No thread contexts in minidump.</div>';

            const regHtml = selTh && selTh.regs
                ? `<div class="ins-kv"><span class="mono">rip</span><button class="cap-pill" data-jump="${esc(selTh.rip)}">${esc(selTh.rip)}</button></div>`
                  + `<div class="ins-kv"><span class="mono">rsp</span><b class="mono">${esc(selTh.rsp)}</b></div>`
                  + `<div class="ins-kv"><span class="mono">rflags</span><b class="mono">${esc(selTh.rflags)}</b></div>`
                  + Object.entries(selTh.regs).map(([k, v]) =>
                      `<div class="ins-kv"><span class="mono">${k}</span><b class="mono">${esc(v)}</b></div>`
                  ).join('')
                : '<div class="ins-empty">Select a thread to inspect its 16 registers.</div>';

            const modHtml = mods.length
                ? `<div class="ov-table">${mods.map((m) =>
                    `<div class="dbg-tbl-row">`
                    + `<span class="mono t-sym" style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(m.name)}</span>`
                    + `<button class="cap-pill" data-jump="${esc(m.base)}">${esc(m.base)}</button>`
                    + `<span class="mono prot-muted" style="width:68px;text-align:right">${fmtSize(m.size)}</span></div>`
                ).join('')}</div>`
                : '<div class="ins-empty">No modules recorded in minidump.</div>';

            bodyHtml = `
              <div class="prot-chips">
                <span class="meta-chip">OS: <b>Windows ${esc(dmp.os)}</b></span>
                <span class="meta-chip">CPUs: <b>${dmp.ncpu}</b></span>
                <span class="meta-chip">Arch: <b>${dmpArchLabel(dmp.arch)}</b></span>
                <span class="prot-pill tone-hi">${esc(dmp.exc_code)}${hint ? ' · ' + hint : ''}</span>
                <span class="meta-chip">Fault VA: <button class="cap-pill" data-jump="${esc(dmp.exc_addr)}">${esc(dmp.exc_addr)}</button></span>
                <span class="meta-chip">Fault TID: <b>${dmp.exc_tid}</b></span>
                <span class="meta-chip">Mem Ranges: <b>${dmp.nmem}</b></span>
              </div>
              <div class="dmp-grid">
                <div class="dbg-col" style="padding:0">
                  <div class="pane-head"><span>Threads (${threads.length})</span><span class="pane-meta">click to inspect</span></div>
                  <div style="flex:1;overflow-y:auto">${thHtml}</div>
                </div>
                <div class="dbg-col">
                  <div class="ins-title"><span>Registers</span><span class="mono">${selTh ? 'TID ' + selTh.tid : ''}</span></div>
                  ${regHtml}
                </div>
                <div class="dbg-col">
                  <div class="ins-title">Modules (${mods.length})</div>
                  ${modHtml}
                </div>
              </div>`;
        }

        return `
          <div class="dbg-bar">
            <button class="tb-btn hi" id="dmp-open">Open .dmp…</button>
            <span class="mono">${loaded ? esc(baseName) : 'No crash dump loaded'}</span>
          </div>
          ${dmp && !loaded && dmp.err ? `<div class="dbg-err">${esc(dmp.err)}</div>` : ''}
          ${bodyHtml}`;
    }

    function renderDebug(container, bundle, curVa, hooks) {
        const b = bundle || {};
        const tab = b.tab || 'local';
        const dbg = b.dbg;
        const gdb = b.gdb;
        const dmp = b.dmp;

        let statusText = 'IDLE';
        if (tab === 'local') {
            statusText = dbg && dbg.attached ? `PID ${dbg.pid} · ${dbg.paused ? 'PAUSED' : 'RUNNING'}` : 'IDLE';
        } else if (tab === 'gdb') {
            statusText = gdb && gdb.connected ? `GDB ${gdb.host}:${gdb.port}` : 'DISCONNECTED';
        } else {
            statusText = dmp && dmp.loaded ? `${(dmp.threads || []).length} threads · ${(dmp.mods || []).length} mods` : 'NO DUMP';
        }

        const inner = tab === 'gdb'
            ? renderDebugGdb(b)
            : (tab === 'dmp' ? renderDebugDmp(b) : renderDebugLocal(b, curVa, hooks));

        container.innerHTML = `
          <div class="ir-wrap">
            <div class="dob-bar">
              <button class="tb-btn${tab === 'local' ? ' hi' : ''}" data-dbgtab="local">Local Win32</button>
              <button class="tb-btn${tab === 'gdb' ? ' hi' : ''}" data-dbgtab="gdb">Remote GDB</button>
              <button class="tb-btn${tab === 'dmp' ? ' hi' : ''}" data-dbgtab="dmp">Crash Dump (.dmp)</button>
              <span style="flex:1"></span>
              <span class="mono">${esc(statusText)}</span>
            </div>
            ${inner}
          </div>`;

        container.querySelectorAll('[data-dbgtab]').forEach((btn) => {
            btn.onclick = () => hooks.onTab(btn.dataset.dbgtab);
        });
        container.querySelectorAll('[data-jump]').forEach((el) => {
            el.onclick = (e) => { e.stopPropagation(); if (hooks.onJump) hooks.onJump(el.dataset.jump); };
        });

        if (tab === 'local') {
            container.querySelector('#dbg-launch').onclick = hooks.onLaunch;
            container.querySelector('#dbg-attach').onclick = hooks.onAttach;
            container.querySelector('#dbg-step').onclick = hooks.onStep;
            container.querySelector('#dbg-over').onclick = hooks.onStepOver;
            container.querySelector('#dbg-out').onclick = hooks.onStepOut;
            container.querySelector('#dbg-cont').onclick = hooks.onCont;
            const pauseBtn = container.querySelector('#dbg-pause');
            if (pauseBtn && hooks.onPause) pauseBtn.addEventListener('click', hooks.onPause);
            container.querySelectorAll('[data-reg-edit]').forEach((el) => {
                const trigger = (e) => {
                    e.stopPropagation();
                    if (hooks.onSetReg) hooks.onSetReg(el.dataset.regEdit, el.dataset.regVal || '0x0');
                };
                el.addEventListener('click', trigger);
                el.addEventListener('dblclick', trigger);
            });
            container.querySelector('#dbg-ttd-rec').onclick = hooks.onTtdRec;
            container.querySelector('#dbg-ttd-back').onclick = hooks.onTtdBack;
            container.querySelector('#dbg-ttd-who').onclick = hooks.onTtdWho;
            container.querySelector('#dbg-bp').onclick = () => hooks.onBp(curVa, 0);
            container.querySelector('#dbg-condbp').onclick = hooks.onCondBp;
            container.querySelector('#dbg-hwbp').onclick = hooks.onHwBp;
            container.querySelector('#dbg-membp').onclick = hooks.onMemBp;
            container.querySelector('#dbg-sync').onclick = hooks.onSyncRip;
            container.querySelector('#dbg-dump').onclick = hooks.onDumpPe;
            container.querySelector('#dbg-detach').onclick = hooks.onDetach;
            container.querySelector('#dbg-kill').onclick = hooks.onKill;
            const sc = container.querySelector('#dbg-scrub');
            if (sc) sc.oninput = (e) => hooks.onScrub(Number(e.target.value));
            container.querySelectorAll('[data-dbp]').forEach((el) => { el.onclick = () => hooks.onBp(el.dataset.dbp, 1); });
            container.querySelectorAll('[data-dhwbp]').forEach((el) => { el.onclick = () => hooks.onDelHwBp(Number(el.dataset.dhwbp)); });
            container.querySelectorAll('[data-dmembp]').forEach((el) => { el.onclick = () => hooks.onDelMemBp(el.dataset.dmembp); });
            container.querySelectorAll('[data-dbgside]').forEach((el) => { el.onclick = () => hooks.onSideTab(el.dataset.dbgside); });
            const ref = container.querySelector('#dbg-side-ref');
            if (ref) ref.onclick = hooks.onRefreshSide;
        } else if (tab === 'gdb') {
            const hostIn = container.querySelector('#gdb-host');
            const portIn = container.querySelector('#gdb-port');
            hostIn.oninput = () => hooks.onGdbDraft(hostIn.value, portIn.value);
            portIn.oninput = () => hooks.onGdbDraft(hostIn.value, portIn.value);
            const doConn = () => hooks.onGdbConnect(hostIn.value.trim(), parseInt(portIn.value, 10) || 1234);
            container.querySelector('#gdb-connect').onclick = doConn;
            portIn.onkeydown = (e) => { if (e.key === 'Enter') doConn(); };
            container.querySelector('#gdb-step').onclick = hooks.onGdbStep;
            container.querySelector('#gdb-cont').onclick = hooks.onGdbCont;
            container.querySelector('#gdb-swbp').onclick = () => hooks.onGdbBp(0);
            container.querySelector('#gdb-hwbp').onclick = () => hooks.onGdbBp(1);
            container.querySelector('#gdb-disc').onclick = hooks.onGdbDisconnect;
            container.querySelectorAll('[data-gdbdel]').forEach((el) => {
                el.onclick = () => hooks.onGdbDelBp(Number(el.dataset.gdbdel));
            });
        } else {
            container.querySelector('#dmp-open').onclick = hooks.onDmpOpen;
            container.querySelectorAll('[data-dmptid]').forEach((el) => {
                el.onclick = () => hooks.onDmpSelectThread(Number(el.dataset.dmptid));
            });
        }
    }

    function renderXGraphSvg(container, xg, hooks) {
        if (!xg || !xg.ok || !xg.nodes || !xg.nodes.length) {
            container.innerHTML = '<div class="welcome"><p>No multi-hop xrefs found around this address.</p></div>';
            return;
        }
        const byDepth = new Map();
        xg.nodes.forEach((n, idx) => {
            const d = n.depth || 0;
            if (!byDepth.has(d)) byDepth.set(d, []);
            byDepth.get(d).push({ ...n, idx });
        });
        const depths = [...byDepth.keys()].sort((a, b) => a - b);
        const nw = 196, nh = 32, colGap = 250, rowGap = 44;
        const pos = new Array(xg.nodes.length);
        let maxRows = 1;
        depths.forEach((d, ci) => {
            const list = byDepth.get(d);
            maxRows = Math.max(maxRows, list.length);
            list.forEach((n, ri) => {
                pos[n.idx] = { x: 24 + ci * colGap, y: 28 + ri * rowGap };
            });
        });
        const totalW = Math.max(640, depths.length * colGap + 40);
        const totalH = Math.max(260, maxRows * rowGap + 56);

        const edgeSvg = (xg.edges || []).map((e) => {
            const a = pos[e.from], b = pos[e.to];
            if (!a || !b) return '';
            const sx = a.x + nw, sy = a.y + nh / 2, ex = b.x, ey = b.y + nh / 2, mx = (sx + ex) / 2;
            const cls = e.type === 1 ? 'e-t' : 'e-u';
            return `<path class="cfg-edge ${cls}" d="M ${sx} ${sy} C ${mx} ${sy}, ${mx} ${ey}, ${ex} ${ey}" marker-end="url(#xg-arr)"/>`;
        }).join('');

        const nodeSvg = xg.nodes.map((n, idx) => {
            const p = pos[idx];
            const cls = n.depth === 0 ? 'cg-center' : n.depth < 0 ? 'cg-in' : 'cg-out';
            const lbl = (n.name || n.va).slice(0, 24);
            return `<g class="cg-node ${cls}" data-va="${n.va}"><rect x="${p.x}" y="${p.y}" width="${nw}" height="${nh}" rx="5"/><text x="${p.x + 9}" y="${p.y + 20}">${esc(lbl)}</text></g>`;
        }).join('');

        container.innerHTML = `<div class="cg-wrap"><svg id="xg-svg" width="${totalW}" height="${totalH}" class="cg-svg">`
            + `<defs><marker id="xg-arr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,1 L9,5 L0,9 z" fill="var(--edge-u)"/></marker></defs>`
            + `${edgeSvg}${nodeSvg}</svg></div>`;

        container.querySelectorAll('.cg-node').forEach((el) => {
            el.onclick = () => hooks.onJump(el.dataset.va);
            el.onmouseenter = (e) => hooks.onPeek(el.dataset.va, e);
            el.onmouseleave = hooks.onHidePeek;
        });
    }

    function renderCallsHub(container, sub, cg, xg, pathSt, curVa, hooks) {
        container.innerHTML = `
          <div class="dob-bar">
            <button class="tb-btn${sub === 'calls' ? ' hi' : ''}" data-csub="calls">Call Graph</button>
            <button class="tb-btn${sub === 'xgraph' ? ' hi' : ''}" data-csub="xgraph">Xrefs Graph (2-hop)</button>
            <button class="tb-btn${sub === 'path' ? ' hi' : ''}" data-csub="path">Pathfinder</button>
            <span style="flex:1"></span>
            ${sub !== 'path' ? '<button class="tb-btn" id="cg-exp-svg">Export SVG…</button>' : ''}
          </div>
          <div id="cg-slot" style="flex:1;overflow:auto"></div>`;

        container.querySelectorAll('[data-csub]').forEach((b) => { b.onclick = () => hooks.onSub(b.dataset.csub); });
        const slot = container.querySelector('#cg-slot');

        if (sub === 'calls') {
            window.cfgView.renderCallGraph(slot, cg, hooks);
        } else if (sub === 'xgraph') {
            renderXGraphSvg(slot, xg, hooks);
        } else {
            const stepsHtml = (pathSt && pathSt.res && pathSt.res.ok && pathSt.res.steps)
                ? `<div class="pf-chain">${pathSt.res.steps.map((s, i) =>
                    `<button class="cap-pill" data-va="${s.va}">${i + 1}. ${esc(s.name || s.va)} (${s.va.slice(-8)})</button>`
                  ).join('<span class="pf-arr">→</span>')}</div>`
                : (pathSt && pathSt.res && !pathSt.res.ok ? `<div class="ins-empty">${esc(pathSt.res.err || 'No call path found')}</div>` : '<div class="ins-empty">Enter source and destination symbols or hex VAs to find the shortest call path.</div>');

            slot.innerHTML = `
              <div class="ov-wrap">
                <div class="pf-form">
                  <input id="pf-from" class="modal-input" placeholder="From VA or symbol" value="${esc(pathSt.from || curVa)}">
                  <span style="color:var(--fg-muted)">→</span>
                  <input id="pf-to" class="modal-input" placeholder="To VA or symbol (e.g. CreateFileW)" value="${esc(pathSt.to || '')}">
                  <button class="tb-btn hi" id="pf-go">Find Path</button>
                </div>
                ${stepsHtml}
              </div>`;

            slot.querySelector('#pf-go').onclick = () => {
                hooks.onPath(slot.querySelector('#pf-from').value.trim(), slot.querySelector('#pf-to').value.trim());
            };
            slot.querySelectorAll('[data-va]').forEach((b) => { b.onclick = () => hooks.onJump(b.dataset.va); });
        }

        const expBtn = container.querySelector('#cg-exp-svg');
        if (expBtn) expBtn.onclick = () => exportSvgMarkup(slot.querySelector('svg'), sub + '.svg');
    }

    function renderCffGraphSvg(cff, curVa) {
        const edges = (cff && cff.ok && cff.edges) ? cff.edges : [];
        if (!edges.length) {
            return '<div class="ins-empty" style="padding:14px">No recovered real-block edges to graph.</div>';
        }
        const adj = new Map();
        const inDeg = new Map();
        const order = [];
        const addNode = (va) => {
            if (!va || adj.has(va)) return;
            adj.set(va, []);
            inDeg.set(va, 0);
            order.push(va);
        };
        for (const e of edges) {
            addNode(e.from);
            addNode(e.to);
            adj.get(e.from).push(e.to);
            inDeg.set(e.to, (inDeg.get(e.to) || 0) + 1);
        }

        const depth = new Map();
        const bfs = (start) => {
            if (depth.has(start)) return;
            const q = [start];
            depth.set(start, 0);
            while (q.length) {
                const u = q.shift();
                const d = depth.get(u);
                for (const v of (adj.get(u) || [])) {
                    if (!depth.has(v)) {
                        depth.set(v, d + 1);
                        q.push(v);
                    }
                }
            }
        };
        const roots = order.filter((va) => inDeg.get(va) === 0);
        if (cff.func_va && adj.has(cff.func_va) && !roots.includes(cff.func_va)) roots.unshift(cff.func_va);
        for (const r of roots) bfs(r);
        for (const va of order) bfs(va);

        const layers = [];
        for (const va of order) {
            const d = depth.get(va) || 0;
            while (layers.length <= d) layers.push([]);
            layers[d].push(va);
        }

        const nw = 152, nh = 34, colGap = 184, rowGap = 72, padX = 28, padY = 26;
        const maxCols = Math.max(1, ...layers.map((l) => l.length));
        const innerW = (maxCols - 1) * colGap + nw;
        const pos = new Map();
        layers.forEach((list, li) => {
            const rowW = (list.length - 1) * colGap + nw;
            const ox = padX + (innerW - rowW) * 0.5;
            list.forEach((va, ci) => {
                pos.set(va, { x: ox + ci * colGap, y: padY + li * rowGap, layer: li });
            });
        });

        const totalW = Math.max(460, innerW + padX * 2 + 52);
        const totalH = Math.max(220, layers.length * rowGap + padY * 2);
        const curLo = (curVa || '').toLowerCase();
        const fnLo = (cff.func_va || '').toLowerCase();
        let backIdx = 0;

        const edgeSvg = edges.map((e) => {
            const a = pos.get(e.from), b = pos.get(e.to);
            if (!a || !b) return '';
            const cls = e.kind === 1 ? 'e-t' : e.kind === 2 ? 'e-f' : 'e-u';
            const mk = e.kind === 1 ? 'cff-arr-t' : e.kind === 2 ? 'cff-arr-f' : 'cff-arr-u';
            const kLbl = e.kind === 1 ? 'TRUE' : e.kind === 2 ? 'FALSE' : 'UNCOND';
            const sx = a.x + (e.kind === 1 ? nw * 0.68 : e.kind === 2 ? nw * 0.32 : nw * 0.5);
            const sy = a.y + nh;
            const ex = b.x + nw * 0.5;
            const ey = b.y;
            const isBack = b.layer <= a.layer;
            let d;
            if (!isBack) {
                const my = (sy + ey) * 0.5;
                d = `M ${sx} ${sy} C ${sx} ${my}, ${ex} ${my}, ${ex} ${ey}`;
            } else {
                const side = Math.max(a.x, b.x) + nw + 18 + (backIdx++ % 4) * 10;
                d = `M ${sx} ${sy} L ${sx} ${sy + 10} L ${side} ${sy + 10} L ${side} ${ey - 12} L ${ex} ${ey - 12} L ${ex} ${ey}`;
            }
            return `<path class="cfg-edge ${cls}${isBack ? ' back' : ''}" d="${d}" marker-end="url(#${mk})">`
                + `<title>${esc(e.from)} → ${esc(e.to)} [${kLbl}] state ${esc(e.state)}</title></path>`;
        }).join('');

        const nodeSvg = order.map((va) => {
            const p = pos.get(va);
            const lo = va.toLowerCase();
            const isHi = lo === curLo || lo === fnLo;
            return `<g class="cg-node${isHi ? ' cg-center' : ''}" data-va="${esc(va)}">`
                + `<rect x="${p.x}" y="${p.y}" width="${nw}" height="${nh}" rx="5"/>`
                + `<text x="${p.x + nw * 0.5}" y="${p.y + 21}" text-anchor="middle">${esc(va)}</text>`
                + `</g>`;
        }).join('');

        return `<div class="cg-wrap"><svg id="cff-svg" width="${totalW}" height="${totalH}" class="cg-svg">`
            + `<defs>`
            + `<marker id="cff-arr-t" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,1 L9,5 L0,9 z" fill="var(--edge-t)"/></marker>`
            + `<marker id="cff-arr-f" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,1 L9,5 L0,9 z" fill="var(--edge-f)"/></marker>`
            + `<marker id="cff-arr-u" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,1 L9,5 L0,9 z" fill="var(--edge-u)"/></marker>`
            + `</defs>`
            + `${edgeSvg}${nodeSvg}</svg></div>`;
    }

    function renderCffTab(cff, curVa) {
        if (!cff || !cff.ok) {
            return '<div class="welcome"><p>Select an executable function to run Control Flow Flattening unflattening.</p></div>';
        }
        const edges = cff.edges || [];
        const dispChip = (cff.disp_va && cff.disp_va !== '0x0')
            ? `<button class="cap-pill" data-jump="${esc(cff.disp_va)}" title="Jump to dispatcher">Dispatcher: ${esc(cff.disp_va)}</button>`
            : '<span class="meta-chip">Dispatcher: <b>—</b></span>';
        const curLo = (curVa || '').toLowerCase();

        const edgeRows = edges.length
            ? edges.map((e) => {
                const kLbl = e.kind === 1 ? 'TRUE' : e.kind === 2 ? 'FALSE' : 'UNCOND';
                const kCls = e.kind === 1 ? 'cff-k-t' : e.kind === 2 ? 'cff-k-f' : 'cff-k-u';
                const cur = e.from && e.from.toLowerCase() === curLo ? ' cur' : '';
                return `<div class="prot-row${cur}" data-va="${esc(e.from)}">`
                    + `<button class="cap-pill" data-jump="${esc(e.from)}" title="Jump to ${esc(e.from)}">${esc(e.from)}</button>`
                    + `<span class="pf-arr">→</span>`
                    + `<button class="cap-pill" data-jump="${esc(e.to)}" title="Jump to ${esc(e.to)}">${esc(e.to)}</button>`
                    + `<span class="prot-badge ${kCls}">${kLbl}</span>`
                    + `<span class="mono prot-muted prot-push">state ${esc(e.state)}</span>`
                    + `</div>`;
            }).join('')
            : '<div class="ins-empty">No recovered control-flow edges for this function.</div>';

        return `
          <div class="prot-chips">
            <span class="prot-pill ${cff.detected ? 'tone-hi' : 'tone-ok'}">${cff.detected ? 'Detected' : 'Not flattened'}</span>
            ${dispChip}
            <span class="meta-chip">State Var: <b>${esc(cff.state || '—')}</b></span>
            <span class="meta-chip">Blocks: <b>${cff.orig_blks} → ${cff.real_blks}</b></span>
            <span class="meta-chip">Backbone Cut: <b>${cff.cut}</b></span>
          </div>
          <div class="pro-split">
            <div class="pro-main">${renderCffGraphSvg(cff, curVa)}</div>
            <div class="pro-side prot-side-wide">
              <div class="ins-title">Recovered Real-Block Edges (${edges.length})</div>
              <div class="prot-list">${edgeRows}</div>
            </div>
          </div>`;
    }

    function renderMbaEvalHtml(ev) {
        if (!ev) return '<span class="prot-muted">Click Simplify or pick a preset</span>';
        if (ev.ok) {
            return `<span class="mba-res-eq">= ${esc(ev.simple)}</span><span class="meta-chip">saved <b>${ev.saved}</b> ops</span>`;
        }
        return `<span class="prot-muted">no reduction (${esc(ev.simple || '')})</span>`;
    }

    function renderMbaTab(mbaScan, mbaExpr, mbaEval, curVa) {
        const expr = mbaExpr !== undefined && mbaExpr !== null ? mbaExpr : '(x ^ y) + 2 * (x & y)';
        const hits = (mbaScan && mbaScan.ok && mbaScan.hits) ? mbaScan.hits : [];
        const curLo = (curVa || '').toLowerCase();

        const hitsHtml = !mbaScan || !mbaScan.ok
            ? '<div class="ins-empty" style="padding:14px">Select an executable function to scan for Mixed Boolean-Arithmetic expressions.</div>'
            : (hits.length
                ? `<div class="ov-table">${hits.map((h) => {
                    const cur = h.va && h.va.toLowerCase() === curLo ? ' cur' : '';
                    return `<div class="prot-row${cur}" data-va="${esc(h.va)}">`
                        + `<button class="cap-pill" data-jump="${esc(h.va)}">${esc(h.va)}</button>`
                        + `<span class="mono prot-expr"><span class="prot-orig">${esc(h.orig)}</span> <span class="pf-arr">→</span> <span class="t-str">${esc(h.simple)}</span></span>`
                        + `<span class="meta-chip">saved <b>${h.saved}</b> ops</span>`
                        + `</div>`;
                }).join('')}</div>`
                : '<div class="ins-empty" style="padding:14px">No MBA patterns detected in current function.</div>');

        return `
          <div class="mba-play">
            <div class="mba-row">
              <span class="mba-lbl">Live MBA Playground</span>
              <input id="mba-in" class="modal-input mba-input" value="${esc(expr)}" placeholder="Enter MBA expression..." spellcheck="false">
              <button class="tb-btn hi" id="mba-go">Simplify</button>
            </div>
            <div class="mba-row mba-sub">
              <div class="mba-presets">
                <span class="prot-muted">Presets:</span>
                <button class="cap-pill" data-mba-preset="(x ^ y) + 2*(x &amp; y)">(x ^ y) + 2*(x &amp; y)</button>
                <button class="cap-pill" data-mba-preset="(x | y) - (x &amp; y)">(x | y) - (x &amp; y)</button>
                <button class="cap-pill" data-mba-preset="~(~x | ~y)">~(~x | ~y)</button>
              </div>
              <div id="mba-out" class="mba-out mono">${renderMbaEvalHtml(mbaEval)}</div>
            </div>
          </div>
          <div class="prot-scroll">
            <div class="ov-wrap">
              <div class="ov-block">
                <div class="ov-h">Scanned Function MBA Hits (${hits.length})</div>
                ${hitsHtml}
              </div>
            </div>
          </div>`;
    }

    function vmKindCls(kind) {
        const k = String(kind || '').toUpperCase();
        if (/XOR|AND|OR|NOT|SHL|SHR|ROL|ROR/.test(k)) return 'pk-bit';
        if (/ADD|SUB|MUL|DIV|NEG|INC|DEC/.test(k)) return 'pk-alu';
        if (/PUSH|POP|LOAD|STORE|MOV|CONST|MEM|REG/.test(k)) return 'pk-mem';
        if (/JMP|JCC|BR|CALL|RET|EXIT|HLT|CMP/.test(k)) return 'pk-ctl';
        return 'pk-def';
    }

    function renderVmTab(vm, curVa) {
        if (!vm || !vm.ok) {
            return '<div class="welcome"><p>Select an executable function to run VM handler lifting and virtual trace folding.</p></div>';
        }
        const handlers = vm.handlers || [];
        const trace = vm.trace || [];
        const curLo = (curVa || '').toLowerCase();

        const dispChip = (vm.disp_va && vm.disp_va !== '0x0')
            ? `<button class="cap-pill" data-jump="${esc(vm.disp_va)}" title="Jump to VM dispatcher">Dispatcher: ${esc(vm.disp_va)}</button>`
            : '<span class="meta-chip">Dispatcher: <b>—</b></span>';
        const tblChip = (vm.table_va && vm.table_va !== '0x0')
            ? `<button class="cap-pill" data-jump="${esc(vm.table_va)}" title="Jump to handler table">Table: ${esc(vm.table_va)}</button>`
            : '<span class="meta-chip">Table: <b>—</b></span>';

        const hRows = handlers.length
            ? handlers.map((h) => {
                const cur = h.va && h.va.toLowerCase() === curLo ? ' cur' : '';
                const opHex = '0x' + Number(h.op || 0).toString(16).padStart(2, '0');
                return `<div class="prot-row vm-h-row${cur}" data-va="${esc(h.va)}">`
                    + `<span class="mono prot-muted vm-op">${opHex}</span>`
                    + `<span class="prot-badge ${vmKindCls(h.kind)}">${esc(h.kind || 'VM_OP')}</span>`
                    + `<button class="cap-pill" data-jump="${esc(h.va)}">${esc(h.va)}</button>`
                    + `<span class="mono prot-muted vm-nins">${h.nins} ins</span>`
                    + `<span class="mono vm-sem">${esc(h.sem || '')}</span>`
                    + `</div>`;
            }).join('')
            : '<div class="ins-empty" style="padding:12px">No VM handler table classified in this function.</div>';

        const tRows = trace.length
            ? trace.map((t, i) => {
                const cur = t.va && t.va.toLowerCase() === curLo ? ' cur' : '';
                return `<div class="prot-row vm-t-row${cur}" data-va="${esc(t.va)}">`
                    + `<span class="dec-ln" style="width:28px;padding-right:6px">${i + 1}</span>`
                    + `<span class="mono prot-muted" style="flex-shrink:0">${esc(t.va ? t.va.slice(-8) : '')}</span>`
                    + `<span class="prot-badge ${vmKindCls(t.op)}">${esc(t.op || '')}</span>`
                    + `<span class="mono vm-det">${esc(t.detail || '')}</span>`
                    + `</div>`;
            }).join('')
            : '<div class="ins-empty">No folded virtual trace steps recovered.</div>';

        return `
          <div class="prot-chips">
            <span class="prot-pill ${vm.detected ? 'tone-hi' : 'tone-ok'}">${vm.detected ? 'Detected' : 'Not virtualized'}</span>
            <span class="meta-chip">Style: <b>${esc(vm.style || '—')}</b></span>
            ${dispChip}
            ${tblChip}
            <span class="meta-chip">VIP: <b>${esc(vm.vip || '—')}</b></span>
            <span class="meta-chip">VSP: <b>${esc(vm.vsp || '—')}</b></span>
          </div>
          <div class="pro-split">
            <div class="pro-main">
              <div class="pane-head"><span>VM Handler Table (${handlers.length})</span><span class="pane-meta">opcode · kind · va · nins · lifted IR</span></div>
              <div class="prot-list">${hRows}</div>
            </div>
            <div class="pro-side prot-side-wide">
              <div class="ins-title">Virtual Trace (${trace.length})</div>
              <div class="prot-list">${tRows}</div>
            </div>
          </div>`;
    }

    function algoCls(algo) {
        const a = String(algo || '').toUpperCase();
        if (a.includes('FNV')) return 'pk-bit';
        if (a.includes('DJB')) return 'pk-alu';
        if (a.includes('ROR')) return 'pk-ctl';
        if (a.includes('CRC')) return 'pk-mem';
        return 'pk-def';
    }

    function renderUnpTab(hashesRes, strsRes, curVa) {
        const hashes = (hashesRes && hashesRes.ok && hashesRes.hits) ? hashesRes.hits : [];
        const strs = (strsRes && strsRes.ok && strsRes.hits) ? strsRes.hits : [];
        const curLo = (curVa || '').toLowerCase();

        const hashRows = hashes.length
            ? hashes.map((h) => {
                const cur = h.va && h.va.toLowerCase() === curLo ? ' cur' : '';
                return `<div class="prot-row${cur}" data-va="${esc(h.va)}">`
                    + `<button class="cap-pill" data-jump="${esc(h.va)}">${esc(h.va)}</button>`
                    + `<span class="mono prot-muted">${esc(h.hash)}</span>`
                    + `<span class="prot-badge ${algoCls(h.algo)}">${esc(h.algo)}</span>`
                    + `<span class="mono t-fn unp-val">${esc(h.api)}</span>`
                    + `</div>`;
            }).join('')
            : '<div class="ins-empty" style="padding:12px">No known API hashes (FNV1a / DJB2 / ROR13 / CRC32 / SDBM) resolved.</div>';

        const strRows = strs.length
            ? strs.map((s) => {
                const cur = s.va && s.va.toLowerCase() === curLo ? ' cur' : '';
                return `<div class="prot-row${cur}" data-va="${esc(s.va)}">`
                    + `<button class="cap-pill" data-jump="${esc(s.va)}">${esc(s.va)}</button>`
                    + `<span class="prot-badge pk-mem">${esc(s.method)}</span>`
                    + `<span class="mono prot-muted">${esc(s.key)}</span>`
                    + `<span class="mono t-str unp-val">"${esc(s.text)}"</span>`
                    + `</div>`;
            }).join('')
            : '<div class="ins-empty" style="padding:12px">No decrypted strings recovered for current function.</div>';

        return `
          <div class="unp-split">
            <div class="unp-col">
              <div class="pane-head">
                <span>Resolved API Hashes (${hashes.length})</span>
                <button class="mini-btn hi" id="unp-apply-h"${hashes.length ? '' : ' disabled'}>Annotate Hashes</button>
              </div>
              <div class="unp-list">${hashRows}</div>
            </div>
            <div class="unp-col">
              <div class="pane-head">
                <span>Decrypted Strings (${strs.length})</span>
                <button class="mini-btn hi" id="unp-apply-s"${strs.length ? '' : ' disabled'}>Annotate Strings</button>
              </div>
              <div class="unp-list">${strRows}</div>
            </div>
          </div>`;
    }

    function renderDeobfLab(container, sub, bundle, curVa, hooks) {
        const mode = sub || 'junk';
        const b = bundle || {};
        let rightHtml = '';
        let bodyHtml = '';

        if (mode === 'junk') {
            bodyHtml = '<div id="dob-junk-slot" class="prot-slot"></div>';
        } else if (mode === 'cff') {
            if (b.cff && b.cff.ok && b.cff.edges && b.cff.edges.length) {
                rightHtml = '<button class="tb-btn" id="cff-exp-svg">Export SVG…</button>';
            }
            bodyHtml = renderCffTab(b.cff, curVa);
        } else if (mode === 'mba') {
            bodyHtml = renderMbaTab(b.mbaScan, b.mbaExpr, b.mbaEval, curVa);
        } else if (mode === 'vm') {
            bodyHtml = renderVmTab(b.vm, curVa);
        } else {
            bodyHtml = renderUnpTab(b.hashes, b.strs, curVa);
        }

        container.innerHTML = `
          <div class="ir-wrap">
            <div class="dob-bar">
              <button class="tb-btn${mode === 'junk' ? ' hi' : ''}" data-dobsub="junk">Junk &amp; Stack</button>
              <button class="tb-btn${mode === 'cff' ? ' hi' : ''}" data-dobsub="cff">CFF Unflatten</button>
              <button class="tb-btn${mode === 'mba' ? ' hi' : ''}" data-dobsub="mba">MBA Simplifier</button>
              <button class="tb-btn${mode === 'vm' ? ' hi' : ''}" data-dobsub="vm">VM Lifter</button>
              <button class="tb-btn${mode === 'unp' ? ' hi' : ''}" data-dobsub="unp">Hashes &amp; Strings</button>
              <span style="flex:1"></span>
              ${rightHtml}
            </div>
            ${bodyHtml}
          </div>`;

        container.querySelectorAll('[data-dobsub]').forEach((btn) => {
            btn.onclick = () => hooks.onSub(btn.dataset.dobsub);
        });

        if (mode === 'junk') {
            window.triView.renderDeobf(container.querySelector('#dob-junk-slot'), b.deobf, curVa, {
                onSelect: hooks.onSelect,
                onTrace: hooks.onTrace
            });
            return;
        }

        container.querySelectorAll('.prot-row[data-va], .cg-node[data-va]').forEach((el) => {
            el.onclick = () => {
                container.querySelectorAll('.prot-row.cur').forEach((r) => r.classList.remove('cur'));
                if (el.classList.contains('prot-row')) el.classList.add('cur');
                hooks.onSelect(el.dataset.va);
            };
            el.ondblclick = () => hooks.onJump(el.dataset.va);
        });
        container.querySelectorAll('[data-jump]').forEach((el) => {
            el.onclick = (e) => { e.stopPropagation(); hooks.onJump(el.dataset.jump); };
        });

        const cffExp = container.querySelector('#cff-exp-svg');
        if (cffExp) cffExp.onclick = () => exportSvgMarkup(container.querySelector('#cff-svg'), 'cff_unflattened.svg');

        const mbaIn = container.querySelector('#mba-in');
        const mbaGo = container.querySelector('#mba-go');
        const mbaOut = container.querySelector('#mba-out');
        if (mbaIn && mbaGo && mbaOut) {
            const runMba = async (exprOverride) => {
                const q = (exprOverride !== undefined ? exprOverride : mbaIn.value).trim();
                if (!q) return;
                hooks.onMbaDraft(q);
                const r = await hooks.onMbaEval(q);
                mbaOut.innerHTML = renderMbaEvalHtml(r);
            };
            mbaIn.oninput = () => hooks.onMbaDraft(mbaIn.value);
            mbaGo.onclick = () => runMba();
            mbaIn.onkeydown = (e) => {
                if (e.key === 'Enter') { e.preventDefault(); runMba(); }
            };
            container.querySelectorAll('[data-mba-preset]').forEach((btn) => {
                btn.onclick = () => {
                    mbaIn.value = btn.dataset.mbaPreset;
                    runMba(mbaIn.value);
                };
            });
        }

        const applyH = container.querySelector('#unp-apply-h');
        if (applyH) applyH.onclick = () => hooks.onApplyHashes();
        const applyS = container.querySelector('#unp-apply-s');
        if (applyS) applyS.onclick = () => hooks.onApplyStrs();
    }

    function tntKindCls(kind) {
        const k = String(kind || '').toUpperCase();
        if (k === 'TAINT_SINK') return 'tnt-k-sink';
        if (k === 'TAINT_BRANCH') return 'tnt-k-branch';
        if (k === 'TAINT_STORE') return 'tnt-k-store';
        if (k === 'TAINT_IND') return 'tnt-k-ind';
        if (k === 'SHIM_CALL') return 'tnt-k-shim';
        return 'pk-def';
    }

    function renderTaintTab(cfg, res, curVa) {
        const reg = (cfg && cfg.reg) || 'rcx';
        const bufLen = (cfg && cfg.bufLen !== undefined) ? Number(cfg.bufLen) : 0;
        const steps = (cfg && cfg.steps) ? Number(cfg.steps) : 128;
        const regOpts = ['rcx', 'rdx', 'r8', 'r9', 'rdi', 'rsi', 'rax', 'x0']
            .map((r) => `<option value="${r}"${r === reg ? ' selected' : ''}>${r}</option>`).join('');
        const bufOpts = [0, 32, 64, 256]
            .map((n) => `<option value="${n}"${n === bufLen ? ' selected' : ''}>${n} B</option>`).join('');
        const stepOpts = [64, 128, 256]
            .map((n) => `<option value="${n}"${n === steps ? ' selected' : ''}>${n}</option>`).join('');

        let body = `<div class="welcome"><p>Select a source register, buffer length, and step budget, then click Run Taint to trace taint propagation and API shims from ${esc(curVa)}.</p></div>`;
        if (res && !res.ok) {
            body = `<div class="welcome"><p>Taint propagation could not start at ${esc(curVa)}. Select executable code and retry.</p></div>`;
        } else if (res && res.ok) {
            const tainted = Array.isArray(res.tainted_regs) ? res.tainted_regs : [];
            const taintedSet = new Set(tainted);
            const events = Array.isArray(res.events) ? res.events : [];
            const curLo = (curVa || '').toLowerCase();

            const pillsHtml = tainted.length
                ? tainted.map((r) => `<span class="tnt-reg-pill">${esc(r)}</span>`).join('')
                : '<span class="prot-muted">none</span>';

            const evRows = events.length
                ? events.map((ev, i) => {
                    const cur = ev.va && ev.va.toLowerCase() === curLo ? ' cur' : '';
                    return `<div class="prot-row${cur}" data-va="${esc(ev.va)}">`
                        + `<span class="dec-ln" style="width:28px;padding-right:6px">${i + 1}</span>`
                        + `<button class="cap-pill" data-jump="${esc(ev.va)}">${esc(ev.va)}</button>`
                        + `<span class="prot-badge ${tntKindCls(ev.kind)}">${esc(ev.kind)}</span>`
                        + `<span class="mono vm-det">${esc(ev.detail || '')}</span>`
                        + `<span class="mono prot-muted">mask 0x${Number(ev.mask || 0).toString(16)}</span>`
                        + `</div>`;
                }).join('')
                : '<div class="ins-empty" style="padding:12px">No taint sink, branch, store, indirect, or API shim events recorded.</div>';

            const regRows = Object.entries(res.regs || {}).map(([k, v]) => {
                const hi = taintedSet.has(k);
                return `<div class="ins-kv${hi ? ' tnt-reg-hi' : ''}">`
                    + `<span class="mono">${esc(k)}${hi ? ' <span class="ssa-arg-pill">T</span>' : ''}</span>`
                    + `<b class="mono">${esc(v)}</b></div>`;
            }).join('');

            body = `
              <div class="prot-chips">
                <span class="meta-chip">Stop: <b>${esc(res.stop || '—')}</b></span>
                <span class="meta-chip">Steps: <b>${res.nstep}</b></span>
                <span class="meta-chip">Tainted Bytes: <b>${res.taint_bytes}</b></span>
                <span class="meta-chip">API Shims: <b>${res.shims}</b></span>
                <span class="prot-muted">Tainted Regs:</span>
                ${pillsHtml}
              </div>
              <div class="pro-split">
                <div class="pro-main">
                  <div class="pane-head"><span>Taint &amp; Shim Events (${events.length})</span><span class="pane-meta">start ${esc(res.start || curVa)}</span></div>
                  <div class="prot-list">${evRows}</div>
                </div>
                <div class="pro-side">
                  <div class="ins-title">Final Registers (${tainted.length} tainted)</div>
                  ${regRows}
                </div>
              </div>`;
        }

        return `
          <div class="dbg-bar">
            <span>Source Reg</span>
            <select id="tnt-reg" class="dbg-sel">${regOpts}</select>
            <span>Buffer Len</span>
            <select id="tnt-blen" class="dbg-sel">${bufOpts}</select>
            <span>Steps</span>
            <select id="tnt-steps" class="dbg-sel">${stepOpts}</select>
            <button class="tb-btn hi" id="tnt-run">Run Taint</button>
            <span style="flex:1"></span>
            <span class="mono prot-muted">VA ${esc(curVa)}</span>
          </div>
          ${body}`;
    }

    function renderSymTab(symSt, curVa) {
        const s = symSt || { from: '', to: '', res: null };
        const fromVal = s.from || curVa || '';
        const toVal = s.to || '';
        const res = s.res;

        let body = '<div class="ins-empty">Enter From VA and To VA (or symbol names) within a function and click Solve Path to collect symbolic path constraints and concrete witness inputs.</div>';
        if (res && !res.ok) {
            body = `<div class="ins-empty" style="color:var(--tok-ret)">${esc(res.err || 'Symbolic path solver could not analyze this range.')}</div>`;
        } else if (res && res.ok) {
            const path = Array.isArray(res.path) ? res.path : [];
            const cons = Array.isArray(res.constraints) ? res.constraints : [];
            const wits = Array.isArray(res.witness) ? res.witness : [];

            const pathHtml = path.length
                ? `<div class="pf-chain">${path.map((va, i) =>
                    `<button class="cap-pill" data-jump="${esc(va)}">${i + 1}. ${esc(va)}</button>`
                  ).join('<span class="pf-arr">→</span>')}</div>`
                : '<div class="ins-empty">No CFG block path found.</div>';

            const consHtml = cons.length
                ? `<div class="ov-table">${cons.map((c, i) =>
                    `<div class="sym-cons-row"><span class="prot-muted" style="width:24px">${i + 1}.</span><span>${esc(c)}</span></div>`
                  ).join('')}</div>`
                : '<div class="ins-empty">No branch constraints along this path (unconditional).</div>';

            const witHtml = wits.length
                ? `<div class="sym-wit-grid">${wits.map((w) =>
                    `<div class="sym-wit-card">`
                    + `<div><span class="t-reg">${esc(w.var)}</span> <span class="prot-muted">=</span> <b class="t-num">${esc(w.val)}</b></div>`
                    + (w.expr ? `<div class="prot-muted">${esc(w.expr)}</div>` : '')
                    + `</div>`
                  ).join('')}</div>`
                : '<div class="ins-empty">No concrete witness bindings synthesized.</div>';

            body = `
              <div class="ov-hero">
                <div class="ov-hero-l">
                  <div class="ov-verdict ${res.reachable ? 'tone-ok' : 'tone-hi'}">${res.reachable ? 'REACHABLE' : 'UNREACHABLE'}</div>
                  <div class="ov-sub">${esc(res.summary || (res.reachable ? 'Target block is reachable in CFG.' : 'Target block is unreachable from start VA.'))}</div>
                </div>
              </div>
              <div class="ov-block">
                <div class="ov-h">CFG Block Path (${path.length} blocks)</div>
                ${pathHtml}
              </div>
              <div class="ov-block">
                <div class="ov-h">Collected Symbolic Path Constraints (${cons.length})</div>
                ${consHtml}
              </div>
              <div class="ov-block">
                <div class="ov-h">Solved Concrete Witness Inputs (${wits.length})</div>
                ${witHtml}
              </div>`;
        }

        return `
          <div class="dbg-bar">
            <span>From VA</span>
            <input id="sym-from" class="dbg-in" style="width:180px" placeholder="0x... or symbol" value="${esc(fromVal)}" spellcheck="false">
            <span class="pf-arr">→</span>
            <span>To VA</span>
            <input id="sym-to" class="dbg-in" style="width:180px" placeholder="Target VA or symbol" value="${esc(toVal)}" spellcheck="false">
            <button class="tb-btn hi" id="sym-go">Solve Path</button>
          </div>
          <div class="prot-scroll">
            <div class="ov-wrap">${body}</div>
          </div>`;
    }

    function renderTraceLab(container, sub, bundle, curVa, hooks) {
        const mode = sub || 'emu';
        const b = bundle || {};

        let bodyHtml = '';
        if (mode === 'emu') {
            bodyHtml = '<div id="trace-emu-slot" class="trace-emu-slot"></div>';
        } else if (mode === 'taint') {
            bodyHtml = renderTaintTab(b.taintCfg, b.taintRes, curVa);
        } else {
            bodyHtml = renderSymTab(b.symSt, curVa);
        }

        container.innerHTML = `
          <div class="ir-wrap">
            <div class="dob-bar">
              <button class="tb-btn${mode === 'emu' ? ' hi' : ''}" data-trsub="emu">Micro-Emu</button>
              <button class="tb-btn${mode === 'taint' ? ' hi' : ''}" data-trsub="taint">Taint &amp; Shims</button>
              <button class="tb-btn${mode === 'sym' ? ' hi' : ''}" data-trsub="sym">Path Solver</button>
              <span style="flex:1"></span>
              <span class="mono prot-muted">${esc(curVa)}</span>
            </div>
            ${bodyHtml}
          </div>`;

        container.querySelectorAll('[data-trsub]').forEach((btn) => {
            btn.onclick = () => hooks.onSub(btn.dataset.trsub);
        });

        if (mode === 'emu') {
            window.triView.renderTrace(container.querySelector('#trace-emu-slot'), b.emu, b.emuSteps, {
                onRerun: hooks.onEmuRerun,
                onSelect: hooks.onSelect
            });
            return;
        }

        container.querySelectorAll('.prot-row[data-va]').forEach((el) => {
            el.onclick = () => {
                container.querySelectorAll('.prot-row.cur').forEach((r) => r.classList.remove('cur'));
                el.classList.add('cur');
                hooks.onSelect(el.dataset.va);
            };
            el.ondblclick = () => hooks.onJump(el.dataset.va);
        });
        container.querySelectorAll('[data-jump]').forEach((el) => {
            el.onclick = (e) => { e.stopPropagation(); hooks.onJump(el.dataset.jump); };
        });

        if (mode === 'taint') {
            const regEl = container.querySelector('#tnt-reg');
            const blenEl = container.querySelector('#tnt-blen');
            const stepsEl = container.querySelector('#tnt-steps');
            const readCfg = () => ({
                reg: regEl.value,
                bufLen: Number(blenEl.value) || 0,
                steps: Number(stepsEl.value) || 128
            });
            regEl.onchange = () => hooks.onTaintCfg(readCfg());
            blenEl.onchange = () => hooks.onTaintCfg(readCfg());
            stepsEl.onchange = () => hooks.onTaintCfg(readCfg());
            container.querySelector('#tnt-run').onclick = () => hooks.onRunTaint(readCfg());
        } else {
            const fEl = container.querySelector('#sym-from');
            const tEl = container.querySelector('#sym-to');
            const syncDraft = () => hooks.onSymDraft(fEl.value, tEl.value);
            fEl.oninput = syncDraft;
            tEl.oninput = syncDraft;
            const runSolve = () => hooks.onSymSolve(fEl.value.trim(), tEl.value.trim());
            container.querySelector('#sym-go').onclick = runSolve;
            fEl.onkeydown = (e) => { if (e.key === 'Enter') runSolve(); };
            tEl.onkeydown = (e) => { if (e.key === 'Enter') runSolve(); };
        }
    }

    // ---- Dalga E: Audit Mode (Vuln Slicer, YARA, Carver & IOCs, Hilbert Map, AI Queue & Live Collab) ----

    let collabActiveFlag = false;

    function setCollabActive(active) {
        collabActiveFlag = !!active;
    }

    function broadcastCollab(msg) {
        if (!collabActiveFlag || !msg || !window.xdis || !window.xdis.collabSend) {
            return Promise.resolve({ ok: false });
        }
        return window.xdis.collabSend(msg);
    }

    function parseCssHexRgb(hex, fallback) {
        const s = String(hex || '').trim();
        const m = s.match(/^#([0-9a-f]{6})$/i);
        if (m) {
            const n = parseInt(m[1], 16);
            return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
        }
        const m3 = s.match(/^#([0-9a-f]{3})$/i);
        if (m3) {
            return [
                parseInt(m3[1][0] + m3[1][0], 16),
                parseInt(m3[1][1] + m3[1][1], 16),
                parseInt(m3[1][2] + m3[1][2], 16)
            ];
        }
        const mRgb = s.match(/^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/i);
        if (mRgb) return [Number(mRgb[1]), Number(mRgb[2]), Number(mRgb[3])];
        return fallback;
    }

    function lerpRgb(a, b, t) {
        const k = Math.max(0, Math.min(1, t));
        return [
            Math.round(a[0] + (b[0] - a[0]) * k),
            Math.round(a[1] + (b[1] - a[1]) * k),
            Math.round(a[2] + (b[2] - a[2]) * k)
        ];
    }

    function rgbCss(c) {
        return `rgb(${c[0]},${c[1]},${c[2]})`;
    }

    const HILBERT_CLASSES = [
        { id: 0, label: 'Zero / Pad' },
        { id: 1, label: 'Code' },
        { id: 2, label: 'Data' },
        { id: 3, label: 'Strings' },
        { id: 4, label: 'High-Entropy / Packed' }
    ];

    function hilbertNormEnt(rawVal) {
        return Math.min(8.0, Math.max(0.0, Number(rawVal || 0) / 10.0));
    }

    function getHilbertPalette() {
        const cs = getComputedStyle(document.documentElement);
        const bg = parseCssHexRgb(cs.getPropertyValue('--bg'), [23, 25, 29]);
        const pad = parseCssHexRgb(cs.getPropertyValue('--border-hi'), [58, 66, 82]);
        const code = parseCssHexRgb(cs.getPropertyValue('--edge-u'), [125, 154, 184]);
        const data = parseCssHexRgb(cs.getPropertyValue('--tok-call'), [210, 169, 120]);
        const strs = parseCssHexRgb(cs.getPropertyValue('--tok-str'), [158, 185, 137]);
        const packed = parseCssHexRgb(cs.getPropertyValue('--tok-ret'), [201, 134, 134]);
        const fg = cs.getPropertyValue('--fg').trim() || '#ced4de';
        return { bg, classes: [pad, code, data, strs, packed], fg };
    }

    function hilbertCellColor(pal, clsId, entBits) {
        const id = (clsId >= 0 && clsId < pal.classes.length) ? clsId : 0;
        const frac = Math.max(0, Math.min(1, entBits / 8.0));
        const t = id === 0 ? (0.28 + 0.42 * frac) : (0.36 + 0.64 * frac);
        return rgbCss(lerpRgb(pal.bg, pal.classes[id], t));
    }

    function sevToneCls(sev) {
        const s = String(sev || '').toUpperCase();
        if (s === 'HIGH' || s === 'CRIT' || s === 'CRITICAL') return 'tone-hi';
        if (s === 'MED' || s === 'MEDIUM' || s === 'WARN') return 'tone-mid';
        return 'tone-ok';
    }

    function kindBadgeCls(kind) {
        const k = String(kind || '').toUpperCase();
        if (/PE|ELF|MACHO|URL|SINK|OVERFLOW|FMT|CMD/.test(k)) return 'pk-ctl';
        if (/ZIP|GZIP|ZLIB|PDF|PNG|IPV4|IP|DOMAIN/.test(k)) return 'pk-mem';
        if (/REG|KEY|CERT|PEM|MUTEX|EMAIL/.test(k)) return 'pk-bit';
        return 'pk-alu';
    }

    function fmtTimeShort(ts) {
        const d = ts ? new Date(ts) : new Date();
        const pad = (n) => String(n).padStart(2, '0');
        return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    }

    function renderVulnTab(vuln, curVa) {
        const ok = !!(vuln && vuln.ok);
        const items = (ok && Array.isArray(vuln.items)) ? vuln.items : [];
        const nhigh = ok ? Number(vuln.nhigh || 0) : 0;
        const nmed = ok ? Number(vuln.nmed || 0) : 0;
        const curLo = (curVa || '').toLowerCase();

        const rowsHtml = !vuln
            ? '<div class="welcome"><p>Click Scan Vulnerabilities to run backward source-to-sink taint slicing across analyzed functions.</p></div>'
            : (items.length
                ? `<div class="vln-list">${items.map((it) => {
                    const cur = it.va && it.va.toLowerCase() === curLo ? ' cur' : '';
                    const hops = Number(it.hops || 0);
                    const flow = it.source
                        ? `${esc(it.source)} → ${esc(it.sink || 'sink')}`
                        : esc(it.sink || '');
                    return `<div class="vln-row${cur}" data-jump="${esc(it.va)}">`
                        + `<span class="vln-sev ${sevToneCls(it.sev)}">${esc(it.sev || 'INFO')}</span>`
                        + `<span class="prot-badge ${kindBadgeCls(it.kind)}">${esc(it.kind || 'VULN')}</span>`
                        + `<div class="vln-body">`
                        + `<div class="vln-top">`
                        + `<span class="mono t-sym">${esc(it.func || 'sub')}</span>`
                        + (flow ? `<span class="vln-flow">${flow}</span>` : '')
                        + `<span class="vln-hops">(${hops} hop${hops === 1 ? '' : 's'})</span>`
                        + `</div>`
                        + (it.detail ? `<div class="vln-detail" title="${esc(it.detail)}">${esc(it.detail)}</div>` : '')
                        + `</div>`
                        + `<button class="cap-pill" data-jump="${esc(it.va)}">${esc(it.va)}</button>`
                        + `</div>`;
                }).join('')}</div>`
                : '<div class="ins-empty" style="padding:14px">No vulnerable source-to-sink paths flagged in this binary.</div>');

        return `
          <div class="dbg-bar">
            <button class="tb-btn hi" id="aud-vuln-scan">Scan Vulnerabilities</button>
            <span class="dbg-sep"></span>
            <span class="prot-pill ${nhigh > 0 ? 'tone-hi' : 'pk-def'}">HIGH ${nhigh}</span>
            <span class="prot-pill ${nmed > 0 ? 'tone-mid' : 'pk-def'}">MED ${nmed}</span>
            <span class="meta-chip">Total: <b>${items.length}</b></span>
          </div>
          <div class="aud-scroll">${rowsHtml}</div>`;
    }

    function renderYaraTab(rulesText, res, curVa) {
        const hasRes = !!res;
        const ok = !!(res && res.ok);
        const hits = (ok && Array.isArray(res.hits)) ? res.hits : [];
        const curLo = (curVa || '').toLowerCase();
        const errText = (res && res.err) ? res.err : (hasRes && !ok ? 'YARA scan failed.' : '');

        const hitRows = !hasRes
            ? '<tr><td colspan="6" class="ins-empty" style="padding:12px">Edit YARA rules above or load defaults, then click Run Scan.</td></tr>'
            : (hits.length
                ? hits.map((h) => {
                    const hasVa = h.va && h.va !== '0x0';
                    const cur = hasVa && h.va.toLowerCase() === curLo ? ' cur' : '';
                    const offHex = '0x' + Number(h.off || 0).toString(16);
                    return `<tr class="yara-row${cur}" data-yva="${esc(h.va || '0x0')}" data-yoff="${Number(h.off || 0)}">`
                        + `<td class="mono t-sym">${esc(h.rule || '')}</td>`
                        + `<td class="mono t-reg">${esc(h.id || '')}</td>`
                        + `<td>${hasVa ? `<button class="cap-pill" data-jump="${esc(h.va)}">${esc(h.va)}</button>` : '<span class="mono prot-muted">unmapped</span>'}</td>`
                        + `<td class="mono prot-muted">${offHex}</td>`
                        + `<td class="mono">${Number(h.nmatch || 0)}</td>`
                        + `<td class="yara-desc" title="${esc(h.desc || '')}">${esc(h.desc || '')}</td>`
                        + `</tr>`;
                }).join('')
                : '<tr><td colspan="6" class="ins-empty" style="padding:12px">No YARA rules matched this binary.</td></tr>');

        return `
          <div class="dbg-bar">
            <button class="tb-btn hi" id="aud-yara-run">Run Scan</button>
            <button class="tb-btn" id="aud-yara-def">Load Default Rules</button>
            <span class="dbg-sep"></span>
            <span class="meta-chip">Rules: <b>${ok ? Number(res.nrules || 0) : 0}</b></span>
            <span class="meta-chip">Hits: <b>${hits.length}</b></span>
          </div>
          ${errText ? `<div class="dbg-err">${esc(errText)}</div>` : ''}
          <div class="yara-layout">
            <div class="yara-ed-wrap">
              <textarea id="aud-yara-rules" class="yara-ed" spellcheck="false" placeholder="rule Example { strings: $a = &quot;test&quot; condition: $a }">${esc(rulesText || '')}</textarea>
            </div>
            <div class="yara-hits-wrap">
              <div class="pane-head"><span>Rule Hits (${hits.length})</span><span class="pane-meta">click row to jump to VA</span></div>
              <div class="yara-tbl-scroll">
                <table class="ovl-tbl">
                  <thead>
                    <tr><th>Rule</th><th>ID</th><th>VA</th><th>Offset</th><th>Matches</th><th>Description</th></tr>
                  </thead>
                  <tbody>${hitRows}</tbody>
                </table>
              </div>
            </div>
          </div>`;
    }

    function renderCarveTab(carveRes, iocRes, iocFilter, curVa) {
        const carveItems = (carveRes && carveRes.ok && Array.isArray(carveRes.items)) ? carveRes.items : [];
        const iocItems = (iocRes && iocRes.ok && Array.isArray(iocRes.items)) ? iocRes.items : [];
        const curLo = (curVa || '').toLowerCase();

        const carveRows = !carveRes
            ? '<div class="ins-empty" style="padding:12px">Click Scan Embedded to carve nested PE, ELF, ZIP, PNG, PDF, and certificate payloads.</div>'
            : (carveItems.length
                ? carveItems.map((it, idx) => {
                    const hasVa = it.va && it.va !== '0x0';
                    const cur = hasVa && it.va.toLowerCase() === curLo ? ' cur' : '';
                    const offHex = '+0x' + Number(it.off || 0).toString(16);
                    const entStr = Number(it.ent || 0).toFixed(2);
                    return `<div class="carve-row${cur}" data-cva="${esc(it.va || '0x0')}" data-coff="${Number(it.off || 0)}">`
                        + `<span class="prot-badge ${kindBadgeCls(it.kind)}">${esc(it.kind || 'BIN')}</span>`
                        + `<div class="carve-info">`
                        + `<div class="carve-top">`
                        + `<span class="mono prot-muted">${offHex}</span>`
                        + (hasVa ? `<button class="cap-pill" data-jump="${esc(it.va)}">${esc(it.va)}</button>` : '<span class="mono prot-muted">unmapped</span>')
                        + `<span class="mono">${fmtSize(it.size)}</span>`
                        + `<span class="meta-chip">H ${entStr}</span>`
                        + `</div>`
                        + (it.detail ? `<div class="carve-det" title="${esc(it.detail)}">${esc(it.detail)}</div>` : '')
                        + `</div>`
                        + `<button class="mini-btn" data-carve-ext="${idx}">Extract…</button>`
                        + `</div>`;
                }).join('')
                : '<div class="ins-empty" style="padding:12px">No embedded file artifacts carved from binary.</div>');

        return `
          <div class="unp-split">
            <div class="unp-col">
              <div class="pane-head">
                <span>Carved Artifacts (${carveItems.length})</span>
                <button class="mini-btn hi" id="aud-carve-scan">Scan Embedded</button>
              </div>
              <div class="unp-list">${carveRows}</div>
            </div>
            <div class="unp-col">
              <div class="pane-head">
                <span>Extracted IOCs <span id="aud-ioc-cnt" class="pane-meta">(${iocItems.length})</span></span>
                <div class="pane-acts">
                  <button class="mini-btn" id="aud-ioc-copy"${iocItems.length ? '' : ' disabled'}>Copy All</button>
                  <button class="mini-btn hi" id="aud-ioc-scan">Extract IOCs</button>
                </div>
              </div>
              <div class="ioc-filter-bar">
                <input id="aud-ioc-filter" class="ioc-filter-in" type="text" value="${esc(iocFilter || '')}" placeholder="Filter IOCs by kind, VA, or value…" spellcheck="false">
              </div>
              <div id="aud-ioc-list" class="unp-list"></div>
            </div>
          </div>`;
    }

    function fillIocList(listEl, countEl, copyBtn, iocRes, filterText, curVa, hooks) {
        if (!listEl) return [];
        const all = (iocRes && iocRes.ok && Array.isArray(iocRes.items)) ? iocRes.items : [];
        const q = String(filterText || '').trim().toLowerCase();
        const filtered = q
            ? all.filter((it) =>
                String(it.kind || '').toLowerCase().includes(q)
                || String(it.value || '').toLowerCase().includes(q)
                || String(it.va || '').toLowerCase().includes(q)
            )
            : all;

        if (countEl) {
            countEl.textContent = q ? `(${filtered.length}/${all.length})` : `(${all.length})`;
        }
        if (copyBtn) copyBtn.disabled = filtered.length === 0;

        if (!iocRes) {
            listEl.innerHTML = '<div class="ins-empty" style="padding:12px">Click Extract IOCs to harvest URLs, IPv4 addresses, domains, registry paths, and file indicators.</div>';
            return filtered;
        }
        if (!filtered.length) {
            listEl.innerHTML = `<div class="ins-empty" style="padding:12px">${all.length ? 'No IOCs match current filter.' : 'No IOCs extracted from binary strings.'}</div>`;
            return filtered;
        }
        const curLo = (curVa || '').toLowerCase();
        listEl.innerHTML = filtered.map((it) => {
            const hasVa = it.va && it.va !== '0x0';
            const cur = hasVa && it.va.toLowerCase() === curLo ? ' cur' : '';
            return `<div class="prot-row${cur}" data-jump="${esc(it.va || '0x0')}">`
                + `<span class="prot-badge ${kindBadgeCls(it.kind)}">${esc(it.kind || 'IOC')}</span>`
                + (hasVa ? `<button class="cap-pill" data-jump="${esc(it.va)}">${esc(it.va)}</button>` : '<span class="mono prot-muted">—</span>')
                + `<span class="mono ioc-val" title="${esc(it.value || '')}">${esc(it.value || '')}</span>`
                + `</div>`;
        }).join('');

        listEl.querySelectorAll('[data-jump]').forEach((el) => {
            el.addEventListener('click', (e) => {
                e.stopPropagation();
                const va = el.dataset.jump;
                if (va && va !== '0x0') hooks.onJump(va);
            });
        });
        return filtered;
    }

    function renderHilbertTab(order, hr) {
        const ord = Number(order) || 6;
        const ok = !!(hr && hr.ok && hr.side > 0 && Array.isArray(hr.cls));
        const ncell = ok ? Number(hr.ncell || (hr.side * hr.side)) : 0;
        const counts = [0, 0, 0, 0, 0];
        let avgEnt = 0;
        if (ok && Array.isArray(hr.ent)) {
            let sum = 0;
            for (let i = 0; i < ncell; i++) {
                const c = hr.cls[i];
                if (c >= 0 && c < 5) counts[c]++;
                sum += hilbertNormEnt(hr.ent[i]);
            }
            avgEnt = ncell ? (sum / ncell) : 0;
        }

        const ordOpts = [
            [4, '16x16 (Order 4 · 256 cells)'],
            [5, '32x32 (Order 5 · 1024 cells)'],
            [6, '64x64 (Order 6 · 4096 cells)']
        ].map(([v, lbl]) => `<option value="${v}"${v === ord ? ' selected' : ''}>${lbl}</option>`).join('');

        const legHtml = HILBERT_CLASSES.map((c) => {
            const cnt = counts[c.id] || 0;
            const pct = ncell ? ((cnt * 100) / ncell).toFixed(1) + '%' : '—';
            return `<div class="hilb-leg-row">`
                + `<span class="hilb-leg-l"><span class="hilb-swatch" data-hcls="${c.id}"></span><span>${c.id} · ${c.label}</span></span>`
                + `<span class="mono">${cnt} (${pct})</span>`
                + `</div>`;
        }).join('');

        return `
          <div class="dbg-bar">
            <span>Resolution</span>
            <select id="aud-hilb-ord" class="dbg-sel">${ordOpts}</select>
            <button class="tb-btn hi" id="aud-hilb-run">Render</button>
            <span class="dbg-sep"></span>
            <span class="meta-chip">Grid: <b>${ok ? `${hr.side}x${hr.side}` : '—'}</b></span>
            <span class="meta-chip">Avg Ent: <b>${ok ? avgEnt.toFixed(2) : '—'}</b></span>
            <span class="meta-chip">High-Ent: <b>${ok ? counts[4] : 0}</b></span>
          </div>
          <div class="hilb-stage">
            <div class="hilb-left">
              <div class="hilb-canvas-frame">
                <canvas id="hilbert-canvas" width="512" height="512"></canvas>
              </div>
              <div id="hilb-inspector" class="hilb-inspector">
                ${ok ? 'Hover canvas to inspect cell · Click cell to jump to Disasm or Hex' : 'Click Render to generate Hilbert space-filling entropy map.'}
              </div>
            </div>
            <div class="hilb-side">
              <div class="ins-title"><span>Byte Class Legend</span><span class="mono">Ent 0.0 – 8.0</span></div>
              <div class="hilb-legend">${legHtml}</div>
              <div class="hilb-hint">
                Intensity scales with Shannon entropy (0.0 to 8.0 bits/byte) across the active theme palette.
                Click any mapped cell to jump directly to Disasm, or an unmapped cell to open Hex view.
              </div>
            </div>
          </div>`;
    }

    function paintHilbertCanvas(container, hr, hooks) {
        const pal = getHilbertPalette();
        container.querySelectorAll('.hilb-swatch[data-hcls]').forEach((sw) => {
            const cid = Number(sw.dataset.hcls);
            sw.style.backgroundColor = hilbertCellColor(pal, cid, cid === 0 ? 4.0 : 6.8);
        });

        const canvas = container.querySelector('#hilbert-canvas');
        const insp = container.querySelector('#hilb-inspector');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        ctx.imageSmoothingEnabled = false;
        ctx.fillStyle = rgbCss(pal.bg);
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        if (!hr || !hr.ok || !hr.side || !Array.isArray(hr.cls)) return;

        const side = Number(hr.side);
        const ncell = Math.min(Number(hr.ncell || side * side), hr.cls.length);
        const cellPx = Math.floor(canvas.width / side);

        for (let y = 0; y < side; y++) {
            for (let x = 0; x < side; x++) {
                const idx = y * side + x;
                if (idx >= ncell) continue;
                const c = hr.cls[idx] || 0;
                const eBits = hilbertNormEnt(hr.ent ? hr.ent[idx] : 0);
                ctx.fillStyle = hilbertCellColor(pal, c, eBits);
                ctx.fillRect(x * cellPx, y * cellPx, cellPx, cellPx);
            }
        }

        const baseCanvas = document.createElement('canvas');
        baseCanvas.width = canvas.width;
        baseCanvas.height = canvas.height;
        baseCanvas.getContext('2d').drawImage(canvas, 0, 0);

        const defaultHint = 'Hover canvas to inspect cell · Click cell to jump to Disasm or Hex';

        function cellAtEvent(ev) {
            const rect = canvas.getBoundingClientRect();
            const sx = canvas.width / (rect.width || 512);
            const sy = canvas.height / (rect.height || 512);
            const gx = Math.floor((ev.clientX - rect.left) * sx / cellPx);
            const gy = Math.floor((ev.clientY - rect.top) * sy / cellPx);
            if (gx < 0 || gx >= side || gy < 0 || gy >= side) return null;
            const idx = gy * side + gx;
            if (idx < 0 || idx >= ncell) return null;
            const clsId = hr.cls[idx] || 0;
            const entBits = hilbertNormEnt(hr.ent ? hr.ent[idx] : 0);
            const off = hr.offs ? Number(hr.offs[idx] || 0) : 0;
            const va = (hr.vas && hr.vas[idx]) ? String(hr.vas[idx]) : '0x0';
            return { gx, gy, idx, clsId, entBits, off, va };
        }

        canvas.addEventListener('mousemove', (ev) => {
            const cell = cellAtEvent(ev);
            ctx.drawImage(baseCanvas, 0, 0);
            if (!cell) {
                if (insp) insp.textContent = defaultHint;
                return;
            }
            ctx.strokeStyle = pal.fg;
            ctx.lineWidth = 1.5;
            ctx.strokeRect(cell.gx * cellPx + 0.75, cell.gy * cellPx + 0.75, cellPx - 1.5, cellPx - 1.5);
            if (insp) {
                const clsName = (HILBERT_CLASSES[cell.clsId] || HILBERT_CLASSES[0]).label;
                const vaTxt = cell.va && cell.va !== '0x0' ? cell.va : 'unmapped';
                insp.innerHTML =
                    `<span>Cell <b>(${cell.gx},${cell.gy})</b></span>`
                    + `<span>| File <b>+0x${cell.off.toString(16)}</b></span>`
                    + `<span>| VA <b>${esc(vaTxt)}</b></span>`
                    + `<span>| Ent <b>${cell.entBits.toFixed(1)}</b></span>`
                    + `<span>| <b>${esc(clsName)}</b></span>`;
            }
        });

        canvas.addEventListener('mouseleave', () => {
            ctx.drawImage(baseCanvas, 0, 0);
            if (insp) insp.textContent = defaultHint;
        });

        canvas.addEventListener('click', (ev) => {
            const cell = cellAtEvent(ev);
            if (!cell) return;
            if (cell.va && cell.va !== '0x0') hooks.onJump(cell.va);
            else if (hooks.onJumpHex) hooks.onJumpHex(cell.off, cell.va);
        });
    }

    function renderCollabPeersHtml(col) {
        const peers = Array.isArray(col.peers) ? col.peers : [];
        if (!col.active || !peers.length) {
            return '<span class="prot-muted">Not connected to a room. Host a TCP room or join a teammate.</span>';
        }
        const cursors = col.peerCursors || {};
        return peers.map((nick) => {
            const isSelf = nick === col.nick;
            const c = cursors[nick];
            const hasVa = !!(c && c.va && c.va !== '0x0');
            const vaHtml = hasVa
                ? `<span class="prot-muted">${esc(c.va)}</span><button class="mini-btn" data-col-follow="${esc(c.va)}">Follow</button>`
                : (isSelf ? '<span class="prot-muted">(you)</span>' : '<span class="prot-muted">idle</span>');
            return `<span class="col-peer-pill${isSelf ? ' is-self' : ''}">`
                + `<b>${esc(nick)}</b>${vaHtml}</span>`;
        }).join('');
    }

    function renderCollabLogHtml(col) {
        const entries = Array.isArray(col.log) ? col.log : [];
        if (!entries.length) {
            return '<div class="ins-empty">Room activity, remote renames/comments, and team chat appear here.</div>';
        }
        return entries.map((e) => {
            const ts = `<span class="col-log-ts">${fmtTimeShort(e.ts)}</span>`;
            const vaBtn = (e.va && e.va !== '0x0')
                ? ` <button class="cap-pill" data-jump="${esc(e.va)}">${esc(e.va)}</button>`
                : '';
            if (e.kind === 'sys') {
                return `<div class="col-log-row">${ts}<span class="col-log-sys">${esc(e.text)}</span></div>`;
            }
            if (e.kind === 'act') {
                return `<div class="col-log-row">${ts}<span class="col-log-from">${esc(e.from || 'peer')}</span>`
                    + `<span class="col-log-act">${esc(e.text)}</span>${vaBtn}</div>`;
            }
            return `<div class="col-log-row">${ts}<span class="col-log-from">${esc(e.from || 'peer')}:</span>`
                + `<span>${esc(e.text)}</span></div>`;
        }).join('');
    }

    function renderQueueAndCollabTab(sugsRes, draft, col, curVa) {
        const items = (sugsRes && sugsRes.ok && Array.isArray(sugsRes.items)) ? sugsRes.items : [];
        const pending = (sugsRes && sugsRes.ok) ? Number(sugsRes.pending || 0) : 0;
        const d = draft || { va: '', kind: 'rename', val: '', reason: '', conf: '85' };
        const vaVal = d.va || curVa || '0x0';
        const kindVal = d.kind || 'rename';
        const confVal = d.conf !== undefined && d.conf !== '' ? d.conf : '85';

        const sugRows = items.length
            ? items.map((s) => {
                const stStr = String(s.status || 'pending').toLowerCase();
                const isPend = stStr === 'pending';
                const stCls = stStr === 'accepted' ? 'sug-st-accepted' : (stStr === 'rejected' ? 'sug-st-rejected' : 'sug-st-pending');
                const confNum = Number(s.conf || 0);
                const confCls = confNum >= 80 ? 'tone-ok' : (confNum >= 50 ? 'tone-mid' : 'tone-hi');
                const hasVa = s.va && s.va !== '0x0';
                return `<div class="sug-row${isPend ? '' : ' is-decided'}">`
                    + `<div class="sug-main">`
                    + `<div class="sug-top">`
                    + `<span class="prot-badge ${stCls}">${esc(stStr.toUpperCase())}</span>`
                    + `<span class="prot-badge ${confCls}">${confNum}%</span>`
                    + `<span class="meta-chip">${esc(s.kind || 'rename')}</span>`
                    + (hasVa ? `<button class="cap-pill" data-jump="${esc(s.va)}">${esc(s.va)}</button>` : '')
                    + `<span class="sug-val">${esc(s.val || '')}</span>`
                    + `</div>`
                    + (s.reason ? `<div class="sug-rsn">${esc(s.reason)}</div>` : '')
                    + `</div>`
                    + `<div class="sug-acts">`
                    + (isPend
                        ? `<button class="mini-btn hi" data-sug-acc="${s.id}">Accept</button>`
                          + `<button class="mini-btn" data-sug-rej="${s.id}">Reject</button>`
                        : `<span class="mono prot-muted">#${s.id}</span>`)
                    + `</div>`
                    + `</div>`;
            }).join('')
            : '<div class="ins-empty" style="padding:12px">No queued AI suggestions. Propose an annotation above or let an MCP agent queue suggestions via propose_annotation.</div>';

        const colStatusTxt = col.active
            ? (col.role === 'host' ? `HOST ${col.host}:${col.port}` : `CONNECTED ${col.host}:${col.port}`)
            : 'OFFLINE';

        return `
          <div class="aud-split-cards">
            <div class="aud-card">
              <div class="aud-card-head">
                <span class="aud-card-title">AI Suggestion Queue</span>
                <span class="meta-chip">Pending: <b>${pending}</b></span>
                <span style="flex:1"></span>
                <button class="mini-btn" id="aud-sug-ref">Refresh</button>
                <button class="mini-btn hi" id="aud-sug-acc80"${pending ? '' : ' disabled'}>Accept &gt;= 80%</button>
                <button class="mini-btn" id="aud-sug-rejall"${pending ? '' : ' disabled'}>Reject All</button>
              </div>
              <div class="sug-form">
                <input id="sug-va" class="dbg-in" style="width:118px" value="${esc(vaVal)}" placeholder="0x..." spellcheck="false">
                <select id="sug-kind" class="dbg-sel">
                  <option value="rename"${kindVal === 'rename' ? ' selected' : ''}>rename</option>
                  <option value="cmt"${kindVal === 'cmt' ? ' selected' : ''}>cmt</option>
                  <option value="type"${kindVal === 'type' ? ' selected' : ''}>type</option>
                </select>
                <input id="sug-val" class="dbg-in" style="flex:1;min-width:120px" value="${esc(d.val || '')}" placeholder="Proposed name / comment / C type…" spellcheck="false">
                <input id="sug-reason" class="dbg-in" style="width:130px" value="${esc(d.reason || '')}" placeholder="Reason (opt)" spellcheck="false">
                <input id="sug-conf" class="dbg-in" type="number" min="0" max="100" style="width:56px" value="${esc(confVal)}" title="Confidence 0..100">
                <button class="tb-btn hi" id="aud-sug-add">Add</button>
              </div>
              <div class="sug-list">${sugRows}</div>
            </div>

            <div class="aud-card">
              <div class="aud-card-head">
                <span class="aud-card-title">xdis Live Collab</span>
                <span id="col-status-pill" class="prot-pill ${col.active ? 'tone-ok' : 'pk-def'}">${esc(colStatusTxt)}</span>
              </div>
              <div class="col-form">
                <span>Nick</span>
                <input id="col-nick" class="dbg-in" style="width:88px" value="${esc(col.nick || 'analyst')}" spellcheck="false">
                <span>Host</span>
                <input id="col-host" class="dbg-in" style="width:108px" value="${esc(col.host || '127.0.0.1')}" spellcheck="false">
                <span>Port</span>
                <input id="col-port" class="dbg-in" style="width:62px" value="${esc(col.port || '4545')}" spellcheck="false">
                <input id="col-pass" type="password" class="dbg-in" style="width:88px" value="${esc(col.pass || '')}" placeholder="Secret (opt)" title="Optional shared room secret" spellcheck="false">
                <button class="tb-btn hi" id="col-host-btn">Host Room</button>
                <button class="tb-btn" id="col-join-btn">Join Room</button>
                <button class="tb-btn" id="col-stop-btn"${col.active ? '' : ' disabled'}>Disconnect</button>
              </div>
              <div id="col-err" class="dbg-err${col.err ? '' : ' hidden'}">${esc(col.err || '')}</div>
              <div id="col-peers-bar" class="col-peers-bar">${renderCollabPeersHtml(col)}</div>
              <div id="col-log" class="col-log">${renderCollabLogHtml(col)}</div>
              <div class="col-chat-bar">
                <input id="col-chat-in" class="dbg-in col-chat-in" value="${esc(col.chatDraft || '')}" placeholder="Send team message…" spellcheck="false"${col.active ? '' : ' disabled'}>
                <button class="tb-btn hi" id="col-chat-send"${col.active ? '' : ' disabled'}>Send</button>
              </div>
            </div>
          </div>`;
    }

    function wireCollabDynamicLinks(root, hooks) {
        if (!root) return;
        root.querySelectorAll('[data-col-follow]').forEach((btn) => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                if (hooks.onJump) hooks.onJump(btn.dataset.colFollow);
            });
        });
        root.querySelectorAll('[data-jump]').forEach((btn) => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                if (hooks.onJump) hooks.onJump(btn.dataset.jump);
            });
        });
    }

    function updateAuditCollab(container, col, hooks) {
        if (!container || !col) return;
        const pill = container.querySelector('#col-status-pill');
        const errEl = container.querySelector('#col-err');
        const peersEl = container.querySelector('#col-peers-bar');
        const logEl = container.querySelector('#col-log');
        const stopBtn = container.querySelector('#col-stop-btn');
        const chatIn = container.querySelector('#col-chat-in');
        const chatBtn = container.querySelector('#col-chat-send');
        if (!pill || !peersEl || !logEl) return;

        const txt = col.active
            ? (col.role === 'host' ? `HOST ${col.host}:${col.port}` : `CONNECTED ${col.host}:${col.port}`)
            : 'OFFLINE';
        pill.textContent = txt;
        pill.className = `prot-pill ${col.active ? 'tone-ok' : 'pk-def'}`;
        if (errEl) {
            errEl.textContent = col.err || '';
            errEl.classList.toggle('hidden', !col.err);
        }
        if (stopBtn) stopBtn.disabled = !col.active;
        if (chatIn) chatIn.disabled = !col.active;
        if (chatBtn) chatBtn.disabled = !col.active;

        peersEl.innerHTML = renderCollabPeersHtml(col);
        logEl.innerHTML = renderCollabLogHtml(col);
        logEl.scrollTop = logEl.scrollHeight;
        wireCollabDynamicLinks(peersEl, hooks);
        wireCollabDynamicLinks(logEl, hooks);
    }

    function renderAudit(container, sub, bundle, curVa, hooks) {
        const mode = sub || 'vuln';
        const b = bundle || {};
        const col = b.collab || { active: false, peers: [], peerCursors: {}, log: [] };
        const pendingN = (b.sugs && b.sugs.ok) ? Number(b.sugs.pending || 0) : 0;

        let bodyHtml = '';
        if (mode === 'vuln') {
            bodyHtml = renderVulnTab(b.vuln, curVa);
        } else if (mode === 'yara') {
            bodyHtml = renderYaraTab(b.yaraRules, b.yaraRes, curVa);
        } else if (mode === 'carve') {
            bodyHtml = renderCarveTab(b.carve, b.iocs, b.iocFilter, curVa);
        } else if (mode === 'hilbert') {
            bodyHtml = renderHilbertTab(b.hilbertOrder, b.hilbert);
        } else {
            bodyHtml = renderQueueAndCollabTab(b.sugs, b.sugDraft, col, curVa);
        }

        const liveTag = col.active ? ' · LIVE' : '';
        const qTag = pendingN > 0 ? ` (${pendingN})` : '';

        container.innerHTML = `
          <div class="ir-wrap">
            <div class="dob-bar">
              <button class="tb-btn${mode === 'vuln' ? ' hi' : ''}" data-audsub="vuln">Vuln Slicer</button>
              <button class="tb-btn${mode === 'yara' ? ' hi' : ''}" data-audsub="yara">YARA Scanner</button>
              <button class="tb-btn${mode === 'carve' ? ' hi' : ''}" data-audsub="carve">Carver &amp; IOCs</button>
              <button class="tb-btn${mode === 'hilbert' ? ' hi' : ''}" data-audsub="hilbert">Hilbert Map</button>
              <button class="tb-btn${mode === 'queue' ? ' hi' : ''}" data-audsub="queue">AI Queue &amp; Live${qTag}${liveTag}</button>
              <span style="flex:1"></span>
              <span class="mono prot-muted">${esc(curVa)}</span>
            </div>
            ${bodyHtml}
          </div>`;

        container.querySelectorAll('[data-audsub]').forEach((btn) => {
            btn.addEventListener('click', () => hooks.onSub(btn.dataset.audsub));
        });

        container.querySelectorAll('[data-jump]').forEach((el) => {
            el.addEventListener('click', (e) => {
                e.stopPropagation();
                const va = el.dataset.jump;
                if (va && va !== '0x0') hooks.onJump(va);
            });
        });

        if (mode === 'vuln') {
            const btn = container.querySelector('#aud-vuln-scan');
            if (btn) btn.addEventListener('click', () => hooks.onVulnScan());
        } else if (mode === 'yara') {
            const ed = container.querySelector('#aud-yara-rules');
            const runBtn = container.querySelector('#aud-yara-run');
            const defBtn = container.querySelector('#aud-yara-def');
            if (ed) ed.addEventListener('input', () => hooks.onYaraDraft(ed.value));
            if (runBtn) runBtn.addEventListener('click', () => hooks.onYaraRun(ed ? ed.value : ''));
            if (defBtn) defBtn.addEventListener('click', () => hooks.onYaraDefaults());
            container.querySelectorAll('.yara-row').forEach((tr) => {
                tr.addEventListener('click', () => {
                    const va = tr.dataset.yva;
                    const off = Number(tr.dataset.yoff || 0);
                    if (va && va !== '0x0') hooks.onJump(va);
                    else if (hooks.onJumpHex) hooks.onJumpHex(off, va);
                });
            });
        } else if (mode === 'carve') {
            const carveItems = (b.carve && b.carve.ok && Array.isArray(b.carve.items)) ? b.carve.items : [];
            const cScan = container.querySelector('#aud-carve-scan');
            const iScan = container.querySelector('#aud-ioc-scan');
            const iCopy = container.querySelector('#aud-ioc-copy');
            const iFlt = container.querySelector('#aud-ioc-filter');
            const iList = container.querySelector('#aud-ioc-list');
            const iCnt = container.querySelector('#aud-ioc-cnt');

            if (cScan) cScan.addEventListener('click', () => hooks.onCarveScan());
            if (iScan) iScan.addEventListener('click', () => hooks.onIocScan());

            container.querySelectorAll('.carve-row').forEach((row) => {
                row.addEventListener('click', () => {
                    const va = row.dataset.cva;
                    const off = Number(row.dataset.coff || 0);
                    if (va && va !== '0x0') hooks.onJump(va);
                    else if (hooks.onJumpHex) hooks.onJumpHex(off, va);
                });
            });
            container.querySelectorAll('[data-carve-ext]').forEach((btn) => {
                btn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const item = carveItems[Number(btn.dataset.carveExt)];
                    if (item && hooks.onCarveExtract) hooks.onCarveExtract(item);
                });
            });

            let curFiltered = fillIocList(iList, iCnt, iCopy, b.iocs, b.iocFilter || '', curVa, hooks);
            if (iFlt) {
                iFlt.addEventListener('input', () => {
                    if (hooks.onIocFilter) hooks.onIocFilter(iFlt.value);
                    curFiltered = fillIocList(iList, iCnt, iCopy, b.iocs, iFlt.value, curVa, hooks);
                });
            }
            if (iCopy) {
                iCopy.addEventListener('click', async () => {
                    if (!curFiltered.length) return;
                    const text = curFiltered.map((it) => `${it.kind}\t${it.va}\t${it.value}`).join('\n');
                    try {
                        await navigator.clipboard.writeText(text);
                    } catch (_) {
                        const ta = document.createElement('textarea');
                        ta.value = text;
                        document.body.appendChild(ta);
                        ta.select();
                        document.execCommand('copy');
                        document.body.removeChild(ta);
                    }
                    iCopy.textContent = 'Copied';
                    iCopy.classList.add('hi');
                    setTimeout(() => { iCopy.textContent = 'Copy All'; iCopy.classList.remove('hi'); }, 1200);
                });
            }
        } else if (mode === 'hilbert') {
            const ordSel = container.querySelector('#aud-hilb-ord');
            const runBtn = container.querySelector('#aud-hilb-run');
            if (ordSel) ordSel.addEventListener('change', () => hooks.onHilbertOrder(Number(ordSel.value) || 6));
            if (runBtn) runBtn.addEventListener('click', () => hooks.onHilbertRender(ordSel ? (Number(ordSel.value) || 6) : 6));
            paintHilbertCanvas(container, b.hilbert, hooks);
        } else {
            const refBtn = container.querySelector('#aud-sug-ref');
            const acc80 = container.querySelector('#aud-sug-acc80');
            const rejAll = container.querySelector('#aud-sug-rejall');
            const addBtn = container.querySelector('#aud-sug-add');
            const sVa = container.querySelector('#sug-va');
            const sKind = container.querySelector('#sug-kind');
            const sVal = container.querySelector('#sug-val');
            const sRsn = container.querySelector('#sug-reason');
            const sConf = container.querySelector('#sug-conf');

            const readSugDraft = () => ({
                va: sVa ? sVa.value : curVa,
                kind: sKind ? sKind.value : 'rename',
                val: sVal ? sVal.value : '',
                reason: sRsn ? sRsn.value : '',
                conf: sConf ? sConf.value : '85'
            });
            [sVa, sKind, sVal, sRsn, sConf].forEach((el) => {
                if (!el) return;
                el.addEventListener('input', () => hooks.onSugDraft && hooks.onSugDraft(readSugDraft()));
                el.addEventListener('change', () => hooks.onSugDraft && hooks.onSugDraft(readSugDraft()));
            });
            const doAddSug = () => {
                const d = readSugDraft();
                if (!d.val.trim()) return;
                hooks.onSugAdd({
                    va: d.va.trim() || curVa,
                    kind: d.kind,
                    val: d.val.trim(),
                    reason: d.reason.trim(),
                    conf: Math.max(0, Math.min(100, parseInt(d.conf, 10) || 85))
                });
            };
            if (addBtn) addBtn.addEventListener('click', doAddSug);
            [sVal, sRsn].forEach((el) => {
                if (el) el.addEventListener('keydown', (e) => { if (e.key === 'Enter') doAddSug(); });
            });
            if (refBtn) refBtn.addEventListener('click', () => hooks.onSugRefresh());
            if (acc80) acc80.addEventListener('click', () => hooks.onSugDecide(0, 1, 80));
            if (rejAll) rejAll.addEventListener('click', () => hooks.onSugDecide(0, 0, 0));
            container.querySelectorAll('[data-sug-acc]').forEach((btn) => {
                btn.addEventListener('click', () => hooks.onSugDecide(Number(btn.dataset.sugAcc), 1, 0));
            });
            container.querySelectorAll('[data-sug-rej]').forEach((btn) => {
                btn.addEventListener('click', () => hooks.onSugDecide(Number(btn.dataset.sugRej), 0, 0));
            });

            const cNick = container.querySelector('#col-nick');
            const cHost = container.querySelector('#col-host');
            const cPort = container.querySelector('#col-port');
            const cPass = container.querySelector('#col-pass');
            const cHostBtn = container.querySelector('#col-host-btn');
            const cJoinBtn = container.querySelector('#col-join-btn');
            const cStopBtn = container.querySelector('#col-stop-btn');
            const cChatIn = container.querySelector('#col-chat-in');
            const cChatSend = container.querySelector('#col-chat-send');
            const cLog = container.querySelector('#col-log');

            const syncColDraft = () => {
                if (hooks.onCollabDraft) {
                    hooks.onCollabDraft({
                        nick: cNick ? cNick.value : 'analyst',
                        host: cHost ? cHost.value : '127.0.0.1',
                        port: cPort ? cPort.value : '4545',
                        pass: cPass ? cPass.value : '',
                        chatDraft: cChatIn ? cChatIn.value : ''
                    });
                }
            };
            [cNick, cHost, cPort, cPass, cChatIn].forEach((el) => {
                if (el) el.addEventListener('input', syncColDraft);
            });
            if (cHostBtn) {
                cHostBtn.addEventListener('click', () => hooks.onCollabHost({
                    nick: (cNick && cNick.value.trim()) || 'host',
                    host: (cHost && cHost.value.trim()) || '127.0.0.1',
                    port: parseInt(cPort ? cPort.value : '4545', 10) || 4545,
                    pass: cPass ? cPass.value : ''
                }));
            }
            if (cJoinBtn) {
                cJoinBtn.addEventListener('click', () => hooks.onCollabJoin({
                    nick: (cNick && cNick.value.trim()) || 'guest',
                    host: (cHost && cHost.value.trim()) || '127.0.0.1',
                    port: parseInt(cPort ? cPort.value : '4545', 10) || 4545,
                    pass: cPass ? cPass.value : ''
                }));
            }
            if (cStopBtn) cStopBtn.addEventListener('click', () => hooks.onCollabStop());

            const doSendChat = () => {
                if (!cChatIn) return;
                const text = cChatIn.value.trim();
                if (!text) return;
                cChatIn.value = '';
                syncColDraft();
                hooks.onCollabChat(text);
            };
            if (cChatSend) cChatSend.addEventListener('click', doSendChat);
            if (cChatIn) cChatIn.addEventListener('keydown', (e) => { if (e.key === 'Enter') doSendChat(); });

            wireCollabDynamicLinks(container.querySelector('#col-peers-bar'), hooks);
            if (cLog) {
                wireCollabDynamicLinks(cLog, hooks);
                cLog.scrollTop = cLog.scrollHeight;
            }
        }
    }

    const api = {
        exportSvgMarkup,
        renderIR,
        renderSnapshotsModal,
        renderSigModal,
        renderDiff,
        renderTypes,
        renderDebug,
        renderCallsHub,
        renderDeobfLab,
        renderTraceLab,
        renderAudit,
        updateAuditCollab,
        setCollabActive,
        broadcastCollab
    };
    window.xdisPro = api;
    return api;
})();
