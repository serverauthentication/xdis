window.vw = (() => {
    const REGS = new Set([
        'rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','rip',
        'eax','ebx','ecx','edx','esi','edi','ebp','esp','eip',
        'ax','bx','cx','dx','si','di','bp','sp','al','bl','cl','dl',
        'ah','bh','ch','dh','sil','dil','bpl','spl',
        'r8','r9','r10','r11','r12','r13','r14','r15',
        'r8d','r9d','r10d','r11d','r12d','r13d','r14d','r15d',
        'r8w','r9w','r10w','r11w','r12w','r13w','r14w','r15w',
        'r8b','r9b','r10b','r11b','r12b','r13b','r14b','r15b',
        'cs','ds','es','fs','gs','ss'
    ]);
    const PTRS = new Set(['byte','word','dword','qword','xmmword','ymmword','ptr']);
    const CKW  = new Set(['if','else','while','for','do','switch','case','default','return','break','continue','goto','void','const','struct','sizeof','NULL','true','false']);
    const CTYP = new Set(['bool','int64_t','uint64_t','int32_t','uint32_t','uint16_t','int16_t','uint8_t','int8_t','char','wchar_t','short','long','int','unsigned','float','double','fn_t','size_t','HANDLE','BOOL','DWORD','LPCWSTR','LPCSTR','LPSTR','LPWSTR','LPVOID','PVOID','HMODULE','FARPROC','FILE','HWND','HKEY','SOCKET']);
    const numFmtMap = new Map();

    function clearNumFormats() {
        numFmtMap.clear();
    }

    function isPrintableByte(v) {
        return v >= 0x20n && v <= 0x7en;
    }

    function formatNumVal(v, fmt) {
        if (fmt === 'dec') return v.toString(10);
        if (fmt === 'char' && isPrintableByte(v)) {
            const ch = String.fromCharCode(Number(v));
            const out = ch === "'" ? "\\'" : ch === '\\' ? '\\\\' : ch;
            return `'${out}'`;
        }
        return '0x' + v.toString(16);
    }

    function nextNumFmt(cur, v) {
        if (cur === 'hex') return 'dec';
        if (cur === 'dec') return isPrintableByte(v) ? 'char' : 'hex';
        return 'hex';
    }

    function esc(s) {
        return String(s || '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    }

    function padVa(va) {
        return String(va || '0x0').replace(/^0x/i, '').padStart(16, '0');
    }

    function mnemCls(flow) {
        if (flow === 3) return 'f-call';
        if (flow === 1 || flow === 2) return 'f-jmp';
        if (flow === 4 || flow === 5) return 'f-ret';
        return 'f-norm';
    }

    function hiAsmOps(ops, tgt, tsym, tmem) {
        if (tgt && !tmem && tsym) {
            return `<span class="t-sym" data-tgt="${esc(tgt)}">${esc(tsym)}</span>`;
        }
        return esc(ops).replace(/\b(0x[0-9a-fA-F]+|\d+|[a-zA-Z_]\w*)\b/g, (tok) => {
            const lo = tok.toLowerCase();
            if (/^0x[0-9a-f]+$/i.test(tok) || /^\d+$/.test(tok)) {
                if (tgt && tok.toLowerCase() === tgt.toLowerCase()) {
                    return `<span class="t-sym" data-tgt="${esc(tgt)}">${tok}</span>`;
                }
                return `<span class="t-num">${tok}</span>`;
            }
            if (REGS.has(lo) || /^[xy]mm\d+$/.test(lo)) return `<span class="t-reg">${tok}</span>`;
            if (PTRS.has(lo)) return `<span class="t-ptr">${tok}</span>`;
            return tok;
        });
    }

    function hiC(text, selVar, lineKey, varMap, extraTypes) {
        let out = '';
        let i = 0;
        let numIdx = 0;
        while (i < text.length) {
            const ch = text[i];
            if (ch === '/' && text[i + 1] === '/') {
                out += `<span class="t-cmt">${esc(text.slice(i))}</span>`;
                break;
            }
            if (ch === 'L' && (text[i + 1] === '"' || text[i + 1] === "'")) {
                const q = text[i + 1];
                let j = i + 2;
                while (j < text.length && text[j] !== q) { if (text[j] === '\\') j++; j++; }
                out += `<span class="t-str">${esc(text.slice(i, j + 1))}</span>`;
                i = j + 1;
            } else if (ch === '"' || ch === "'") {
                const q = ch;
                let j = i + 1;
                while (j < text.length && text[j] !== q) { if (text[j] === '\\') j++; j++; }
                out += `<span class="t-str">${esc(text.slice(i, j + 1))}</span>`;
                i = j + 1;
            } else if ((ch === '-' && text[i + 1] === '>') || (ch === '.' && /[a-zA-Z_]/.test(text[i + 1] || ''))) {
                const op = ch === '-' ? '-&gt;' : '.';
                i += ch === '-' ? 2 : 1;
                let j = i;
                while (j < text.length && /\w/.test(text[j])) j++;
                const fld = text.slice(i, j);
                out += op + (fld ? `<span class="t-fld">${esc(fld)}</span>` : '');
                i = j;
            } else if (/[a-zA-Z_]/.test(ch)) {
                let j = i + 1;
                while (j < text.length && /\w/.test(text[j])) j++;
                const w = text.slice(i, j);
                const vinfo = varMap ? varMap.get(w) : null;
                const orig = vinfo ? vinfo.orig : w;
                const vsel = (selVar && (selVar === w || selVar === orig)) ? ' var-hi' : '';
                if (CKW.has(w)) out += `<span class="t-kw">${w}</span>`;
                else if (CTYP.has(w) || (extraTypes && extraTypes.has(w))) out += `<span class="t-type">${esc(w)}</span>`;
                else if (text[j] === '(') out += `<span class="t-fn" data-sym="${esc(w)}">${esc(w)}</span>`;
                else if (/^(loc_|g_|sub_)/.test(w)) out += `<span class="t-sym" data-sym="${esc(w)}">${esc(w)}</span>`;
                else if (vinfo) {
                    const tip = `${vinfo.type} ${vinfo.name}${vinfo.arg ? ' (param)' : (vinfo.stack_off ? ` (stack ${vinfo.stack_off})` : '')} — Click select, Dbl-click rename, Right-click/Y retype`;
                    out += `<span class="t-reg t-var${vsel}" data-var="${esc(w)}" data-orig="${esc(orig)}" title="${esc(tip)}">${esc(w)}</span>`;
                } else if (/^(a\d+|v\d+|var_\w+|stk_\w+|arg_\w+)$/.test(w)) {
                    out += `<span class="t-reg t-var${vsel}" data-var="${esc(w)}" data-orig="${esc(w)}">${esc(w)}</span>`;
                } else {
                    out += `<span class="t-var${vsel}" data-var="${esc(w)}" data-orig="${esc(w)}">${esc(w)}</span>`;
                }
                i = j;
            } else if (/[0-9]/.test(ch)) {
                let j = i;
                if (text[i] === '0' && (text[i + 1] === 'x' || text[i + 1] === 'X')) {
                    j += 2;
                    while (j < text.length && /[0-9a-fA-F]/.test(text[j])) j++;
                    while (j < text.length && /[uUlL]/.test(text[j])) j++;
                } else {
                    while (j < text.length && /[0-9]/.test(text[j])) j++;
                    if (text[j] === '.' && /[0-9]/.test(text[j + 1] || '')) {
                        j++;
                        while (j < text.length && /[0-9eE+-]/.test(text[j])) j++;
                        if (text[j] === 'f' || text[j] === 'F') j++;
                    }
                }
                const num = text.slice(i, j);
                if (/^0x[0-9a-f]{5,}$/i.test(num)) {
                    out += `<span class="t-sym" data-tgt="${num}">${num}</span>`;
                } else if (num.includes('.') || /[uUlLfF]$/.test(num)) {
                    out += `<span class="t-num">${esc(num)}</span>`;
                } else {
                    let v = null;
                    try { v = BigInt(num); } catch (_) {}
                    if (v !== null && lineKey) {
                        const key = `${lineKey}:${numIdx++}`;
                        const origFmt = /^0x/i.test(num) ? 'hex' : 'dec';
                        const fmt = numFmtMap.get(key) || origFmt;
                        const disp = fmt === origFmt && !numFmtMap.has(key) ? num : formatNumVal(v, fmt);
                        out += `<span class="t-num dec-num" data-nkey="${esc(key)}" data-nval="${v.toString()}" data-nfmt="${fmt}" title="Click to toggle hex / dec / ASCII">${esc(disp)}</span>`;
                    } else {
                        out += `<span class="t-num">${esc(num)}</span>`;
                    }
                }
                i = j;
            } else {
                out += esc(ch);
                i++;
            }
        }
        return out;
    }

    function renderDis(container, rows, curVa, syncVa, showBytes, explainOn, hooks) {
        const html = ['<div class="dis-wrap">'];
        for (const r of rows) {
            if (r.sym) {
                const xr = r.xrefs ? `xrefs: ${r.xrefs}` : '';
                html.push(`<div class="dis-hdr" data-va="${r.va}"><span>${esc(r.sym)}:</span><span class="hdr-meta">${esc(r.sec)} ${xr}</span></div>`);
            }
            const isCur = r.va.toLowerCase() === curVa.toLowerCase();
            const isSync = syncVa && r.va.toLowerCase() === syncVa.toLowerCase();
            let cmtHtml = '';
            if (r.cmt) cmtHtml = `<span class="c-cmt">; ${esc(r.cmt)}</span>`;
            else if (r.tstr) cmtHtml = `<span class="c-cmt is-str">; "${esc(r.tstr)}"</span>`;
            else if (r.tsym && r.tmem) cmtHtml = `<span class="c-cmt is-sym" data-tgt="${esc(r.tgt)}">; ${esc(r.tsym)}</span>`;
            else if (explainOn && window.triView) {
                const gl = window.triView.explain(r.mnem);
                if (gl) cmtHtml = `<span class="c-cmt is-gl">; ${esc(gl)}</span>`;
            }

            const bytesCol = (showBytes && !explainOn) ? `<span class="c-bytes">${esc(r.bytes)}</span>` : '';
            const tip = window.triView ? window.triView.explain(r.mnem) : '';
            html.push(
                `<div class="dis-row${isCur ? ' cur' : ''}${isSync ? ' sync' : ''}" data-va="${r.va}"${r.tgt ? ` data-tgt="${r.tgt}"` : ''}>`
                + `<span class="c-addr">${padVa(r.va)}</span>`
                + bytesCol
                + `<span class="c-mnem ${mnemCls(r.flow)}"${tip ? ` title="${esc(tip)}"` : ''}>${esc(r.mnem)}</span>`
                + `<span class="c-ops"${explainOn ? ' style="min-width:17ch"' : ''}>${hiAsmOps(r.ops, r.tgt, r.tsym, r.tmem)}</span>`
                + cmtHtml
                + `</div>`
            );
        }
        html.push('</div>');
        container.innerHTML = html.join('');

        container.querySelectorAll('.dis-row').forEach((el) => {
            el.addEventListener('click', () => hooks.onSelect(el.dataset.va));
            el.addEventListener('dblclick', () => { if (el.dataset.tgt) hooks.onJump(el.dataset.tgt); });
        });
        container.querySelectorAll('[data-tgt]').forEach((el) => {
            if (el.classList.contains('dis-row')) return;
            el.addEventListener('click', (e) => { e.stopPropagation(); hooks.onJump(el.dataset.tgt); });
            el.addEventListener('mouseenter', (e) => hooks.onPeek(el.dataset.tgt, e));
            el.addEventListener('mouseleave', () => hooks.onHidePeek());
        });
    }

    function renderDec(container, dec, curVa, selVar, hooks) {
        if (!dec || !dec.ok || !dec.lines || dec.lines.length === 0) {
            container.innerHTML = '<div class="welcome"><p>Select executable code to decompile.</p></div>';
            return;
        }
        let curBig = 0n;
        try { curBig = BigInt(curVa || '0x0'); } catch (_) {}
        const fnKey = dec.func_va || '0x0';
        const varMap = new Map();
        const extraTypes = new Set();
        const vars = Array.isArray(dec.vars) ? dec.vars : [];
        for (const v of vars) {
            if (v.name) varMap.set(v.name, v);
            if (v.orig) varMap.set(v.orig, v);
            if (v.type) {
                const base = v.type.replace(/\bconst\b/g, '').replace(/[*&]/g, '').trim();
                if (base && /^[A-Za-z_]\w*$/.test(base)) extraTypes.add(base);
            }
        }

        // range-accurate sync: exact match first, otherwise nearest preceding statement VA
        let syncIdx = -1;
        let bestVa = 0n;
        for (let idx = 0; idx < dec.lines.length; idx++) {
            const raw = dec.lines[idx].va;
            if (!raw || raw === '0x0') continue;
            let lva = 0n;
            try { lva = BigInt(raw); } catch (_) { continue; }
            if (lva === curBig) { syncIdx = idx; break; }
            if (curBig > 0n && lva <= curBig && lva >= bestVa) { bestVa = lva; syncIdx = idx; }
        }

        const html = ['<div class="dec-wrap">'];
        dec.lines.forEach((ln, idx) => {
            const hasVa = ln.va && ln.va !== '0x0';
            const sync = idx === syncIdx;
            html.push(
                `<div class="dec-row${sync ? ' sync' : ''}"${hasVa ? ` data-va="${ln.va}"` : ''}>`
                + `<span class="dec-ln">${idx + 1}</span>`
                + `<span class="dec-code">${hiC(ln.text, selVar, `${fnKey}:${idx}`, varMap, extraTypes)}</span>`
                + `</div>`
            );
        });
        html.push('</div>');
        container.innerHTML = html.join('');

        container.querySelectorAll('.dec-row[data-va]').forEach((el) => {
            el.addEventListener('click', () => hooks.onSyncVa(el.dataset.va));
        });
        container.querySelectorAll('.dec-num').forEach((el) => {
            el.addEventListener('click', (e) => {
                e.stopPropagation();
                const v = BigInt(el.dataset.nval);
                const next = nextNumFmt(el.dataset.nfmt, v);
                el.dataset.nfmt = next;
                el.textContent = formatNumVal(v, next);
                numFmtMap.set(el.dataset.nkey, next);
            });
        });
        container.querySelectorAll('.t-var').forEach((el) => {
            const vname = el.dataset.var;
            const orig = el.dataset.orig || vname;
            el.addEventListener('click', (e) => {
                e.stopPropagation();
                hooks.onSelectVar(orig);
            });
            el.addEventListener('dblclick', (e) => {
                e.stopPropagation();
                hooks.onRenameVar(orig);
            });
            el.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                e.stopPropagation();
                hooks.onSelectVar(orig);
                if (hooks.onRetypeVar) hooks.onRetypeVar(orig);
            });
        });
        container.querySelectorAll('[data-sym], [data-tgt]').forEach((el) => {
            const sym = el.dataset.sym;
            const tgt = el.dataset.tgt;
            el.addEventListener('dblclick', (e) => { e.stopPropagation(); hooks.onSymJump(tgt || sym); });
            el.addEventListener('mouseenter', (e) => hooks.onSymPeek(tgt || sym, e));
            el.addEventListener('mouseleave', () => hooks.onHidePeek());
        });

        const synced = container.querySelector('.dec-row.sync');
        if (synced) synced.scrollIntoView({ block: 'nearest' });
    }

    function renderHex(container, data, curVa, hooks) {
        if (!data || !data.ok) return;
        const curBig = BigInt(curVa || '0x0');
        const html = ['<div class="hex-wrap">'];
        for (const r of data.rows) {
            const base = BigInt(r.va);
            const inRow = curBig >= base && curBig < base + 16n;
            let bytes = '', asc = '';
            for (let i = 0; i < 16; i++) {
                const va = '0x' + (base + BigInt(i)).toString(16);
                const sel = base + BigInt(i) === curBig;
                const gap = i === 7 ? ' gap' : '';
                if (i < r.n) {
                    const b = r.hex.slice(i * 2, i * 2 + 2);
                    const v = parseInt(b, 16);
                    bytes += `<span class="hb${v === 0 ? ' zero' : ''}${sel ? ' sel' : ''}${gap}" data-va="${va}">${b}</span>`;
                    asc += (v >= 0x20 && v <= 0x7E) ? esc(String.fromCharCode(v)) : '.';
                } else {
                    bytes += `<span class="hb zero${gap}">--</span>`;
                    asc += ' ';
                }
            }
            html.push(`<div class="hex-row${inRow ? ' cur' : ''}"><span class="c-addr">${padVa(r.va)}</span><span class="hex-bytes">${bytes}</span><span class="hex-asc">${asc}</span></div>`);
        }
        html.push('</div>');
        container.innerHTML = html.join('');
        container.querySelectorAll('.hb[data-va]').forEach((el) => {
            el.addEventListener('click', () => hooks.onSelect(el.dataset.va));
            el.addEventListener('dblclick', () => hooks.onPatch(el.dataset.va));
        });
    }

    function entColor(h) {
        if (h >= 7.1) return 'var(--tok-ret)';
        if (h >= 5.5) return 'var(--tok-call)';
        if (h >= 3.0) return 'var(--tok-mnem)';
        return 'var(--tok-str)';
    }

    function renderNav(el, info, curVa, navMode, entMap) {
        if (!info || !info.secs || !info.secs.length) { el.innerHTML = ''; return; }
        const min = BigInt(info.min_va), max = BigInt(info.max_va);
        const span = Number(max - min) || 1;
        const parts = [];

        if (navMode === 'entropy' && entMap && entMap.bins && entMap.bins.length) {
            const w = 100 / entMap.bins.length;
            entMap.bins.forEach((h, i) => {
                const op = Math.min(0.92, Math.max(0.18, h / 8.0));
                parts.push(`<div class="nav-seg" style="left:${i * w}%;width:${w + 0.1}%;background:${entColor(h)};opacity:${op}"></div>`);
            });
        } else {
            for (const s of info.secs) {
                const l = (Number(BigInt(s.va) - min) / span) * 100;
                const w = Math.max(0.4, (Number(s.vsize) / span) * 100);
                const cls = (s.perm & 4) ? 'exec' : (s.perm & 2) ? 'rw' : 'ro';
                parts.push(`<div class="nav-seg ${cls}" style="left:${l}%;width:${w}%"></div>`);
            }
        }
        if (curVa) {
            const p = Math.min(99.8, Math.max(0, (Number(BigInt(curVa) - min) / span) * 100));
            parts.push(`<div class="nav-needle" style="left:${p}%"></div>`);
        }
        el.innerHTML = parts.join('');
    }

    function renderInspector(el, ins, hooks) {
        if (!ins || !ins.ok) {
            el.innerHTML = '<div class="ins-empty">Select an address to inspect bytes, types, and entropy.</div>';
            return;
        }
        const bytes = new Uint8Array(16);
        for (let i = 0; i < ins.n && i < 16; i++) bytes[i] = parseInt(ins.hex.slice(i * 2, i * 2 + 2), 16);
        const dv = new DataView(bytes.buffer);
        const u8 = ins.n >= 1 ? dv.getUint8(0) : 0;
        const i8 = ins.n >= 1 ? dv.getInt8(0) : 0;
        const u16 = ins.n >= 2 ? dv.getUint16(0, true) : 0;
        const u32 = ins.n >= 4 ? dv.getUint32(0, true) : 0;
        const i32 = ins.n >= 4 ? dv.getInt32(0, true) : 0;
        const u64 = ins.n >= 8 ? dv.getBigUint64(0, true) : 0n;
        const f32 = ins.n >= 4 ? dv.getFloat32(0, true) : 0;
        const f64 = ins.n >= 8 ? dv.getFloat64(0, true) : 0;
        let asc = '', u16s = '';
        for (let i = 0; i < ins.n; i++) asc += (bytes[i] >= 0x20 && bytes[i] <= 0x7E) ? String.fromCharCode(bytes[i]) : '.';
        for (let i = 0; i + 1 < ins.n; i += 2) {
            const ch = bytes[i] | (bytes[i + 1] << 8);
            u16s += (ch >= 0x20 && ch <= 0x7E) ? String.fromCharCode(ch) : '.';
        }
        const perm = `${ins.perm & 1 ? 'r' : '-'}${ins.perm & 2 ? 'w' : '-'}${ins.perm & 4 ? 'x' : '-'}`;
        const entPct = Math.min(100, Math.round((ins.ent / 8.0) * 100));

        el.innerHTML = `
          <div class="ins-sec">
            <div class="ins-title">Location</div>
            <div class="ins-kv"><span>VA</span><b class="mono">${ins.va}</b></div>
            <div class="ins-kv"><span>File offset</span><b class="mono">${ins.has_off ? '0x' + ins.off.toString(16) : '—'}</b></div>
            <div class="ins-kv"><span>Section</span><b class="mono">${esc(ins.sec)} (${perm})</b></div>
            <div class="ins-kv"><span>Function</span><b class="mono t-sym">${esc(ins.fn || '—')}</b></div>
            <div class="ins-kv"><span>Xrefs to VA</span><b class="mono">${ins.xrefs}</b></div>
          </div>
          <div class="ins-sec">
            <div class="ins-title">Local entropy (256B) <span class="mono">${ins.ent.toFixed(2)} / 8.0</span></div>
            <div class="ent-bar"><div class="ent-fill" style="width:${entPct}%;background:${entColor(ins.ent)}"></div></div>
          </div>
          <div class="ins-sec">
            <div class="ins-title">Data interpreter</div>
            <div class="ins-kv"><span>u8 / i8</span><b class="mono">0x${u8.toString(16).padStart(2,'0')} (${u8} / ${i8})</b></div>
            <div class="ins-kv"><span>u16</span><b class="mono">0x${u16.toString(16)} (${u16})</b></div>
            <div class="ins-kv"><span>u32 / i32</span><b class="mono">0x${u32.toString(16)} (${i32})</b></div>
            <div class="ins-kv"><span>u64</span><b class="mono">0x${u64.toString(16)}</b></div>
            <div class="ins-kv"><span>f32</span><b class="mono">${Number.isFinite(f32) ? f32.toPrecision(5) : 'NaN'}</b></div>
            <div class="ins-kv"><span>f64</span><b class="mono">${Number.isFinite(f64) ? f64.toPrecision(6) : 'NaN'}</b></div>
            <div class="ins-kv"><span>ASCII</span><b class="mono t-str">${esc(asc)}</b></div>
            <div class="ins-kv"><span>UTF-16</span><b class="mono t-str">${esc(u16s)}</b></div>
          </div>
          <div class="ins-sec">
            <div class="ins-title">Quick patch &amp; sig (COW)</div>
            <div class="ins-acts">
              <button class="tb-btn" data-qa="nop">NOP ins</button>
              <button class="tb-btn" data-qa="ret0">ret 0</button>
              <button class="tb-btn" data-qa="ret1">ret 1</button>
              <button class="tb-btn" data-qa="asm">Assemble…</button>
              <button class="tb-btn" data-qa="hex">Hex bytes…</button>
              <button class="tb-btn" data-qa="sig">Make Sig</button>
            </div>
          </div>`;

        el.querySelectorAll('[data-qa]').forEach((b) => {
            b.onclick = () => hooks.onQuickPatch(b.dataset.qa);
        });
    }

    function renderPeekHtml(p) {
        const meta = `${p.sec}${p.fsize ? ` | ${p.fsize}B` : ''}${p.xrefs ? ` | ${p.xrefs} xrefs` : ''}`;
        let body = `<div class="peek-head"><span class="peek-sym">${esc(p.sym || p.va)}</span><span class="peek-meta">${esc(meta)}</span></div>`;
        if (p.str) body += `<div class="peek-str">"${esc(p.str)}"</div>`;
        if (p.lines && p.lines.length) {
            body += '<div class="peek-lines">' + p.lines.map((l) =>
                `<div class="peek-row"><span class="c-addr" style="width:10ch">${l.va.slice(-8)}</span>`
                + `<span class="c-mnem ${mnemCls(l.flow)}" style="width:9ch">${esc(l.mnem)}</span>`
                + `<span>${hiAsmOps(l.ops)}</span></div>`
            ).join('') + '</div>';
        }
        return body;
    }

    function sectionRangeFor(info, vaBig) {
        if (info && info.secs && info.secs.length) {
            const sec = info.secs.find((s) => {
                const lo = BigInt(s.va);
                return vaBig >= lo && vaBig < lo + BigInt(s.vsize || 0);
            });
            if (sec) return { name: sec.name || 'sec', start: BigInt(sec.va), size: Math.max(1, Number(sec.vsize || 1)) };
        }
        const lo = BigInt((info && info.min_va) || '0x0');
        const hi = BigInt((info && info.max_va) || '0x1');
        return { name: 'image', start: lo, size: Math.max(1, Number(hi - lo)) };
    }

    function bindVScroll(trackEl, onSeek) {
        if (!trackEl || trackEl._vsBound) return;
        trackEl._vsBound = true;
        const thumb = trackEl.querySelector('.vscroll-thumb');
        const tip = trackEl.querySelector('.vscroll-tip');

        function calcAt(clientY) {
            const st = trackEl._vs;
            if (!st) return null;
            const rect = trackEl.getBoundingClientRect();
            const h = Math.max(1, rect.height);
            const th = st.thumbH || 24;
            const usable = Math.max(1, h - th);
            const y = Math.max(0, Math.min(usable, clientY - rect.top - th / 2));
            const frac = y / usable;
            let va = st.start + BigInt(Math.floor(frac * Math.max(0, st.size - 1)));
            if (st.isHex) {
                va = va & ~15n;
                if (va < st.start) va = st.start;
            }
            return { y, frac, va: '0x' + va.toString(16), name: st.name };
        }

        function showTip(pos) {
            if (!tip || !pos) return;
            const th = (trackEl._vs && trackEl._vs.thumbH) || 24;
            tip.textContent = `${pos.name} · ${(pos.frac * 100).toFixed(1)}% · ${pos.va}`;
            tip.style.top = Math.max(12, Math.min((trackEl.clientHeight || 200) - 12, pos.y + th / 2)) + 'px';
            tip.classList.remove('hidden');
        }

        trackEl.addEventListener('mousedown', (e) => {
            if (!trackEl._vs) return;
            e.preventDefault();
            trackEl._vs.dragging = true;
            trackEl.classList.add('dragging');
            const apply = (ev) => {
                const pos = calcAt(ev.clientY);
                if (!pos) return;
                if (thumb) thumb.style.top = pos.y + 'px';
                showTip(pos);
                onSeek(pos.va);
            };
            apply(e);
            const move = (ev) => apply(ev);
            const up = () => {
                if (trackEl._vs) trackEl._vs.dragging = false;
                trackEl.classList.remove('dragging');
                if (tip) tip.classList.add('hidden');
                window.removeEventListener('mousemove', move);
                window.removeEventListener('mouseup', up);
            };
            window.addEventListener('mousemove', move);
            window.addEventListener('mouseup', up);
        });

        trackEl.addEventListener('mousemove', (e) => {
            if (!trackEl._vs || trackEl._vs.dragging) return;
            showTip(calcAt(e.clientY));
        });
        trackEl.addEventListener('mouseleave', () => {
            if (trackEl._vs && trackEl._vs.dragging) return;
            if (tip) tip.classList.add('hidden');
        });
    }

    function updateVScroll(trackEl, bodyEl, info, topVa, visibleBytes, isHex, active) {
        if (!trackEl || !bodyEl) return;
        if (!active || !info || !topVa) {
            trackEl.classList.add('hidden');
            bodyEl.classList.remove('vscroll-on');
            trackEl._vs = null;
            return;
        }
        trackEl.classList.remove('hidden');
        bodyEl.classList.add('vscroll-on');
        const vaBig = BigInt(topVa);
        const rng = sectionRangeFor(info, vaBig);
        const h = Math.max(48, trackEl.clientHeight || bodyEl.clientHeight || 400);
        const th = Math.round(Math.max(24, Math.min(h * 0.45, h * ((visibleBytes || 256) / rng.size))));
        const usable = Math.max(1, h - th);
        const frac = Math.max(0, Math.min(1, Number(vaBig - rng.start) / rng.size));
        const dragging = !!(trackEl._vs && trackEl._vs.dragging);
        trackEl._vs = { name: rng.name, start: rng.start, size: rng.size, thumbH: th, isHex: !!isHex, dragging };

        const thumb = trackEl.querySelector('.vscroll-thumb');
        if (thumb) {
            thumb.style.height = th + 'px';
            if (!dragging) thumb.style.top = Math.round(frac * usable) + 'px';
        }
    }

    return { esc, padVa, clearNumFormats, renderDis, renderDec, renderHex, renderNav, renderInspector, renderPeekHtml, bindVScroll, updateVScroll };
})();
