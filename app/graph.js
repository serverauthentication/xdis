window.cfgView = (() => {
    let tx = 28, ty = 20, scale = 1.0;
    let lastFunc = '';
    let drag = null;

    window.addEventListener('mousemove', (e) => {
        if (!drag) return;
        tx = drag.ox + (e.clientX - drag.sx);
        ty = drag.oy + (e.clientY - drag.sy);
        drag.apply();
    });
    window.addEventListener('mouseup', () => {
        if (!drag) return;
        drag.stage.classList.remove('dragging');
        drag = null;
    });

    function flowColor(flow) {
        if (flow === 3) return 'var(--tok-call)';
        if (flow === 1 || flow === 2) return 'var(--tok-jmp)';
        if (flow === 4 || flow === 5) return 'var(--tok-ret)';
        return 'var(--tok-mnem)';
    }

    function esc(s) {
        return String(s || '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    }

    function edgePath(a, b, kind, back) {
        const sx = a.x + (kind === 1 ? a.w * 0.66 : kind === 2 ? a.w * 0.34 : a.w * 0.5);
        const sy = a.y + a.h;
        const ex = b.x + b.w * 0.5;
        const ey = b.y;
        if (!back && ey >= sy) {
            const my = (sy + ey) * 0.5;
            return `M ${sx} ${sy} C ${sx} ${my}, ${ex} ${my}, ${ex} ${ey}`;
        }
        const side = Math.max(a.x + a.w, b.x + b.w) + 28;
        return `M ${sx} ${sy} L ${sx} ${sy + 14} L ${side} ${sy + 14} L ${side} ${ey - 16} L ${ex} ${ey - 16} L ${ex} ${ey}`;
    }

    function render(container, data, curVa, hooks) {
        if (!data || !data.ok || !data.blks || data.blks.length === 0) {
            container.innerHTML = '<div class="welcome"><p>No control flow graph at current address.</p></div>';
            return;
        }

        if (lastFunc !== data.func_va) {
            lastFunc = data.func_va;
            const cw = container.clientWidth || 720;
            tx = Math.max(24, (cw - data.w) * 0.5);
            ty = 20;
            scale = Math.min(1.0, Math.max(0.45, (cw - 48) / Math.max(data.w, 1)));
        }

        const edgeSvg = data.edges.map((e) => {
            const a = data.blks[e.from], b = data.blks[e.to];
            if (!a || !b) return '';
            const cls = e.kind === 1 ? 'e-t' : e.kind === 2 ? 'e-f' : 'e-u';
            const mk = e.kind === 1 ? 'arr-t' : e.kind === 2 ? 'arr-f' : 'arr-u';
            return `<path class="cfg-edge ${cls}${e.back ? ' back' : ''}" d="${edgePath(a, b, e.kind, e.back)}" marker-end="url(#${mk})"/>`;
        }).join('');

        const blkSvg = data.blks.map((b) => {
            const active = BigInt(curVa) >= BigInt(b.start) && BigInt(curVa) < BigInt(b.end);
            const title = b.sym || ('loc_' + b.start.slice(2));
            const maxOp = Math.max(14, Math.floor((b.w - 160) / 7.4));
            const rows = b.ins.map((ins, i) => {
                const y = b.y + 36 + i * 20;
                const isCur = ins.va.toLowerCase() === curVa.toLowerCase();
                const rawOps = (ins.tgt && !ins.tmem && ins.tsym) ? ins.tsym : ins.ops;
                const ops = rawOps.length > maxOp ? rawOps.slice(0, maxOp - 1) + '…' : rawOps;
                const tAttr = ins.tgt ? ` data-tgt="${ins.tgt}"` : '';
                return `<g class="cfg-ins${isCur ? ' cur' : ''}" data-va="${ins.va}"${tAttr}>`
                    + `<rect x="${b.x + 2}" y="${y - 14}" width="${b.w - 4}" height="19" fill="transparent"/>`
                    + `<text x="${b.x + 10}" y="${y}" fill="var(--tok-addr)">${ins.va.slice(-8)}</text>`
                    + `<text x="${b.x + 80}" y="${y}" fill="${flowColor(ins.flow)}">${esc(ins.mnem)}</text>`
                    + `<text x="${b.x + 148}" y="${y}" fill="${ins.tsym ? 'var(--tok-sym)' : 'var(--fg)'}">${esc(ops)}</text>`
                    + `</g>`;
            }).join('');
            return `<g class="cfg-blk${active ? ' active' : ''}">`
                + `<rect class="blk-box" x="${b.x}" y="${b.y}" width="${b.w}" height="${b.h}"/>`
                + `<rect class="blk-hdr" x="${b.x + 1}" y="${b.y + 1}" width="${b.w - 2}" height="22"/>`
                + `<text x="${b.x + 10}" y="${b.y + 16}" fill="var(--tok-sym)" font-weight="600">${esc(title)}</text>`
                + rows + `</g>`;
        }).join('');

        const miniBlks = data.blks.map((b) =>
            `<rect x="${b.x}" y="${b.y}" width="${b.w}" height="${b.h}" fill="var(--border-hi)" rx="2"/>`
        ).join('');

        container.innerHTML = `
          <div class="cfg-stage" id="cfg-stage">
            <div class="cfg-hud">
              <button class="tb-btn" id="cfg-fit">Fit</button>
              <button class="tb-btn" id="cfg-z1">100%</button>
              <button class="tb-btn" id="cfg-exp">SVG</button>
            </div>
            <svg class="cfg-svg" id="cfg-svg">
              <defs>
                <marker id="arr-t" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,1 L9,5 L0,9 z" fill="var(--edge-t)"/></marker>
                <marker id="arr-f" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,1 L9,5 L0,9 z" fill="var(--edge-f)"/></marker>
                <marker id="arr-u" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,1 L9,5 L0,9 z" fill="var(--edge-u)"/></marker>
              </defs>
              <g id="cfg-vp">${edgeSvg}${blkSvg}</g>
            </svg>
            <div class="cfg-mini">
              <svg width="168" height="118" viewBox="0 0 ${Math.max(data.w, 200)} ${Math.max(data.h, 200)}" preserveAspectRatio="xMidYMid meet">
                ${miniBlks}
                <rect id="cfg-mrect" fill="none" stroke="var(--accent)" stroke-width="10"/>
              </svg>
            </div>
          </div>`;

        const stage = container.querySelector('#cfg-stage');
        const vp = container.querySelector('#cfg-vp');
        const mrect = container.querySelector('#cfg-mrect');

        function applyTransform() {
            vp.setAttribute('transform', `translate(${tx},${ty}) scale(${scale})`);
            const vw = (stage.clientWidth || 700) / scale;
            const vh = (stage.clientHeight || 500) / scale;
            mrect.setAttribute('x', -tx / scale);
            mrect.setAttribute('y', -ty / scale);
            mrect.setAttribute('width', vw);
            mrect.setAttribute('height', vh);
        }
        applyTransform();

        stage.addEventListener('mousedown', (e) => {
            if (e.target.closest('.cfg-ins') || e.target.closest('.cfg-hud')) return;
            drag = { sx: e.clientX, sy: e.clientY, ox: tx, oy: ty, stage, apply: applyTransform };
            stage.classList.add('dragging');
        });
        stage.addEventListener('wheel', (e) => {
            e.preventDefault();
            const r = stage.getBoundingClientRect();
            const mx = e.clientX - r.left, my = e.clientY - r.top;
            const f = e.deltaY < 0 ? 1.12 : 0.89;
            const ns = Math.min(2.2, Math.max(0.22, scale * f));
            tx = mx - (mx - tx) * (ns / scale);
            ty = my - (my - ty) * (ns / scale);
            scale = ns;
            applyTransform();
        }, { passive: false });

        stage.querySelector('#cfg-fit').onclick = () => {
            const cw = stage.clientWidth || 700, ch = stage.clientHeight || 500;
            scale = Math.min(1.0, (cw - 40) / Math.max(data.w, 1), (ch - 40) / Math.max(data.h, 1));
            tx = (cw - data.w * scale) * 0.5;
            ty = 18;
            applyTransform();
        };
        stage.querySelector('#cfg-z1').onclick = () => { scale = 1.0; applyTransform(); };
        stage.querySelector('#cfg-exp').onclick = () => {
            if (window.proView) window.proView.exportSvgMarkup(stage.querySelector('#cfg-svg'), (data.name || 'cfg') + '.svg');
        };

        stage.querySelectorAll('.cfg-ins').forEach((el) => {
            const va = el.dataset.va;
            const tgt = el.dataset.tgt;
            el.addEventListener('click', () => hooks.onSelect(va));
            el.addEventListener('dblclick', () => { if (tgt) hooks.onJump(tgt); });
            el.addEventListener('mouseenter', (e) => { if (tgt) hooks.onPeek(tgt, e); });
            el.addEventListener('mouseleave', () => hooks.onHidePeek());
        });
    }

    function renderCallGraph(container, cg, hooks) {
        if (!cg || !cg.ok) {
            container.innerHTML = '<div class="welcome"><p>No call graph at current address.</p></div>';
            return;
        }
        const nw = 216, nh = 34, gap = 10;
        const callers = cg.callers || [];
        const callees = cg.callees || [];
        const rows = Math.max(callers.length, callees.length, 1);
        const totalH = Math.max(240, rows * (nh + gap) + 64);
        const colL = 28, colC = 326, colR = 624;
        const cy = Math.floor(totalH / 2 - nh / 2);

        const nodes = [];
        const edges = [];

        function drawNode(x, y, va, label, cls) {
            const txt = (label || ('sub_' + va.slice(2))).slice(0, 26);
            nodes.push(
                `<g class="cg-node ${cls}" data-va="${va}">`
                + `<rect x="${x}" y="${y}" width="${nw}" height="${nh}" rx="5"/>`
                + `<text x="${x + 10}" y="${y + 21}">${esc(txt)}</text>`
                + `</g>`
            );
        }

        drawNode(colC, cy, cg.va, cg.name || ('sub_' + cg.va.slice(2)), 'cg-center');

        const lStart = Math.floor((totalH - callers.length * (nh + gap)) / 2);
        callers.forEach((c, i) => {
            const y = Math.max(24, lStart) + i * (nh + gap);
            drawNode(colL, y, c.va, c.name, 'cg-in');
            const sx = colL + nw, sy = y + nh / 2, ex = colC, ey = cy + nh / 2, mx = (sx + ex) / 2;
            edges.push(`<path class="cfg-edge e-t" d="M ${sx} ${sy} C ${mx} ${sy}, ${mx} ${ey}, ${ex} ${ey}" marker-end="url(#cg-arr-t)"/>`);
        });

        const rStart = Math.floor((totalH - callees.length * (nh + gap)) / 2);
        callees.forEach((c, i) => {
            const y = Math.max(24, rStart) + i * (nh + gap);
            drawNode(colR, y, c.va, c.name, c.mem ? 'cg-imp' : 'cg-out');
            const sx = colC + nw, sy = cy + nh / 2, ex = colR, ey = y + nh / 2, mx = (sx + ex) / 2;
            edges.push(`<path class="cfg-edge e-u" d="M ${sx} ${sy} C ${mx} ${sy}, ${mx} ${ey}, ${ex} ${ey}" marker-end="url(#cg-arr-u)"/>`);
        });

        container.innerHTML = `
          <div class="cg-wrap">
            <div class="cg-head">
              <span>Callers (${callers.length})</span>
              <span>Current function</span>
              <span>Callees (${callees.length})</span>
            </div>
            <svg width="${colR + nw + 32}" height="${totalH}" class="cg-svg">
              <defs>
                <marker id="cg-arr-t" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,1 L9,5 L0,9 z" fill="var(--edge-t)"/></marker>
                <marker id="cg-arr-u" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,1 L9,5 L0,9 z" fill="var(--edge-u)"/></marker>
              </defs>
              ${edges.join('')}${nodes.join('')}
            </svg>
          </div>`;

        container.querySelectorAll('.cg-node').forEach((el) => {
            const va = el.dataset.va;
            el.addEventListener('click', () => hooks.onJump(va));
            el.addEventListener('mouseenter', (e) => hooks.onPeek(va, e));
            el.addEventListener('mouseleave', () => hooks.onHidePeek());
        });
    }

    return { render, renderCallGraph, reset() { lastFunc = ''; } };
})();
