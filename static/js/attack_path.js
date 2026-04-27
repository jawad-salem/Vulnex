// Vanilla SVG renderer for the attack-path DAG. No D3 / no CDN — keeps CSP
// simple and the bundle weightless. Layout is column-based on topological
// depth; nodes inside the same depth fan out vertically.
(function () {
    'use strict';

    var canvas = document.getElementById('attack-path-canvas');
    if (!canvas) return;

    var dataUrl = canvas.dataset.pathDataUrl;
    var findingUrlPrefix = canvas.dataset.findingUrlPrefix || '/vulns/';
    var SVG_NS = 'http://www.w3.org/2000/svg';

    var KIND_COLOR = {
        entrypoint: '#0ea5e9',
        host:       '#64748b',
        identity:   '#a855f7',
        asset:      '#f59e0b',
        objective:  '#ef4444',
    };

    function fetchData() {
        fetch(dataUrl, { credentials: 'same-origin' })
            .then(function (r) {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            })
            .then(render)
            .catch(function (err) {
                canvas.textContent = 'Failed to load path: ' + err.message;
            });
    }

    function computeDepths(nodes, edges) {
        // Topological depth from any node with no incoming edges.
        var indegree = {}, outAdj = {};
        nodes.forEach(function (n) { indegree[n.id] = 0; outAdj[n.id] = []; });
        edges.forEach(function (e) {
            if (indegree[e.to] !== undefined) indegree[e.to] += 1;
            if (outAdj[e.from]) outAdj[e.from].push(e.to);
        });
        var depths = {};
        var queue = [];
        nodes.forEach(function (n) {
            if (indegree[n.id] === 0) { depths[n.id] = 0; queue.push(n.id); }
        });
        // Fallback: if every node has incoming (cycle), seed with the first.
        if (queue.length === 0 && nodes.length) {
            depths[nodes[0].id] = 0;
            queue.push(nodes[0].id);
        }
        while (queue.length) {
            var cur = queue.shift();
            (outAdj[cur] || []).forEach(function (next) {
                var d = (depths[cur] || 0) + 1;
                if (depths[next] === undefined || d > depths[next]) {
                    depths[next] = d;
                    queue.push(next);
                }
            });
        }
        nodes.forEach(function (n) {
            if (depths[n.id] === undefined) depths[n.id] = 0;
        });
        return depths;
    }

    function layout(nodes, edges, width, height) {
        var depths = computeDepths(nodes, edges);
        var byDepth = {};
        nodes.forEach(function (n) {
            (byDepth[depths[n.id]] = byDepth[depths[n.id]] || []).push(n);
        });
        var depthKeys = Object.keys(byDepth).map(Number).sort(function (a, b) { return a - b; });

        // One pass of barycenter ordering: position each node by the average
        // index of its predecessors in the previous column so edges run roughly
        // parallel instead of fanning across the diagram.
        var orderIndex = {};
        depthKeys.forEach(function (d) {
            byDepth[d].forEach(function (n, i) { orderIndex[n.id] = i; });
        });
        var preds = {};
        edges.forEach(function (e) { (preds[e.to] = preds[e.to] || []).push(e.from); });
        depthKeys.forEach(function (d) {
            if (d === depthKeys[0]) return;
            byDepth[d].sort(function (a, b) {
                function bary(n) {
                    var ps = preds[n.id] || [];
                    if (!ps.length) return orderIndex[n.id];
                    var sum = 0, count = 0;
                    ps.forEach(function (pid) {
                        if (orderIndex[pid] !== undefined) { sum += orderIndex[pid]; count += 1; }
                    });
                    return count ? sum / count : orderIndex[n.id];
                }
                return bary(a) - bary(b);
            });
            byDepth[d].forEach(function (n, i) { orderIndex[n.id] = i; });
        });

        var maxDepth = depthKeys[depthKeys.length - 1] || 0;
        var colSpacing = (width - 160) / Math.max(maxDepth, 1);
        var positions = {};
        depthKeys.forEach(function (d) {
            var col = byDepth[d];
            var rowSpacing = (height - 60) / (col.length + 1);
            col.forEach(function (n, i) {
                positions[n.id] = {
                    x: 80 + d * colSpacing,
                    y: 30 + (i + 1) * rowSpacing,
                };
            });
        });
        return positions;
    }

    function svg(name, attrs, parent) {
        var el = document.createElementNS(SVG_NS, name);
        Object.keys(attrs || {}).forEach(function (k) {
            el.setAttribute(k, attrs[k]);
        });
        if (parent) parent.appendChild(el);
        return el;
    }

    function render(data) {
        canvas.innerHTML = '';
        var nodes = data.nodes || [];
        var edges = data.edges || [];

        if (!nodes.length) {
            var p = document.createElement('p');
            p.className = 'text-secondary text-center';
            p.style.padding = '3rem';
            p.textContent = 'No nodes yet — add one in the sidebar to start mapping the kill chain.';
            canvas.appendChild(p);
            return;
        }

        var width = canvas.clientWidth || 800;
        var height = Math.max(canvas.clientHeight || 480, Math.min(900, nodes.length * 70));

        var root = svg('svg', {
            xmlns: SVG_NS,
            viewBox: '0 0 ' + width + ' ' + height,
            width: width, height: height,
            'class': 'attack-path-svg',
        }, canvas);

        // Arrowhead marker.
        var defs = svg('defs', {}, root);
        var marker = svg('marker', {
            id: 'ap-arrow', viewBox: '0 0 10 10',
            refX: 10, refY: 5, markerWidth: 8, markerHeight: 8,
            orient: 'auto-start-reverse',
        }, defs);
        svg('path', { d: 'M0,0 L10,5 L0,10 z', fill: '#cbd5e1' }, marker);

        var positions = layout(nodes, edges, width, height);

        // Edges first so nodes paint on top.
        edges.forEach(function (e) {
            var p1 = positions[e.from], p2 = positions[e.to];
            if (!p1 || !p2) return;
            var line = svg('line', {
                x1: p1.x, y1: p1.y, x2: p2.x, y2: p2.y,
                stroke: '#cbd5e1', 'stroke-width': 1.5,
                'marker-end': 'url(#ap-arrow)',
                'class': 'ap-edge',
            }, root);
            if (e.finding_pk) {
                line.style.cursor = 'pointer';
                line.addEventListener('click', function () {
                    window.location.href = findingUrlPrefix + e.finding_pk + '/';
                });
            }
            // Label near midpoint.
            var mx = (p1.x + p2.x) / 2;
            var my = (p1.y + p2.y) / 2 - 6;
            var label = e.technique;
            if (e.mitre) label += ' (' + e.mitre + ')';
            var t = svg('text', {
                x: mx, y: my, fill: '#94a3b8', 'font-size': 11,
                'text-anchor': 'middle', 'class': 'ap-edge-label',
            }, root);
            t.textContent = label;
            // Hover title.
            var title = svg('title', {}, line);
            var tip = e.technique;
            if (e.mitre) tip += ' [' + e.mitre + ']';
            if (e.finding_title) tip += '\nFinding: ' + e.finding_title;
            title.textContent = tip;
        });

        nodes.forEach(function (n) {
            var p = positions[n.id];
            if (!p) return;
            var color = KIND_COLOR[n.kind] || '#64748b';
            var g = svg('g', { 'class': 'ap-node', transform: 'translate(' + p.x + ',' + p.y + ')' }, root);
            svg('circle', { r: 18, fill: color, stroke: '#1f2638', 'stroke-width': 2 }, g);
            var lbl = svg('text', {
                y: 36, 'text-anchor': 'middle', 'font-size': 12,
                fill: '#e6edf3', 'class': 'ap-node-label',
            }, g);
            lbl.textContent = n.label.length > 28 ? n.label.slice(0, 27) + '…' : n.label;
            var sub = svg('text', {
                y: 50, 'text-anchor': 'middle', 'font-size': 10,
                fill: '#8b949e',
            }, g);
            sub.textContent = n.kind;
        });
    }

    fetchData();
})();
