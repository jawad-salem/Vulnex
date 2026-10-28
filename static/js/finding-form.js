(function() {
    var form = document.getElementById('findingForm');
    if (!form) return;
    // ── Template picker auto-fill ──
    var tplPicker = document.getElementById('templatePicker');
    if (tplPicker) {
        tplPicker.addEventListener('change', function() {
            var pk = this.value;
            if (!pk) return;
            fetch(form.dataset.templateUrl.replace('/0/', '/' + pk + '/'))
                .then(function(r) { return r.json(); })
                .then(function(d) {
                    var fields = [
                        'title', 'description', 'remediation', 'references', 'cwe_id',
                        'attack_vector', 'attack_complexity', 'privileges_required',
                        'user_interaction', 'scope', 'confidentiality_impact',
                        'integrity_impact', 'availability_impact'
                    ];
                    fields.forEach(function(f) {
                        var el = document.getElementById('id_' + f);
                        if (el && d[f] !== undefined) {
                            el.value = d[f];
                        }
                    });
                    updateCvssPreview();
                    form.dispatchEvent(new Event('finding:updated'));
                });
        });
    }

    // ── Discovered host auto-fill ──
    var hostField = document.getElementById('id_host');
    var urlField = document.getElementById('id_url');
    var endpointField = document.getElementById('id_endpoint');
    var hostSelect = document.getElementById('id_discovered_host');

    // Track whether user has manually edited the endpoint — once they do,
    // we stop auto-populating it from the URL
    var endpointDirty = endpointField && endpointField.value.trim() !== '';
    if (endpointField) {
        endpointField.addEventListener('input', function() {
            endpointDirty = true;
        });
    }

    // Track whether the URL was set by us (auto-filled from host selector)
    // vs typed by the user. If auto-filled, changing the host can safely
    // replace it; if user-typed, we leave it alone.
    var urlDirty = urlField && urlField.value.trim() !== '';
    if (urlField) {
        urlField.addEventListener('input', function(e) {
            // Only mark dirty if the event came from actual user input,
            // not from our programmatic dispatchEvent('input') below
            if (e.isTrusted) urlDirty = true;
        });
    }

    function extractPath(urlStr) {
        if (!urlStr) return '';
        try {
            // If no scheme, URL() will throw — prepend one so parsing works
            var toParse = /^https?:\/\//i.test(urlStr) ? urlStr : 'https://' + urlStr;
            var u = new URL(toParse);
            var path = u.pathname + u.search;
            // "/" alone means no real path — treat as empty
            return (path === '/' && !u.search) ? '' : path;
        } catch (e) {
            return '';
        }
    }

    if (urlField) {
        urlField.addEventListener('input', function() {
            if (endpointDirty) return;
            var path = extractPath(urlField.value);
            endpointField.value = path;
        });
    }

    if (hostSelect) {
        hostSelect.addEventListener('change', function() {
            var pk = this.value;
            if (!pk) return;
            fetch(form.dataset.hostUrl.replace('/0/', '/' + pk + '/'))
                .then(function(r) { return r.json(); })
                .then(function(d) {
                    if (hostField && d.hostname) {
                        hostField.value = d.hostname;
                    }
                    // Seed URL with https://hostname — overwrite only if the
                    // URL wasn't manually typed by the user
                    if (urlField && !urlDirty && d.hostname) {
                        urlField.value = 'https://' + d.hostname;
                        // Trigger path extraction (none, so endpoint stays empty)
                        urlField.dispatchEvent(new Event('input', { bubbles: true }));
                    }
                    form.dispatchEvent(new Event('finding:updated'));
                });
        });
    }

    // ── Live CVSS severity preview ──
    var cvssFields = [
        'id_attack_vector', 'id_attack_complexity', 'id_privileges_required',
        'id_user_interaction', 'id_scope', 'id_confidentiality_impact',
        'id_integrity_impact', 'id_availability_impact'
    ];

    var avScores = {N: 0.85, A: 0.62, L: 0.55, P: 0.20};
    var acScores = {L: 0.77, H: 0.44};
    var prScoresU = {N: 0.85, L: 0.62, H: 0.27};
    var prScoresC = {N: 0.85, L: 0.68, H: 0.50};
    var uiScores = {N: 0.85, R: 0.62};
    var impactScores = {H: 0.56, L: 0.22, N: 0.0};

    // Official CVSS Roundup (spec §7.1) — integer-precision to avoid FP errors
    function cvssRoundup(x) {
        var intInput = Math.round(x * 100000);
        if (intInput % 10000 === 0) return intInput / 100000;
        return (Math.floor(intInput / 10000) + 1) / 10;
    }

    function updateCvssPreview() {
        var av = document.getElementById('id_attack_vector').value;
        var ac = document.getElementById('id_attack_complexity').value;
        var pr = document.getElementById('id_privileges_required').value;
        var ui = document.getElementById('id_user_interaction').value;
        var scopeEl = document.getElementById('id_scope');
        var scope = scopeEl ? scopeEl.value : 'U';
        var c = document.getElementById('id_confidentiality_impact').value;
        var i = document.getElementById('id_integrity_impact').value;
        var a = document.getElementById('id_availability_impact').value;

        var iss = 1 - ((1 - impactScores[c]) * (1 - impactScores[i]) * (1 - impactScores[a]));
        var preview = document.getElementById('cvssPreview');
        var badge = document.getElementById('cvssBadge');

        if (iss <= 0) {
            badge.textContent = 'Info — 0.0';
            badge.className = 'badge badge-lg badge-info';
            preview.style.display = 'flex';
            return;
        }

        var scopeChanged = scope === 'C';
        var prScores = scopeChanged ? prScoresC : prScoresU;
        var impact = scopeChanged
            ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
            : 6.42 * iss;

        if (impact <= 0) {
            badge.textContent = 'Info — 0.0';
            badge.className = 'badge badge-lg badge-info';
            preview.style.display = 'flex';
            return;
        }

        var exploitability = 8.22 * avScores[av] * acScores[ac] * prScores[pr] * uiScores[ui];
        var raw = impact + exploitability;
        if (scopeChanged) raw *= 1.08;
        var score = cvssRoundup(Math.min(raw, 10.0));

        var severity, cls;
        if (score >= 9.0) { severity = 'Critical'; cls = 'badge-critical'; }
        else if (score >= 7.0) { severity = 'High'; cls = 'badge-high'; }
        else if (score >= 4.0) { severity = 'Medium'; cls = 'badge-medium'; }
        else if (score >= 0.1) { severity = 'Low'; cls = 'badge-low'; }
        else { severity = 'Info'; cls = 'badge-info'; }

        badge.textContent = severity + ' — ' + score.toFixed(1);
        badge.className = 'badge badge-lg ' + cls;
        preview.style.display = 'flex';
    }

    cvssFields.forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.addEventListener('change', updateCvssPreview);
    });

    // ── CVSS vector string paste ──
    var vectorMap = {
        'AV': {field: 'attack_vector', allowed: ['N', 'A', 'L', 'P']},
        'AC': {field: 'attack_complexity', allowed: ['L', 'H']},
        'PR': {field: 'privileges_required', allowed: ['N', 'L', 'H']},
        'UI': {field: 'user_interaction', allowed: ['N', 'R']},
        'S':  {field: 'scope', allowed: ['U', 'C']},
        'C':  {field: 'confidentiality_impact', allowed: ['H', 'L', 'N']},
        'I':  {field: 'integrity_impact', allowed: ['H', 'L', 'N']},
        'A':  {field: 'availability_impact', allowed: ['H', 'L', 'N']}
    };

    function parseCvssVector(s) {
        if (!s) throw new Error('Empty vector');
        var parts = s.trim().split('/').filter(Boolean);
        if (!parts.length || !/^CVSS:3/i.test(parts[0])) {
            throw new Error('Vector must start with CVSS:3.x');
        }
        var out = {};
        for (var i = 1; i < parts.length; i++) {
            var kv = parts[i].split(':');
            if (kv.length !== 2) throw new Error('Malformed: "' + parts[i] + '"');
            var key = kv[0].toUpperCase();
            var val = kv[1].toUpperCase();
            var m = vectorMap[key];
            if (!m) continue;
            if (m.allowed.indexOf(val) === -1) throw new Error('Invalid value "' + val + '" for ' + key);
            out[m.field] = val;
        }
        return out;
    }

    var parseBtn = document.getElementById('cvssParseBtn');
    var pasteInput = document.getElementById('cvssVectorPaste');
    var parseHelp = document.getElementById('cvssParseHelp');
    if (parseBtn && pasteInput) {
        parseBtn.addEventListener('click', function() {
            try {
                var parsed = parseCvssVector(pasteInput.value);
                Object.keys(parsed).forEach(function(f) {
                    var el = document.getElementById('id_' + f);
                    if (el) el.value = parsed[f];
                });
                updateCvssPreview();
                form.dispatchEvent(new Event('finding:updated'));
                parseHelp.textContent = 'Applied ' + Object.keys(parsed).length + ' metric(s).';
                parseHelp.style.color = 'var(--success)';
            } catch (err) {
                parseHelp.textContent = err.message;
                parseHelp.style.color = 'var(--critical)';
            }
        });
    }

    // Show preview on page load if editing
    updateCvssPreview();
    form.dispatchEvent(new Event('finding:updated'));
})();
