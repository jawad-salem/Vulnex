(function() {
    'use strict';
    var endpoint = window.MARKDOWN_PREVIEW_URL;
    var csrf = document.querySelector('input[name=csrfmiddlewaretoken]');
    if (!endpoint || !csrf) return;
    var token = csrf.value;

    function debounce(fn, ms) {
        var t = null;
        return function() {
            var args = arguments, ctx = this;
            clearTimeout(t);
            t = setTimeout(function() { fn.apply(ctx, args); }, ms);
        };
    }

    function setupField(wrap) {
        var ta = wrap.querySelector('textarea');
        var preview = wrap.querySelector('.md-preview-pane');
        var tabEdit = wrap.querySelector('[data-md-tab="edit"]');
        var tabPreview = wrap.querySelector('[data-md-tab="preview"]');
        if (!ta || !preview || !tabEdit || !tabPreview) return;

        function activate(name) {
            wrap.classList.toggle('md-tab-edit', name === 'edit');
            wrap.classList.toggle('md-tab-preview', name === 'preview');
            tabEdit.classList.toggle('active', name === 'edit');
            tabPreview.classList.toggle('active', name === 'preview');
            tabEdit.setAttribute('aria-selected', name === 'edit' ? 'true' : 'false');
            tabPreview.setAttribute('aria-selected', name === 'preview' ? 'true' : 'false');
            if (name === 'preview') refresh();
        }

        var refresh = debounce(function() {
            var raw = ta.value;
            if (!raw.trim()) {
                preview.innerHTML = '<p class="text-secondary text-sm">Nothing to preview yet.</p>';
                return;
            }
            preview.classList.add('md-preview-loading');
            var body = new URLSearchParams();
            body.set('text', raw);
            body.set('csrfmiddlewaretoken', token);
            fetch(endpoint, {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'X-CSRFToken': token },
                body: body,
            })
                .then(function(r) { return r.text(); })
                .then(function(html) {
                    preview.innerHTML = html || '<p class="text-secondary text-sm">Empty.</p>';
                    preview.classList.remove('md-preview-loading');
                })
                .catch(function() {
                    preview.innerHTML = '<p class="form-error">Preview failed.</p>';
                    preview.classList.remove('md-preview-loading');
                });
        }, 250);

        tabEdit.addEventListener('click', function(e) { e.preventDefault(); activate('edit'); });
        tabPreview.addEventListener('click', function(e) { e.preventDefault(); activate('preview'); });
        ta.addEventListener('input', function() {
            if (wrap.classList.contains('md-tab-preview')) refresh();
        });
        activate('edit');
    }

    document.querySelectorAll('[data-md-field]').forEach(setupField);
})();
