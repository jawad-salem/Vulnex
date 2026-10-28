(function() {
    // Evidence lightbox
    var lb = document.getElementById('evLightbox');
    if (lb) {
        var lbImg = document.getElementById('evLightboxImg'), lbCap = document.getElementById('evLightboxCap');
        var previousFocus;
        var close = function() { lb.classList.remove('open'); lbImg.removeAttribute('src'); previousFocus?.focus(); };
        document.querySelectorAll('[data-lightbox]').forEach(function(a) {
            a.addEventListener('click', function(e) {
                e.preventDefault();
                previousFocus = this;
                lbImg.src = this.getAttribute('href');
                var cap = this.getAttribute('data-cap') || '';
                lbCap.textContent = cap; lbCap.hidden = !cap;
                lb.classList.add('open');
                document.getElementById('evLightboxClose').focus();
            });
        });
        document.getElementById('evLightboxClose').addEventListener('click', close);
        lb.addEventListener('click', function(e) { if (e.target === lb) close(); });
        document.addEventListener('keydown', function(e) { if (!lb.classList.contains('open')) return; if (e.key === 'Escape') close(); if (e.key === 'Tab') { e.preventDefault(); document.getElementById('evLightboxClose').focus(); } });
    }

    // Evidence dropzone filename echo
    var drop = document.getElementById('evDrop');
    if (drop) {
        var fileInput = drop.querySelector('input[type="file"]'), nameEl = document.getElementById('evFileName');
        if (fileInput) {
            fileInput.addEventListener('change', function() {
                if (fileInput.files && fileInput.files.length) { nameEl.textContent = '✓ ' + fileInput.files[0].name; nameEl.hidden = false; }
                else { nameEl.hidden = true; }
            });
            ['dragenter', 'dragover'].forEach(function(ev) { drop.addEventListener(ev, function(e) { e.preventDefault(); drop.classList.add('is-drag'); }); });
            ['dragleave', 'drop'].forEach(function(ev) { drop.addEventListener(ev, function(e) { e.preventDefault(); drop.classList.remove('is-drag'); }); });
            drop.addEventListener('drop', function(e) { if (e.dataTransfer && e.dataTransfer.files.length) { fileInput.files = e.dataTransfer.files; fileInput.dispatchEvent(new Event('change')); } });
        }
    }

    // Inline reproduction (PoC) editor toggle
    var repro = document.getElementById('reproCard');
    if (repro) {
        var view = repro.querySelector('[data-repro-view]');
        var form = repro.querySelector('[data-repro-form]');
        var editBtn = repro.querySelector('[data-repro-edit]');
        var cancelBtn = repro.querySelector('[data-repro-cancel]');
        if (editBtn && form && view) {
            editBtn.addEventListener('click', function() { view.hidden = true; form.hidden = false; editBtn.hidden = true; form.querySelector('textarea').focus(); });
            if (cancelBtn) cancelBtn.addEventListener('click', function() { form.hidden = true; view.hidden = false; editBtn.hidden = false; });
        }
    }
})();
