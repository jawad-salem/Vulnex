/* Global interactions. Template URLs are read from links, never embedded in JS. */
(() => {
    const toggle = document.getElementById('mobileToggle');
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    const main = document.getElementById('main-content');
    const mobile = matchMedia('(max-width: 768px)');
    function menu(open, restoreFocus = false) {
        if (!sidebar || !toggle) return;
        const shown = open && mobile.matches;
        sidebar.classList.toggle('open', shown);
        overlay?.classList.toggle('active', shown);
        toggle.setAttribute('aria-expanded', String(shown));
        sidebar.inert = mobile.matches && !shown;
        if (main) main.inert = shown;
        document.body.style.overflow = shown ? 'hidden' : '';
        if (shown) sidebar.querySelector('a, button')?.focus();
        else if (restoreFocus) toggle.focus();
    }
    toggle?.addEventListener('click', () => menu(toggle.getAttribute('aria-expanded') !== 'true'));
    overlay?.addEventListener('click', () => menu(false, true));
    mobile.addEventListener('change', () => menu(false));
    menu(false);
    document.addEventListener('keydown', event => {
        if (sidebar?.classList.contains('open')) {
            if (event.key === 'Escape') { menu(false, true); return; }
            if (event.key === 'Tab') {
                const focusable = [toggle, ...sidebar.querySelectorAll('a[href], button:not([disabled])')];
                const first = focusable[0], last = focusable[focusable.length - 1];
                if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
                else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
            }
            return;
        }
        const target = event.target;
        if (target.closest('input, textarea, select, button, a, [contenteditable="true"], [role="dialog"]')) return;
        if (event.ctrlKey || event.metaKey || event.altKey) return;
        if (event.key === '/') {
            event.preventDefault();
            document.querySelector('.topbar-search-input, .search-input')?.focus();
        } else {
            const shortcut = Array.from(document.querySelectorAll('[data-shortcut]')).find(link => link.dataset.shortcut === event.key);
            if (shortcut) location.href = shortcut.href;
        }
    });
    document.addEventListener('click', event => {
        const confirm = event.target.closest('[data-confirm]');
        if (confirm && !window.confirm(confirm.dataset.confirm)) { event.preventDefault(); return; }
        const dismiss = event.target.closest('[data-dismiss-parent]');
        if (dismiss) { dismiss.parentElement?.remove(); return; }
        const panelToggle = event.target.closest('[data-toggle-panel]');
        if (panelToggle) {
            const panel = document.getElementById(panelToggle.dataset.togglePanel);
            if (panel) { panel.hidden = !panel.hidden; panelToggle.setAttribute('aria-expanded', String(!panel.hidden)); }
        }
        const row = event.target.closest('[data-href]');
        if (row && !event.target.closest('a, button, input, select, textarea, label')) location.href = row.dataset.href;
    });
    document.addEventListener('submit', event => {
        if (!event.defaultPrevented) event.submitter?.classList.add('loading');
    });
    document.addEventListener('change', event => {
        const input = event.target;
        if (input.form && (input.hasAttribute('data-autosubmit') || input.hasAttribute('data-autosubmit-loading'))) {
            if (input.hasAttribute('data-autosubmit-loading')) input.form.classList.add('form-loading');
            input.form.requestSubmit();
        }
    });
    function markWorkspace() {
        const links = Array.from(document.querySelectorAll('.workspace-nav a'));
        links.forEach(link => link.removeAttribute('aria-current'));
        const matches = links.filter(link => {
            const url = new URL(link.href);
            return url.pathname === location.pathname && (!url.hash || url.hash === location.hash);
        }).sort((a, b) => new URL(b.href).hash.length - new URL(a.href).hash.length);
        let current = matches[0];
        if (!current && location.pathname.includes('/attack-paths/')) current = links.find(link => new URL(link.href).pathname.includes('/attack-paths/'));
        if (!current && location.pathname.startsWith('/vulns/')) current = links.find(link => link.dataset.shortcut === 'f');
        if (!current) current = links.find(link => new URL(link.href).pathname.split('/')[1] === location.pathname.split('/')[1]);
        if (current) {
            current.setAttribute('aria-current', 'page');
        }
    }
    markWorkspace();
    window.addEventListener('hashchange', markWorkspace);
})();
