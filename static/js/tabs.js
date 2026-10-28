/* Shared tab behavior: hash links, keyboard navigation, focus and ARIA. */
(() => {
    document.querySelectorAll('[data-tabs]').forEach((root, index) => {
        const tabs = Array.from(root.querySelectorAll('[role="tab"]'));
        const panels = Array.from(root.querySelectorAll(':scope > [role="tabpanel"]'));
        const available = tabs.filter(tab => panels.some(panel => panel.id === 'tab-' + tab.dataset.tab));
        function activate(name, focus = false, updateHash = false) {
            const selected = available.find(tab => tab.dataset.tab === name) || available[0];
            if (!selected) return;
            available.forEach(tab => {
                const active = tab === selected;
                tab.id = tab.id || `tabs-${index}-${tab.dataset.tab}`;
                tab.setAttribute('aria-controls', 'tab-' + tab.dataset.tab);
                tab.setAttribute('aria-selected', String(active));
                tab.tabIndex = active ? 0 : -1;
                tab.classList.toggle('active', active);
            });
            panels.forEach(panel => {
                const owner = available.find(tab => 'tab-' + tab.dataset.tab === panel.id);
                const active = panel.id === 'tab-' + selected.dataset.tab;
                if (owner) panel.setAttribute('aria-labelledby', owner.id);
                panel.hidden = !active;
                panel.classList.toggle('active', active);
            });
            if (focus) selected.focus();
            if (updateHash) history.replaceState(null, '', '#' + selected.dataset.tab);
        }
        available.forEach((tab, i) => {
            tab.addEventListener('click', () => activate(tab.dataset.tab, false, true));
            tab.addEventListener('keydown', event => {
                let next;
                if (event.key === 'ArrowRight') next = (i + 1) % available.length;
                if (event.key === 'ArrowLeft') next = (i - 1 + available.length) % available.length;
                if (event.key === 'Home') next = 0;
                if (event.key === 'End') next = available.length - 1;
                if (next !== undefined) {
                    event.preventDefault();
                    activate(available[next].dataset.tab, true, true);
                }
            });
        });
        function fromHash() { activate(location.hash.slice(1)); }
        window.addEventListener('hashchange', fromHash);
        fromHash();
    });
})();
