/* Compare actual values, including template and host autofill. No browser storage. */
(() => {
    const form = document.getElementById('findingForm');
    if (!form) return;
    const state = document.getElementById('editorSaveState');
    const snapshot = () => JSON.stringify(Array.from(new FormData(form).entries()));
    const initial = snapshot();
    let submitting = false;
    const dirty = () => snapshot() !== initial;
    function refresh() {
        state.textContent = dirty() ? 'Unsaved changes' : 'No unsaved changes';
        state.classList.toggle('is-dirty', dirty());
    }
    form.addEventListener('input', refresh);
    form.addEventListener('change', refresh);
    form.addEventListener('finding:updated', refresh);
    form.addEventListener('submit', event => { if (!event.defaultPrevented) submitting = true; });
    window.addEventListener('pageshow', () => { submitting = false; refresh(); });
    window.addEventListener('beforeunload', event => {
        if (!submitting && dirty()) { event.preventDefault(); event.returnValue = ''; }
    });
})();
