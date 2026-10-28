/* Shared shell owns panel toggles; tabs.js owns recon tabs. */
(() => {
    const source = document.getElementById('pipeline-presets');
    const select = document.querySelector('[name="preset"]');
    const description = document.getElementById('pipeline-desc');
    if (!source || !select || !description) return;
    const presets = JSON.parse(source.textContent);
    const refresh = () => { description.textContent = presets[select.value]?.description || ''; };
    select.addEventListener('change', refresh);
    refresh();
})();
