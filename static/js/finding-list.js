(function() {
    var bar = document.querySelector('.finding-filters');
    if (!bar) return;
    var toggle = bar.querySelector('[data-filter-toggle]');
    var panel = bar.querySelector('[data-filter-panel]');
    if (!toggle || !panel) return;
    if (bar.dataset.advancedOpen === '1') bar.classList.add('finding-filters--open');
    toggle.addEventListener('click', function() {
        var nowOpen = bar.classList.toggle('finding-filters--open');
        toggle.setAttribute('aria-expanded', nowOpen ? 'true' : 'false');
    });
})();
