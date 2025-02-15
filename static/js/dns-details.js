document.addEventListener('DOMContentLoaded', function() {
    const expandToggles = document.querySelectorAll('.expand-toggle');
    
    expandToggles.forEach(toggle => {
        toggle.addEventListener('click', function() {
            const isExpanded = this.getAttribute('aria-expanded') === 'true';
            this.setAttribute('aria-expanded', !isExpanded);
            
            const details = this.closest('.record-content')
                               .nextElementSibling;
            
            if (!isExpanded) {
                details.classList.remove('hidden');
            } else {
                details.classList.add('hidden');
            }
        });
    });
}); 