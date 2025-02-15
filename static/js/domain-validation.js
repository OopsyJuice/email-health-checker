document.addEventListener('DOMContentLoaded', function() {
    // Elements
    const form = document.getElementById('domain-form');
    const singleInput = document.getElementById('domain-input');
    const multipleInput = document.getElementById('domain-tag-input');
    const submitBtn = document.getElementById('submit-btn');
    const loadingSpinner = document.getElementById('loading-spinner');
    const domainError = document.getElementById('domain-error');
    const multipleDomainError = document.getElementById('multiple-domain-error');
    const singleContainer = document.getElementById('single-domain-container');
    const multipleContainer = document.getElementById('multiple-domains-container');
    const tagsContainer = document.getElementById('domain-tags-container');
    const domainsHiddenInput = document.getElementById('domains-hidden-input');
    const modeInput = document.getElementById('domain-mode');

    // Constants
    const MAX_DOMAINS = 5;
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](\.[a-zA-Z]{2,})+$/;
    const domains = new Set();

    // Mode switching
    document.querySelectorAll('.mode-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const mode = this.dataset.mode;
            
            // Update active states
            document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            
            // Update form mode
            modeInput.value = mode;
            
            // Show/hide containers
            singleContainer.style.display = mode === 'single' ? 'block' : 'none';
            multipleContainer.style.display = mode === 'multiple' ? 'block' : 'none';
            
            // Update button text
            submitBtn.textContent = mode === 'single' ? 'Check Domain' : 'Check Domains';
            
            // Clear errors
            domainError.textContent = '';
            multipleDomainError.textContent = '';
        });
    });

    // Single domain validation
    singleInput.addEventListener('input', function() {
        if (!this.value) {
            domainError.textContent = 'Domain cannot be empty';
            submitBtn.disabled = true;
        } else if (!domainRegex.test(this.value)) {
            domainError.textContent = 'Please enter a valid domain (e.g., example.com)';
            submitBtn.disabled = true;
        } else {
            domainError.textContent = '';
            submitBtn.disabled = false;
        }
    });

    // Multiple domains handling
    multipleInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            const domain = this.value.trim();
            
            if (!domain) return;
            
            if (domains.size >= MAX_DOMAINS) {
                multipleDomainError.textContent = `Maximum ${MAX_DOMAINS} domains allowed`;
                return;
            }

            if (!domainRegex.test(domain)) {
                multipleDomainError.textContent = 'Please enter a valid domain (e.g., example.com)';
                return;
            }

            // Add domain tag
            const tag = document.createElement('div');
            tag.className = 'domain-tag';
            tag.innerHTML = `
                ${domain}
                <button type="button" class="remove-tag">×</button>
            `;

            tag.querySelector('.remove-tag').addEventListener('click', function() {
                domains.delete(domain);
                tag.remove();
                updateMultipleDomainsState();
            });

            tagsContainer.appendChild(tag);
            domains.add(domain);
            this.value = '';
            updateMultipleDomainsState();
        }
    });

    function updateMultipleDomainsState() {
        domainsHiddenInput.value = Array.from(domains).join(',');
        submitBtn.disabled = domains.size === 0;
        multipleInput.disabled = domains.size >= MAX_DOMAINS;
        multipleDomainError.textContent = '';
    }

    // Form submission
    form.addEventListener('submit', function(e) {
        loadingSpinner.classList.remove('hidden');
        submitBtn.disabled = true;
    });
});