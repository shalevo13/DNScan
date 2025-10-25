document.getElementById('scanForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const domain = document.getElementById('domain').value.trim();
    const nameserver = document.getElementById('nameserver').value.trim();
    
    // Hide form and results, show loading
    document.querySelector('.scan-form-container').style.display = 'none';
    document.getElementById('results').style.display = 'none';
    document.getElementById('error').style.display = 'none';
    document.getElementById('loading').style.display = 'block';
    
    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ domain, nameserver })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            displayResults(data);
        } else {
            showError(data.error || 'An error occurred during the scan');
        }
    } catch (error) {
        showError('Failed to connect to the server: ' + error.message);
    } finally {
        document.getElementById('loading').style.display = 'none';
    }
});

function displayResults(data) {
    // Update meta information
    document.getElementById('resultDomain').textContent = data.domain;
    document.getElementById('resultNameserver').textContent = data.nameserver;
    document.getElementById('resultTime').textContent = new Date(data.timestamp).toLocaleString();
    
    // Update statistics
    const stats = data.stats;
    document.getElementById('scoreValue').textContent = stats.score + '%';
    document.getElementById('safeCount').textContent = stats.safe;
    document.getElementById('warningCount').textContent = stats.warning;
    document.getElementById('vulnerableCount').textContent = stats.vulnerable;
    
    // Animate score with color
    const scoreCard = document.querySelector('.score-card');
    if (stats.score >= 80) {
        scoreCard.style.borderColor = 'var(--success)';
    } else if (stats.score >= 50) {
        scoreCard.style.borderColor = 'var(--warning)';
    } else {
        scoreCard.style.borderColor = 'var(--danger)';
    }
    
    // Display individual tests
    const testsContainer = document.getElementById('testsContainer');
    testsContainer.innerHTML = '';
    
    data.tests.forEach((test, index) => {
        const testCard = createTestCard(test, index);
        testsContainer.appendChild(testCard);
    });
    
    // Show results
    document.getElementById('results').style.display = 'block';
    
    // Scroll to results
    document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function createTestCard(test, index) {
    const card = document.createElement('div');
    card.className = 'test-card';
    card.style.animationDelay = `${index * 0.1}s`;
    
    const statusIcon = getStatusIcon(test.status);
    const severityClass = test.severity || 'low';
    
    card.innerHTML = `
        <div class="test-header">
            <div class="test-status-icon ${test.status}">
                ${statusIcon}
            </div>
            <div class="test-info">
                <div class="test-title">
                    ${test.name}
                    <span class="severity-badge ${severityClass}">${severityClass}</span>
                </div>
                <div class="test-description">${test.description}</div>
            </div>
        </div>
        ${test.details.length > 0 ? `
            <div class="test-details">
                <ul>
                    ${test.details.map(detail => `<li>${escapeHtml(detail)}</li>`).join('')}
                </ul>
            </div>
        ` : ''}
    `;
    
    return card;
}

function getStatusIcon(status) {
    const icons = {
        safe: `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M22 11.08V12C22 17.52 17.52 22 12 22C6.48 22 2 17.52 2 12C2 6.48 6.48 2 12 2C13.18 2 14.32 2.22 15.38 2.64" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M22 4L12 14.01L9 11.01" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>`,
        warning: `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M10.29 3.86L1.82 18C1.64571 18.3024 1.55165 18.6453 1.54735 18.9945C1.54305 19.3437 1.62867 19.6886 1.79515 19.9947C1.96163 20.3008 2.20336 20.5577 2.49781 20.7414C2.79226 20.9251 3.12858 21.0293 3.47333 21.0433H20.4067C20.7514 21.0293 21.0877 20.9251 21.3822 20.7414C21.6766 20.5577 21.9184 20.3008 22.0848 19.9947C22.2513 19.6886 22.337 19.3437 22.3327 18.9945C22.3284 18.6453 22.2343 18.3024 22.06 18L13.59 3.86C13.4083 3.56611 13.1572 3.32312 12.8605 3.15448C12.5638 2.98585 12.2308 2.89717 11.8917 2.89717C11.5525 2.89717 11.2195 2.98585 10.9228 3.15448C10.6261 3.32312 10.375 3.56611 10.1933 3.86H10.29Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M12 9V13" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M12 17H12.01" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>`,
        vulnerable: `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M15 9L9 15" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M9 9L15 15" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>`,
        error: `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M12 8V12" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M12 16H12.01" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>`
    };
    
    return icons[status] || icons.error;
}

function showError(message) {
    const errorDiv = document.getElementById('error');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
    document.querySelector('.scan-form-container').style.display = 'block';
    errorDiv.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function resetForm() {
    document.getElementById('scanForm').reset();
    document.getElementById('results').style.display = 'none';
    document.getElementById('error').style.display = 'none';
    document.querySelector('.scan-form-container').style.display = 'block';
    document.querySelector('.intro-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

// Add smooth scroll behavior for all anchors
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    });
});

// Add parallax effect to stars
let ticking = false;
window.addEventListener('scroll', () => {
    if (!ticking) {
        window.requestAnimationFrame(() => {
            const scrolled = window.pageYOffset;
            const stars1 = document.querySelector('.stars');
            const stars2 = document.querySelector('.stars2');
            const stars3 = document.querySelector('.stars3');
            
            if (stars1) stars1.style.transform = `translateY(${scrolled * 0.2}px)`;
            if (stars2) stars2.style.transform = `translateY(${scrolled * 0.3}px)`;
            if (stars3) stars3.style.transform = `translateY(${scrolled * 0.4}px)`;
            
            ticking = false;
        });
        ticking = true;
    }
});
