/**
 * SpiderJS Web Interface
 * Main JavaScript functionality
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize components
    initializeForms();
    initializeTooltips();
    setupApiCalls();
});

/**
 * Initialize form handling
 */
function initializeForms() {
    const scanForm = document.getElementById('scan-form');
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const urlInput = document.getElementById('target-url');
            const options = {
                maxDepth: document.getElementById('max-depth').value || 3,
                timeout: document.getElementById('timeout').value || 30,
                includeXss: document.getElementById('include-xss').checked,
                includeInjection: document.getElementById('include-injection').checked,
                includeCsrf: document.getElementById('include-csrf').checked,
                includeHeaders: document.getElementById('include-headers').checked,
            };
            
            startScan(urlInput.value, options);
        });
    }
    
    const analyzeForm = document.getElementById('analyze-form');
    if (analyzeForm) {
        analyzeForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const urlInput = document.getElementById('bundle-url');
            startAnalysis(urlInput.value);
        });
    }
}

/**
 * Initialize tooltips
 */
function initializeTooltips() {
    const tooltips = document.querySelectorAll('[data-tooltip]');
    tooltips.forEach(tooltip => {
        tooltip.addEventListener('mouseenter', function() {
            const tooltipText = this.getAttribute('data-tooltip');
            
            const tooltipElement = document.createElement('div');
            tooltipElement.className = 'tooltip';
            tooltipElement.textContent = tooltipText;
            
            document.body.appendChild(tooltipElement);
            
            const rect = this.getBoundingClientRect();
            const tooltipRect = tooltipElement.getBoundingClientRect();
            
            tooltipElement.style.left = rect.left + (rect.width / 2) - (tooltipRect.width / 2) + 'px';
            tooltipElement.style.top = rect.bottom + 10 + 'px';
        });
        
        tooltip.addEventListener('mouseleave', function() {
            const tooltips = document.querySelectorAll('.tooltip');
            tooltips.forEach(t => t.remove());
        });
    });
}

/**
 * Set up API calls
 */
function setupApiCalls() {
    // Expose the API functions globally
    window.spiderJsApi = {
        startScan,
        startAnalysis,
        getReport,
        cancelScan
    };
}

/**
 * Start a security scan
 * @param {string} url - The URL to scan
 * @param {object} options - Scan options
 */
function startScan(url, options) {
    showLoading('Scanning in progress...');
    
    fetch('/api/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            url: url,
            options: options
        })
    })
    .then(response => response.json())
    .then(data => {
        hideLoading();
        
        if (data.error) {
            showError(data.error);
            return;
        }
        
        displayResults(data);
    })
    .catch(error => {
        hideLoading();
        showError('An error occurred while scanning: ' + error.message);
    });
}

/**
 * Start a bundle analysis
 * @param {string} url - The URL of the JavaScript bundle
 */
function startAnalysis(url) {
    showLoading('Analyzing bundle...');
    
    fetch('/api/analyze', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            url: url
        })
    })
    .then(response => response.json())
    .then(data => {
        hideLoading();
        
        if (data.error) {
            showError(data.error);
            return;
        }
        
        displayBundleAnalysis(data);
    })
    .catch(error => {
        hideLoading();
        showError('An error occurred while analyzing: ' + error.message);
    });
}

/**
 * Get a report by ID
 * @param {string} reportId - The report ID
 */
function getReport(reportId) {
    showLoading('Loading report...');
    
    fetch(`/api/report/${reportId}`)
    .then(response => response.json())
    .then(data => {
        hideLoading();
        
        if (data.error) {
            showError(data.error);
            return;
        }
        
        displayResults(data);
    })
    .catch(error => {
        hideLoading();
        showError('An error occurred while loading the report: ' + error.message);
    });
}

/**
 * Cancel an ongoing scan
 * @param {string} scanId - The scan ID
 */
function cancelScan(scanId) {
    fetch(`/api/scan/${scanId}/cancel`, {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            showError(data.error);
            return;
        }
        
        showMessage('Scan cancelled successfully');
    })
    .catch(error => {
        showError('An error occurred while cancelling the scan: ' + error.message);
    });
}

/**
 * Display scan results
 * @param {object} data - The scan results
 */
function displayResults(data) {
    const resultsContainer = document.getElementById('results-container');
    if (!resultsContainer) return;
    
    resultsContainer.innerHTML = '';
    
    // Add summary card
    const summaryCard = document.createElement('div');
    summaryCard.className = 'card';
    
    const summaryHeader = document.createElement('div');
    summaryHeader.className = 'card-header';
    summaryHeader.innerHTML = `<h3 class="card-title">Scan Summary</h3>`;
    
    const summaryContent = document.createElement('div');
    summaryContent.className = 'card-content';
    summaryContent.innerHTML = `
        <p><strong>Target:</strong> ${data.target_url}</p>
        <p><strong>Scan ID:</strong> ${data.id}</p>
        <p><strong>Date:</strong> ${new Date(data.created_at).toLocaleString()}</p>
        <p><strong>Total Findings:</strong> ${data.summary.total_findings}</p>
        <p><strong>Security Score:</strong> ${data.summary.score.toFixed(1)}/100</p>
        <div class="findings-breakdown">
            <div class="severity critical">${data.summary.critical_count} Critical</div>
            <div class="severity high">${data.summary.high_count} High</div>
            <div class="severity medium">${data.summary.medium_count} Medium</div>
            <div class="severity low">${data.summary.low_count} Low</div>
            <div class="severity info">${data.summary.info_count} Info</div>
        </div>
    `;
    
    summaryCard.appendChild(summaryHeader);
    summaryCard.appendChild(summaryContent);
    resultsContainer.appendChild(summaryCard);
    
    // Add findings
    const findingsCard = document.createElement('div');
    findingsCard.className = 'card';
    
    const findingsHeader = document.createElement('div');
    findingsHeader.className = 'card-header';
    findingsHeader.innerHTML = `<h3 class="card-title">Findings</h3>`;
    
    const findingsContent = document.createElement('div');
    findingsContent.className = 'card-content';
    
    if (data.findings.length === 0) {
        findingsContent.innerHTML = '<p>No findings detected.</p>';
    } else {
        data.findings.forEach(finding => {
            const findingElement = document.createElement('div');
            findingElement.className = `finding ${finding.severity.toLowerCase()}`;
            
            findingElement.innerHTML = `
                <div class="finding-title">
                    <span>${finding.title}</span>
                    <span class="severity-badge ${finding.severity.toLowerCase()}">${finding.severity}</span>
                </div>
                <div class="finding-description">${finding.description}</div>
                ${finding.evidence ? `<div class="finding-evidence"><strong>Evidence:</strong> <code>${finding.evidence}</code></div>` : ''}
                ${finding.remediation ? `<div class="finding-remediation"><strong>Remediation:</strong> ${finding.remediation}</div>` : ''}
            `;
            
            findingsContent.appendChild(findingElement);
        });
    }
    
    findingsCard.appendChild(findingsHeader);
    findingsCard.appendChild(findingsContent);
    resultsContainer.appendChild(findingsCard);
}

/**
 * Display bundle analysis results
 * @param {object} data - The bundle analysis results
 */
function displayBundleAnalysis(data) {
    const resultsContainer = document.getElementById('results-container');
    if (!resultsContainer) return;
    
    resultsContainer.innerHTML = '';
    
    // Add summary card
    const summaryCard = document.createElement('div');
    summaryCard.className = 'card';
    
    const summaryHeader = document.createElement('div');
    summaryHeader.className = 'card-header';
    summaryHeader.innerHTML = `<h3 class="card-title">Bundle Analysis</h3>`;
    
    const summaryContent = document.createElement('div');
    summaryContent.className = 'card-content';
    summaryContent.innerHTML = `
        <p><strong>URL:</strong> ${data.url}</p>
        <p><strong>Bundle Type:</strong> ${data.bundle_type}</p>
        <p><strong>Minified:</strong> ${data.minified ? 'Yes' : 'No'}</p>
        <p><strong>Source Map Available:</strong> ${data.source_map ? 'Yes' : 'No'}</p>
        <p><strong>Size:</strong> ${(data.size / 1024).toFixed(2)} KB</p>
    `;
    
    summaryCard.appendChild(summaryHeader);
    summaryCard.appendChild(summaryContent);
    resultsContainer.appendChild(summaryCard);
    
    // Add dependencies
    if (data.dependencies && data.dependencies.length > 0) {
        const dependenciesCard = document.createElement('div');
        dependenciesCard.className = 'card';
        
        const dependenciesHeader = document.createElement('div');
        dependenciesHeader.className = 'card-header';
        dependenciesHeader.innerHTML = `<h3 class="card-title">Dependencies</h3>`;
        
        const dependenciesContent = document.createElement('div');
        dependenciesContent.className = 'card-content';
        
        const dependenciesList = document.createElement('ul');
        data.dependencies.forEach(dep => {
            const item = document.createElement('li');
            item.textContent = dep.name + (dep.version ? ` (${dep.version})` : '');
            dependenciesList.appendChild(item);
        });
        
        dependenciesContent.appendChild(dependenciesList);
        dependenciesCard.appendChild(dependenciesHeader);
        dependenciesCard.appendChild(dependenciesContent);
        resultsContainer.appendChild(dependenciesCard);
    }
}

/**
 * Show loading indicator
 * @param {string} message - The loading message
 */
function showLoading(message) {
    const loadingElement = document.createElement('div');
    loadingElement.className = 'loading-overlay';
    loadingElement.innerHTML = `
        <div class="loading-spinner"></div>
        <div class="loading-message">${message || 'Loading...'}</div>
    `;
    
    document.body.appendChild(loadingElement);
}

/**
 * Hide loading indicator
 */
function hideLoading() {
    const loadingElements = document.querySelectorAll('.loading-overlay');
    loadingElements.forEach(el => el.remove());
}

/**
 * Show error message
 * @param {string} message - The error message
 */
function showError(message) {
    const errorElement = document.createElement('div');
    errorElement.className = 'error-message';
    errorElement.textContent = message;
    
    document.body.appendChild(errorElement);
    
    setTimeout(() => {
        errorElement.classList.add('show');
    }, 10);
    
    setTimeout(() => {
        errorElement.classList.remove('show');
        setTimeout(() => {
            errorElement.remove();
        }, 300);
    }, 5000);
}

/**
 * Show success message
 * @param {string} message - The success message
 */
function showMessage(message) {
    const messageElement = document.createElement('div');
    messageElement.className = 'message success';
    messageElement.textContent = message;
    
    document.body.appendChild(messageElement);
    
    setTimeout(() => {
        messageElement.classList.add('show');
    }, 10);
    
    setTimeout(() => {
        messageElement.classList.remove('show');
        setTimeout(() => {
            messageElement.remove();
        }, 300);
    }, 5000);
} 