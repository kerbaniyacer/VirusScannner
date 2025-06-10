const API_KEY = '71e5ab1793a4cf14356a9334fd72d8b4129474c804131ead8eae4e5b154c1a62';

const getElement = (id) => document.getElementById(id);

const updateResult = (content, display = true) => {
    const result = getElement('result');
    result.style.display = display ? 'block' : 'none';
    result.innerHTML = content;
};

const showLoading = (message) => updateResult(`
    <div class="loading">
        <p>${message}</p>
        <div class="spinner"></div>
    </div>
`);

const showError = (message) => updateResult(`<p class="error">${message}</p>`);

async function makeApiRequest(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        headers: {
            'x-apikey': API_KEY,
            ...options.headers
        }
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: { message: response.statusText } }));
        throw new Error(errorData.error?.message || 'Request failed');
    }

    return response.json();
}

async function scanUrl() {
    const url = getElement('urlInput').value.trim();
    if (!url) return showError('Please enter a URL!');

    try {
        new URL(url);
    } catch {
        return showError('Please enter a valid URL (e.g., https://example.com)');
    }

    try {
        showLoading('Submitting URL for scanning...');

        const encodedUrl = encodeURIComponent(url);

        const submitResult = await makeApiRequest(`https://www.virustotal.com/api/v3/urls`, {
            method: 'POST',
            headers: {
                'accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `url=${encodedUrl}`
        });

        if (!submitResult.data?.id) throw new Error('Failed to get analysis ID');

        await new Promise(resolve => setTimeout(resolve, 3000));

        showLoading('Getting scan results...');
        await pollAnalysisResult(submitResult.data.id);
    } catch (error) {
        showError(`Error: ${error.message}`);
    }
}

async function scanFile() {
    const file = getElement('fileInput').files[0];
    if (!file) return showError('Please select a file!');
    if (file.size > 32 * 1024 * 1024) return showError('File size exceeds the 32 MB limit!');

    try {
        showLoading('Uploading file...');

        const formData = new FormData();
        formData.append('file', file);

        const submitResult = await makeApiRequest(`https://www.virustotal.com/api/v3/files`, {
            method: 'POST',
            body: formData
        });

        if (!submitResult.data?.id) throw new Error('Failed to get file ID');

        await new Promise(resolve => setTimeout(resolve, 3000));

        showLoading('Getting scan results...');
        await pollAnalysisResult(submitResult.data.id, file.name);
    } catch (error) {
        showError(`Error: ${error.message}`);
    }
}

async function pollAnalysisResult(analysisId, fileName = '') {
    const maxAttempts = 20;
    let attempts = 0;
    let interval = 2000;

    while (attempts < maxAttempts) {
        try {
            showLoading(`Analyzing ${fileName}... (${((maxAttempts - attempts) * interval / 1000).toFixed(0)}s remaining)`);

            const report = await makeApiRequest(`https://www.virustotal.com/api/v3/analyses/${analysisId}`);
            const stats = report.data?.attributes?.stats;
            const status = report.data?.attributes?.status;

            if (!stats) throw new Error('Invalid analysis response');

            if (status === "completed") {
                showFormattedResults(report);
                return;
            }

            if (status === "failed") {
                throw new Error('Analysis failed');
            }

            attempts++;
            if (attempts >= maxAttempts) {
                throw new Error('Analysis timed out - please try again later');
            }

            interval = Math.min(interval * 1.5, 8000);
            await new Promise(resolve => setTimeout(resolve, interval));
        } catch (error) {
            showError(`Error: ${error.message}`);
            break;
        }
    }
}

function showFormattedResults(data) {
    if (!data?.data?.attributes?.stats) {
        return showError('Invalid response format!');
    }

    const stats = data.data.attributes.stats;
    const total = Object.values(stats).reduce((sum, count) => sum + count, 0);

    if (!total) return showError('No analysis results available!');

    const getPercentage = (count) => ((count / total) * 100).toFixed(1);

    const categories = {
        malicious: { color: "malicious", label: "Malicious" },
        suspicious: { color: "suspicious", label: "Suspicious" },
        harmless: { color: "safe", label: "Clean" },
        undetected: { color: "undetected", label: "Undetected" },
    };

    const percents = Object.keys(categories).reduce((acc, key) => {
        acc[key] = getPercentage(stats[key]);
        return acc;
    }, {});

    const verdict = stats.malicious > 0 ? 'Malicious' :
                    stats.suspicious > 0 ? 'Suspicious' : 'Safe';
    const verdictClass = stats.malicious > 0 ? 'malicious' :
                         stats.suspicious > 0 ? 'suspicious' : 'safe';

    updateResult(`
        <h3>Scan Report</h3>
        <div class="scan-stats">
            <p><strong>Verdict: </strong> <span class="${verdictClass}">${verdict}</span></p>
            <div class="progress-section">
                <div class="progress-label">
                    <span>Detection Results</span>
                    <span class="progress-percent">${percents.malicious}% Detection Rate</span>
                </div>
                <div class="progress-stacked">
                    ${Object.entries(categories).map(([key, { color }]) =>`
                        <div class="progress-bar ${color}" style="width: ${percents[key]}%" title="${categories[key].label}: ${stats[key]} (${percents[key]}%)">
                            <span class="progress-label-overlay">${stats[key]}</span>
                        </div>
                    `
                    ).join('')}
                </div>
                <div class="progress-legend">
                    ${Object.entries(categories).map(([key, { color, label }]) => `
                        <div class="legend-item">
                            <span class="legend-color ${color}"></span>
                            <span>${label} (${percents[key]}%)</span>
                        </div>
                    `).join('')}
                </div>
                <div class="detection-details">
                    ${Object.entries(categories).map(([key, { color, label }]) => `
                        <div class="detail-item ${color}">
                            <span class="detail-label">${label}:</span>
                            <span class="detail-count">${stats[key]}</span>
                            <span class="detail-percent">${percents[key]}%</span>
                        </div>
                    `).join('')}
                </div>
            </div>
            <button onclick="showFullReport(this.getAttribute('data-report'))" data-report='${JSON.stringify(data)}'>View Full Report</button>
        </div>
    `);

    setTimeout(() => {
        const progress = getElement('result').querySelector('.progress-stacked');
        if (progress) progress.classList.add('animate');
    }, 1000);
}
function showFullReport(reportData) {
    const data = typeof reportData === 'string' ? JSON.parse(reportData) : reportData;
    const model = getElement('fullReportModel');
    const result = data.data?.attributes?.results;

    getElement('fullReportContent').innerHTML = `
        <h3>Full Analysis Report</h3>
        ${result ? `
            <table >
                <tr><th>Engine</th><th>Result</th></tr>
                ${Object.entries(result).map(([engine, {category}]) => `
                    <tr>
                        <td>${engine}</td>
                        <td class="${category === "malicious" ? "malicious" : category === "suspicious" ? "suspicious" : category === "harmless" ? "safe" : "undetected"}">${category}</td>        
                    </tr>
                `).join('')}
            </table>
    ` : '<p>No detailed results available.</p>'}
    `;
    model.style.display = 'block';
    model.offsetHeight;
    model.classList.add('show');
}

/// Close the full report model
const closeModel = () => {
    const model = getElement('fullReportModel');
    model.classList.remove('show');
    setTimeout(() => { model.style.display = 'none'; }, 300);
}

// Close model on click outside
window.addEventListener("load", () => {
    const model = getElement('fullReportModel');
    window.addEventListener('click', (event) => event.target === model && closemodel())
});

