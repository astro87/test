document.addEventListener('DOMContentLoaded', () => {

    // NAVIGATION LOGIC /////////////////////////////////////////////////////////
    const navItems = document.querySelectorAll('.nav-item');
    const views = document.querySelectorAll('.page-container');
    const pageTitle = document.getElementById('page-title');
    const pageSubtitle = document.getElementById('page-subtitle');

    const viewTitles = {
        'dashboard': { title: 'System Overview', sub: 'Security Posture & Risk Assessment' },
        'upload': { title: 'Import SBOM', sub: 'Upload Software Bill of Materials for Analysis' },
        'results': { title: 'Analysis Results', sub: 'Vulnerability Detection & Findings' },
        'performance': { title: 'System Metrics', sub: 'Pipeline Execution Performance' }
    };

    // SIDEBAR TOGGLE LOGIC
    const brand = document.querySelector('.brand');
    const sidebar = document.querySelector('.sidebar');

    if (brand && sidebar) {
        brand.addEventListener('click', () => {
            sidebar.classList.toggle('hidden');
        });
    }

    // Initial Trigger for Dashboard (since it's active by default)
    triggerDashboardAnimations();

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const targetView = item.getAttribute('data-view');

            // UI Updates
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');

            // View Switching with Fade
            views.forEach(v => {
                v.classList.remove('active');
            });

            const newView = document.getElementById(`view-${targetView}`);
            if (newView) {
                newView.classList.add('active');
            }

            // Header Update
            const info = viewTitles[targetView];
            if (info) {
                pageTitle.textContent = info.title;
                pageSubtitle.textContent = info.sub;
            }

            // Specific View Logic
            if (targetView === 'dashboard') triggerDashboardAnimations();
            if (targetView === 'performance') animatePerformanceChart();
            if (targetView === 'results') triggerTableStagger();
        });
    });


    // ANIMATION CONTROLLERS ////////////////////////////////////////////////////

    function triggerDashboardAnimations() {
        // Risk Arc
        const riskArc = document.getElementById('risk-arc-visual');
        if (riskArc) {
            riskArc.classList.remove('animate');
            void riskArc.offsetWidth; // Force reflow
            setTimeout(() => riskArc.classList.add('animate'), 100);
        }

        // Risk Score Counter
        const scoreEl = document.getElementById('risk-score');
        if (scoreEl) {
            // If we have a stored score, use it, else default animation
            const target = parseInt(scoreEl.getAttribute('data-target') || '0');
            animateValue(scoreEl, 0, target, 1500);

            // Update Risk Arc visual to match score
            if (riskArc) {
                // Ensure the variable is set on the element's style so CSS sees it
                riskArc.style.setProperty('--arc-end', target + '%');
            }
        }

        // Dist Bars (Sequential)
        const segments = document.querySelectorAll('.dist-segment');
        segments.forEach((seg, index) => {
            seg.style.width = '0';
            setTimeout(() => {
                seg.style.width = seg.getAttribute('data-target');
            }, 600 + (index * 200));
        });
    }

    function animateValue(obj, start, end, duration) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            const ease = 1 - Math.pow(1 - progress, 3);

            obj.innerHTML = Math.floor(progress * (end - start) + start);
            if (progress < 1) {
                window.requestAnimationFrame(step);
            }
        };
        setTimeout(() => window.requestAnimationFrame(step), 300);
    }

    async function animatePerformanceChart() {
        const bars = document.querySelectorAll('#view-performance .bar-fill');
        bars.forEach(b => b.style.width = '0');

        for (let i = 0; i < bars.length; i++) {
            const bar = bars[i];
            const target = bar.getAttribute('data-width');
            await new Promise(r => setTimeout(r, 100));
            bar.style.width = target;
            await new Promise(r => setTimeout(r, 600));
        }
    }

    function triggerTableStagger() {
        const rows = document.querySelectorAll('.data-table tr');
        rows.forEach(r => {
            r.style.animation = 'none';
            r.offsetHeight;
            r.style.animation = null;
        });
    }


    // UPLOAD LOGIC /////////////////////////////////////////////////////////////
    const dropzone = document.getElementById('upload-dropzone');

    if (dropzone) {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) { e.preventDefault(); e.stopPropagation(); }

        dropzone.addEventListener('dragenter', () => dropzone.classList.add('drag-over'));
        dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag-over'));

        dropzone.addEventListener('drop', (e) => {
            dropzone.classList.remove('drag-over');
            const files = e.dataTransfer.files;
            if (files.length > 0) handleFileUpload(files[0]);
        });

        // Allow click to upload too
        dropzone.addEventListener('click', () => {
            const input = document.createElement('input');
            input.type = 'file';
            input.onchange = (e) => {
                if (e.target.files.length > 0) handleFileUpload(e.target.files[0]);
            };
            input.click();
        });
    }

    async function handleFileUpload(file) {
        const dropText = dropzone.querySelector('.upload-text');
        const progressContainer = document.getElementById('upload-progress-container');
        const progressBar = document.getElementById('upload-progress-bar');
        const statusText = document.getElementById('upload-status-text');

        // UI Switch
        dropzone.style.height = '150px';
        dropText.textContent = `Analyzing ${file.name}...`;
        progressContainer.style.display = 'block';
        statusText.textContent = "Uploading...";
        statusText.style.color = "var(--text-secondary)";
        progressBar.style.width = '0%';

        // 1. Prepare FormData
        const formData = new FormData();
        formData.append('file', file);

        try {
            // 2. Upload File
            const uploadRes = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });

            if (!uploadRes.ok) throw new Error("Upload failed");

            const uploadData = await uploadRes.json();
            const jobId = uploadData.job_id;

            statusText.textContent = "Processing...";

            // 3. Start SSE to track progress
            trackJobProgress(jobId, progressBar, statusText);

        } catch (error) {
            console.error(error);
            statusText.textContent = "Error: " + error.message;
            statusText.style.color = "var(--accent-critical)";
        }
    }

    function trackJobProgress(jobId, progressBar, statusText) {
        const eventSource = new EventSource(`/api/events/${jobId}`);

        eventSource.onmessage = (event) => {
            const data = JSON.parse(event.data);

            // Update Progress
            if (data.progress) {
                progressBar.style.width = `${data.progress}%`;
            }

            if (data.status === 'completed') {
                eventSource.close();
                statusText.textContent = "Analysis Complete";
                statusText.style.color = "var(--accent-safe)";

                // Render Results
                if (data.data) {
                    window.lastAnalysisData = data.data; // Save for modals
                    renderResults(data.data);
                    // Also update dashboard if stats are present
                    if (data.data.stats) updateDashboard(data.data.stats, data.stages);
                }

                // Switch to results view
                setTimeout(() => {
                    const resultsBtn = document.querySelector('[data-view="results"]');
                    if (resultsBtn) resultsBtn.click();
                }, 800);
            } else if (data.status === 'failed') {
                eventSource.close();
                statusText.textContent = "Analysis Failed: " + (data.error || "Unknown error");
                statusText.style.color = "var(--accent-critical)";
                progressBar.style.background = "var(--accent-critical)";
            }
        };

        eventSource.onerror = () => {
            // connection lost or error (could happen if job finishes fast)
            // We can try to fetch results just in case
            fetchResultsFallback(jobId, eventSource, statusText);
        };
    }

    async function fetchResultsFallback(jobId, eventSource, statusText) {
        eventSource.close();
        try {
            const res = await fetch(`/api/results/${jobId}`);
            if (res.ok) {
                const data = await res.json();
                if (data.status === 'completed' && data.data) {
                    window.lastAnalysisData = data.data; // Save for modals
                    renderResults(data.data);
                    if (data.data.stats) updateDashboard(data.data.stats, data.stages);

                    statusText.textContent = "Analysis Complete";
                    statusText.style.color = "var(--accent-safe)";
                    setTimeout(() => {
                        const resultsBtn = document.querySelector('[data-view="results"]');
                        if (resultsBtn) resultsBtn.click();
                    }, 800);
                }
            }
        } catch (e) {
            console.error("Fallback fetch failed", e);
        }
    }

    function renderResults(reportData) {
        const tbody = document.getElementById('results-table-body');
        if (!tbody) return;

        tbody.innerHTML = ''; // Clear mock data

        const components = reportData.components || [];

        components.forEach(comp => {
            // Find highest severity and calculate a score if missing
            let severity = 'LOW';
            let score = comp.risk_score || 0.0;

            // If risk score is missing but we have vulnerabilities, calculate explicit score
            if (score === 0 && comp.vulnerabilities && comp.vulnerabilities.length > 0) {
                // Example: Take Max CVSS as the base score
                score = comp.vulnerabilities.reduce((max, v) => Math.max(max, v.cvss || 0), 0);
            }

            // Re-map severity based on the (possibly new) score
            if (score >= 9.0) severity = 'CRITICAL';
            else if (score >= 7.0) severity = 'HIGH';
            else if (score >= 4.0) severity = 'MEDIUM';
            else severity = 'LOW';

            // If component has explicit vulns with severity, use max
            // But let's stick to score for sorting/badging for now

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="color: var(--text-primary); font-weight:500">${comp.name}</td>
                <td>${comp.version || 'N/A'}</td>
                <td>${score.toFixed(1)}</td>
                <td><span class="badge badge-${severity.toLowerCase()}">${severity}</span></td>
                <td>${comp.vulnerabilities ? comp.vulnerabilities.length + " issues detected" : "No issues"}</td>
            `;

            // Attach click
            tr.onclick = () => openDetail(comp, severity);
            tbody.appendChild(tr);
        });
    }

    function updateDashboard(stats, stages) {
        const scoreEl = document.getElementById('risk-score');

        // Use backend score if available, otherwise calculate a weighted score based on distribution
        let riskScore = stats.risk_score;

        if (riskScore === undefined || riskScore === null) {
            // Fallback: Weighted calculation
            // Critical=10, High=5, Medium=2, Low=1
            const dist = stats.risk_distribution || {};
            let totalScore = (dist['CRITICAL'] || 0) * 10 +
                (dist['HIGH'] || 0) * 5 +
                (dist['MEDIUM'] || 0) * 2 +
                (dist['LOW'] || 0) * 1;

            // Normalize slightly? Let's just cap at 100 for display
            riskScore = Math.min(100, totalScore);
        }

        if (scoreEl) {
            scoreEl.setAttribute('data-target', riskScore);
            scoreEl.textContent = riskScore;

            // If currently viewing dashboard, trigger animation now to show new score
            const dashboardView = document.getElementById('view-dashboard');
            if (dashboardView && dashboardView.classList.contains('active')) {
                triggerDashboardAnimations();
            }
        }

        // Update counts
        const metricPanels = document.querySelectorAll('.metric-panel .metric-value');
        if (metricPanels.length >= 4) {
            // 0: Total
            metricPanels[0].textContent = stats.total_components;

            // 1: Vulnerable
            metricPanels[1].textContent = stats.vulnerable_components;

            // 2: Critical
            const critCount = (stats.risk_distribution && stats.risk_distribution['CRITICAL']) || 0;
            metricPanels[2].textContent = critCount;

            // 3: Analysis Time
            let timeText = "0s";
            if (stages) {
                // Sum up values (assuming seconds or close enough)
                // If stages are like {'parsing': 0.1, ...}, sum is total time
                const totalTime = Object.values(stages).reduce((a, b) => a + b, 0);
                timeText = totalTime.toFixed(2) + "s";
            }
            metricPanels[3].textContent = timeText;
        }

        // Update distribution chart
        // stats.risk_distribution = { 'CRITICAL': 5, 'HIGH': 10 ... }
        if (stats.risk_distribution) {
            const dist = stats.risk_distribution;
            const total = stats.vulnerable_components || 1; // avoid div by zero

            const updateBar = (index, key) => {
                const count = dist[key] || 0;
                const pct = Math.round((count / total) * 100) + '%';
                const el = document.querySelector(`.dist-segment:nth-child(${index})`);
                if (el) el.setAttribute('data-target', pct);
            };

            updateBar(1, 'CRITICAL');
            updateBar(2, 'HIGH');
            updateBar(3, 'MEDIUM');
            updateBar(4, 'LOW');
        }
    }
});


// DETAIL PANEL LOGIC //////////////////////////////////////////////////////////
function openDetail(component, severity) {
    const panel = document.getElementById('detail-panel');
    const title = document.getElementById('detail-title');
    const badge = document.getElementById('detail-badge');
    const nlpContainer = document.getElementById('detail-nlp-text');
    const subTitle = document.querySelector('#detail-content div[style*="text-tertiary"]');

    title.textContent = component.name;
    if (subTitle) subTitle.textContent = "Version " + (component.version || 'Unknown');

    // Badge Logic
    badge.className = 'badge';
    if (severity === 'CRITICAL') badge.classList.add('badge-critical');
    else if (severity === 'HIGH') badge.classList.add('badge-high');
    else if (severity === 'MEDIUM') badge.classList.add('badge-medium');
    else badge.classList.add('badge-low');
    badge.textContent = severity;

    // NLP Content
    // Construct a description from vulnerabilities
    let fullText = "No vulnerabilities detected.";
    if (component.vulnerabilities && component.vulnerabilities.length > 0) {
        // Take the first one for the main text, or summarize
        const v = component.vulnerabilities[0];
        fullText = `Identified ${component.vulnerabilities.length} vulnerabilities. Primary concern: ${v.id}. ${v.description || 'No description available.'}`;
    }

    // Clear and Fill
    nlpContainer.innerHTML = '';

    // Split into sentences/lines for "Think" effect
    // Simple split by period, guarding against empty splits
    const sentences = fullText.match(/[^\.!\?]+[\.!\?]+/g) || [fullText];

    sentences.forEach((s, i) => {
        const p = document.createElement('div');
        p.className = 'nlp-text-line';
        p.textContent = s.trim();
        p.style.marginBottom = '8px';
        nlpContainer.appendChild(p);

        // Staggered Fade In
        setTimeout(() => p.classList.add('nlp-visible'), 400 + (i * 600));
    });

    panel.classList.add('open');
}

function closeDetail() {
    document.getElementById('detail-panel').classList.remove('open');
}

// Keep history detail static for now as it's just a demo element in the dashboard
function openHistoryDetail(name, trigger, severity) {
    // Re-using the same panel logic but with manual data
    const panel = document.getElementById('detail-panel');
    const title = document.getElementById('detail-title');
    const badge = document.getElementById('detail-badge');
    const nlpContainer = document.getElementById('detail-nlp-text');

    title.textContent = name;

    badge.className = 'badge';
    if (severity === 'CRITICAL') badge.classList.add('badge-critical');
    if (severity === 'HIGH') badge.classList.add('badge-high');
    if (severity === 'MEDIUM') badge.classList.add('badge-medium');
    if (severity === 'SAFE' || severity === 'LOW') badge.classList.add('badge-low');
    badge.textContent = severity;

    const fullText = `Historical analysis record for ${name}. Triggered via ${trigger}. System scan completed successfully with ${severity} risk assessment. No active threats detected in current session context.`;

    nlpContainer.innerHTML = '';
    const sentences = fullText.split('. ');
    sentences.forEach((s, i) => {
        if (!s.trim()) return;
        const p = document.createElement('div');
        p.className = 'nlp-text-line';
        p.textContent = s + '.';
        p.style.marginBottom = '8px';
        nlpContainer.appendChild(p);
        setTimeout(() => p.classList.add('nlp-visible'), 400 + (i * 600));
    });

    panel.classList.add('open');
}

// MODAL LOGIC /////////////////////////////////////////////////////////////////
// MODAL LOGIC /////////////////////////////////////////////////////////////////
window.openModal = function (type) {
    const modal = document.getElementById('info-modal');
    const title = document.getElementById('modal-title');
    const body = document.getElementById('modal-body');

    if (!modal) return;

    // Retrieve data
    const data = window.lastAnalysisData;
    const components = data ? (data.components || []) : [];

    modal.classList.add('open');

    if (type === 'critical') {
        title.textContent = 'CRITICAL FINDINGS';

        const criticals = components.filter(c => {
            // Re-calculate severity logic consistent with renderResults
            let score = c.risk_score || 0.0;
            if (score === 0 && c.vulnerabilities && c.vulnerabilities.length > 0) {
                score = c.vulnerabilities.reduce((max, v) => Math.max(max, v.cvss || 0), 0);
            }
            return score >= 9.0;
        });

        if (criticals.length === 0) {
            body.innerHTML = `<p>No critical vulnerabilities detected.</p>`;
        } else {
            body.innerHTML = `
                <p>${criticals.length} critical components detected requiring immediate attention:</p>
                <div style="max-height: 300px; overflow-y: auto; margin-top: 15px; padding-right: 5px;">
                    ${criticals.map(c => `
                        <div style="margin-bottom: 8px; padding: 10px; background: rgba(198, 40, 40, 0.1); border: 1px solid rgba(198, 40, 40, 0.3); border-radius: 4px;">
                            <div style="font-weight: 600; color: var(--text-primary);">${c.name} <span style="font-weight:400; color:var(--text-tertiary); font-size:12px;">v${c.version || '?'}</span></div>
                            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">
                                ${c.vulnerabilities && c.vulnerabilities.length > 0 ? c.vulnerabilities[0].id : 'Unknown CVE'}
                            </div>
                        </div>
                    `).join('')}
                </div>
            `;
        }

    } else if (type === 'vulnerable') {
        title.textContent = 'VULNERABILITY SUMMARY';

        const vulns = components.filter(c => c.vulnerabilities && c.vulnerabilities.length > 0);

        if (vulns.length === 0) {
            body.innerHTML = `<p>No vulnerable components detected.</p>`;
        } else {
            body.innerHTML = `
                <p>${vulns.length} components with known security advisories:</p>
                <div style="max-height: 300px; overflow-y: auto; margin-top: 15px; padding-right: 5px;">
                    ${vulns.map(c => `
                        <div style="margin-bottom: 6px; padding: 8px; background: rgba(255,255,255,0.05); border-radius: 4px; display:flex; justify-content:space-between; align-items:center;">
                            <span style="color: var(--text-primary);">${c.name}</span>
                            <span style="font-size: 12px; color: var(--text-tertiary);">${c.vulnerabilities.length} issues</span>
                        </div>
                    `).join('')}
                </div>
            `;
        }

    } else if (type === 'time') {
        title.textContent = 'PERFORMANCE BREAKDOWN';
        body.innerHTML = `
            <p>Total time spent in the analysis pipeline.</p>
            <ul style="margin-top:10px; margin-left:20px; color:var(--text-tertiary);">
                <li>Parsing SBOM</li>
                <li>Graph Construction</li>
                <li>Vulnerability Matching</li>
                <li>Risk Assessment (ML)</li>
            </ul>
        `;
    } else if (type === 'total') {
        title.textContent = 'COMPONENT INVENTORY';
        body.innerHTML = `
             <p>Total inventory of ${components.length} components found in SBOM.</p>
             <div style="max-height: 300px; overflow-y: auto; margin-top: 15px; padding-right: 5px; display:grid; grid-template-columns: 1fr 1fr; gap: 8px;">
                 ${components.map(c => `
                     <div style="font-size: 13px; color: var(--text-secondary); padding: 4px 8px; background: rgba(255,255,255,0.02); border-radius: 2px;">
                         ${c.name} <span style="opacity:0.5">v${c.version || '?'}</span>
                     </div>
                 `).join('')}
             </div>
        `;
    }
};

window.closeModal = function () {
    const m = document.getElementById('info-modal');
    if (m) m.classList.remove('open');
};

// Attack Click Handlers to Metric Panels
// 0: Total, 1: Vuln, 2: Critical, 3: Time
document.addEventListener('DOMContentLoaded', () => {
    // We need to wait a tick or re-query because script.js runs at end of body but just to be safe
    // Actually the initial DOMContentLoaded handles the main logic, but this is appended code.
    // It's safer to just run this block immediately as the script is at the end of body.

    setTimeout(() => {
        const panels = document.querySelectorAll('.metric-panel');
        if (panels.length >= 4) {
            panels[0].style.cursor = 'pointer';
            panels[0].onclick = () => window.openModal('total');

            panels[1].style.cursor = 'pointer';
            panels[1].onclick = () => window.openModal('vulnerable');

            panels[2].style.cursor = 'pointer';
            panels[2].onclick = () => window.openModal('critical');

            panels[3].style.cursor = 'pointer';
            panels[3].onclick = () => window.openModal('time');
        }
    }, 500);
});
