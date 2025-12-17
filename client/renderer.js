// client/renderer.js
import { generateSessionKey, generateIv, aes256cbcEncrypt, computeHmacSHA256, rsaEncryptSessionKey } from './crypto.js';
import Chart from 'chart.js/auto';
import dayjs from 'dayjs';
const { exec } = window.require ? window.require('child_process') : {};

// --- Element references ---
const els = {
    serverUrl: document.getElementById('serverUrl'),
    fetchKeyBtn: document.getElementById('fetchKeyBtn'),
    pubKeyArea: document.getElementById('pubKeyArea'),
    resultArea: document.getElementById('resultArea'),
    sendBtn: document.getElementById('sendBtn'),
    trainBtn: document.getElementById('trainBtn'),
    department: document.getElementById('department'),
    studentId: document.getElementById('studentId'),
    name: document.getElementById('name'),
    email: document.getElementById('email'),
    message: document.getElementById('message'),
    metricTotal: document.getElementById('metricTotal'),
    metricValid: document.getElementById('metricValid'),
    metricTampered: document.getElementById('metricTampered'),
    sparkTotal: document.getElementById('sparkTotal'),
    sparkValid: document.getElementById('sparkValid'),
    sparkTampered: document.getElementById('sparkTampered'),
    outlayChart: document.getElementById('outlayChart'),
    incomeChart: document.getElementById('incomeChart'),
    latestList: document.getElementById('latestList'),
    deptFilter: document.getElementById('deptFilter'),
    segButtons: document.querySelectorAll('.seg'),
    serverStatus: document.getElementById('serverStatus')
};

let serverPublicKeyPem = '';
let outlayChart, incomeChart, sparkTotal, sparkValid, sparkTampered;
let serverProcess = null;

// --- Server status ---
async function updateServerStatus() {
    try {
        const resp = await fetch(`${els.serverUrl.value.replace(/\/$/, '')}/public-key`);
        if (resp.ok) {
            els.serverStatus.textContent = 'Server: Running';
            els.serverStatus.style.color = '#10b981';
        } else {
            els.serverStatus.textContent = 'Server: Stopped';
            els.serverStatus.style.color = '#ef4444';
        }
    } catch {
        els.serverStatus.textContent = 'Server: Stopped';
        els.serverStatus.style.color = '#ef4444';
    }
}

// Optional GUI Start/Stop buttons
els.startServerBtn?.addEventListener('click', () => {
    if (!exec) return alert('Node integration is required for GUI server control.');
    if (serverProcess) return alert('Server already running via GUI!');
    serverProcess = exec('node ../server/app.js', { cwd: __dirname });
    serverProcess.stdout.on('data', data => console.log('[Server]', data));
    serverProcess.stderr.on('data', data => console.error('[Server]', data));
    serverProcess.on('close', () => { serverProcess = null; updateServerStatus(); });
    updateServerStatus();
    alert('Server started via GUI!');
});

els.stopServerBtn?.addEventListener('click', () => {
    if (!serverProcess) return alert('No GUI-launched server is running.');
    serverProcess.kill();
    serverProcess = null;
    updateServerStatus();
    alert('Server stopped via GUI!');
});

setInterval(updateServerStatus, 2000); // Auto-refresh
updateServerStatus(); // Initial check

// --- Charts setup ---
function gradient(ctx, colorA, colorB) {
    const g = ctx.createLinearGradient(0, 0, 0, 180);
    g.addColorStop(0, colorA);
    g.addColorStop(1, colorB);
    return g;
}

function initCharts() {
    const makeSpark = (canvas, data, color='#ff5f8a') => new Chart(canvas, {
        type: 'line',
        data: { labels: data.map((_, i) => i), datasets: [{ data, borderColor: color, tension: 0.4, borderWidth: 2, pointRadius: 0 }] },
        options: { plugins: { legend: { display: false } }, scales: { x: { display: false }, y: { display: false } }, responsive: true }
    });

    sparkTotal = makeSpark(els.sparkTotal.getContext('2d'), [0], '#8b5cf6');
    sparkValid = makeSpark(els.sparkValid.getContext('2d'), [0], '#10b981');
    sparkTampered = makeSpark(els.sparkTampered.getContext('2d'), [0], '#ef4444');

    const ctxO = els.outlayChart.getContext('2d');
    outlayChart = new Chart(ctxO, {
        type: 'line',
        data: { labels: [], datasets: [{ label: 'Messages', data: [], fill: true, backgroundColor: gradient(ctxO, 'rgba(139,92,246,0.35)', 'rgba(255,95,138,0.05)'), borderColor: '#8b5cf6', tension: 0.4, pointRadius: 0, borderWidth: 2 }] },
        options: { plugins: { legend: { display: false } }, scales: { x: { grid: { display: false }, ticks: { color: '#a8b0c2' } }, y: { grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#a8b0c2' } } } }
    });

    const ctxI = els.incomeChart.getContext('2d');
    incomeChart = new Chart(ctxI, {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Messages', data: [], backgroundColor: '#ff5f8a' }] },
        options: { plugins: { legend: { display: false } }, scales: { x: { grid: { display: false }, ticks: { color: '#a8b0c2' } }, y: { grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#a8b0c2' } } } }
    });
}

// --- Fetch public key ---
els.fetchKeyBtn.addEventListener('click', async () => {
    try {
        const resp = await fetch(`${els.serverUrl.value.replace(/\/$/, '')}/public-key`);
        if (!resp.ok) throw new Error(`Status ${resp.status}`);
        serverPublicKeyPem = await resp.text();
        els.pubKeyArea.textContent = serverPublicKeyPem;
    } catch (err) {
        els.pubKeyArea.textContent = `[ERROR] ${err.message}`;
    }
});

// --- Send message ---
els.sendBtn.addEventListener('click', async () => {
    if (!serverPublicKeyPem) { els.resultArea.textContent = 'Fetch the public key first.'; return; }
    try {
        const studentPayload = {
            department: els.department.value,
            studentId: els.studentId.value,
            name: els.name.value,
            email: els.email.value,
            message: els.message.value
        };
        const plaintext = JSON.stringify(studentPayload);

        const sessionKey = generateSessionKey();
        const iv = generateIv();
        const ciphertextBuf = aes256cbcEncrypt(sessionKey, iv, plaintext);

        const canonical = [
            'department=', studentPayload.department,
            '&studentId=', studentPayload.studentId,
            '&ivB64=', iv.toString('base64'),
            '&ciphertextB64=', ciphertextBuf.toString('base64')
        ].join('');

        const hmacBuf = computeHmacSHA256(sessionKey, canonical);
        const encKeyBuf = rsaEncryptSessionKey(serverPublicKeyPem, sessionKey);

        const outgoing = {
            department: studentPayload.department,
            studentId: studentPayload.studentId,
            name: studentPayload.name,
            email: studentPayload.email,
            ivB64: iv.toString('base64'),
            ciphertextB64: ciphertextBuf.toString('base64'),
            encKeyB64: encKeyBuf.toString('base64'),
            hmacB64: hmacBuf.toString('base64'),
            algo: 'RSA-OAEP/AES-256-CBC/HMAC-SHA256',
            timestamp: new Date().toISOString()
        };

        const resp = await fetch(`${els.serverUrl.value.replace(/\/$/, '')}/messages`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(outgoing)
        });
        const data = await resp.json();
        els.resultArea.textContent = JSON.stringify(data, null, 2);

        fetchMetrics();
    } catch (err) {
        els.resultArea.textContent = `[ERROR] ${err.message}`;
    }
});

// --- Train button ---
els.trainBtn.addEventListener('click', async () => {
    for (let i = 0; i < 10; i++) {
        els.message.value = `Training message #${i+1} at ${dayjs().format('HH:mm:ss')}`;
        await els.sendBtn.click();
        await new Promise(r => setTimeout(r, 150));
    }
});

// --- Fetch metrics ---
async function fetchMetrics() {
    try {
        const resp = await fetch(`${els.serverUrl.value.replace(/\/$/, '')}/metrics`);
        if (!resp.ok) throw new Error(`Metrics fetch failed: ${resp.status}`);
        const metrics = await resp.json();

        els.metricTotal.textContent = metrics.total;
        els.metricValid.textContent = metrics.valid;
        els.metricTampered.textContent = metrics.tampered;

        sparkTotal.data.datasets[0].data = metrics.series.total;
        sparkValid.data.datasets[0].data = metrics.series.valid;
        sparkTampered.data.datasets[0].data = metrics.series.tampered;
        sparkTotal.update(); sparkValid.update(); sparkTampered.update();

        outlayChart.data.labels = metrics.outlay.labels;
        outlayChart.data.datasets[0].data = metrics.outlay.values;
        outlayChart.update();

        incomeChart.data.labels = metrics.department.labels;
        incomeChart.data.datasets[0].data = metrics.department.values;
        incomeChart.update();

        els.latestList.innerHTML = '';
        metrics.latest.forEach(m => {
            const li = document.createElement('li');
            const badge = `<span class="badge ${m.hmac_ok ? 'ok' : 'bad'}">${m.hmac_ok ? 'HMAC OK' : 'Tampered'}</span>`;
            li.innerHTML = `<div>${m.name} • ${m.studentId}</div><div>${m.department}</div><div>${badge}</div>`;
            els.latestList.appendChild(li);
        });

        els.deptFilter.innerHTML = '';
        metrics.department.labels.forEach(d => {
            const opt = document.createElement('option');
            opt.value = d;
            opt.textContent = d;
            els.deptFilter.appendChild(opt);
        });
    } catch (err) {
        console.warn('Failed to fetch metrics:', err.message);
    }
}

// --- Seg buttons ---
els.segButtons.forEach(btn => {
    btn.addEventListener('click', () => {
        els.segButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        fetchMetrics();
    });
});

// --- Initialize dashboard ---
initCharts();
fetchMetrics();
setInterval(fetchMetrics, 5000);
