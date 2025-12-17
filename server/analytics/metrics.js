// server/analytics/metrics.js
import fs from 'fs';
import path from 'path';

const LOG_PATH = path.join(process.cwd(), 'server', 'storage.json');

export function computeMetrics() {
    let logs = [];
    try {
        if (fs.existsSync(LOG_PATH)) {
            logs = JSON.parse(fs.readFileSync(LOG_PATH, 'utf8'));
        }
    } catch {
        logs = [];
    }

    const total = logs.length;
    const valid = logs.filter(l => l.hmac_ok).length;
    const tampered = total - valid;

    // Sparkline series (last 7 entries)
    const last7 = logs.slice(-7);
    const series = {
        total: last7.map((_, i) => i + 1),
        valid: last7.map(l => l.hmac_ok ? 1 : 0),
        tampered: last7.map(l => l.hmac_ok ? 0 : 1)
    };

    // Outlay chart: messages per department
    const outlayCounts = {};
    logs.forEach(l => {
        if (!outlayCounts[l.department]) outlayCounts[l.department] = 0;
        outlayCounts[l.department]++;
    });
    const outlay = {
        labels: Object.keys(outlayCounts),
        values: Object.values(outlayCounts)
    };

    // Department chart (bar chart)
    const deptCounts = { ...outlayCounts }; // same as outlay for simplicity
    const department = {
        labels: Object.keys(deptCounts),
        values: Object.values(deptCounts)
    };

    // Latest messages (last 5)
    const latest = logs.slice(-5).reverse().map(l => ({
        name: l.name,
        student_id: l.studentId,
        department: l.department,
        hmac_ok: l.hmac_ok
    }));

    return { total, valid, tampered, series, outlay, department, latest };
}
