// server/app.js
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { ensureRsaKeys, getPublicKeyPEM, rsaDecryptSessionKey, computeHmacSHA256, aes256cbcDecrypt } from './crypto.js';
import { validateIncomingPayload, canonicalStringForHmac } from './models.js';
import { computeMetrics } from './analytics/metrics.js';

const app = express();
const PORT = process.env.PORT || 8000;
const LOG_PATH = path.join(process.cwd(), 'server', 'storage.json');

// Ensure RSA keys exist
ensureRsaKeys();

app.use(helmet());
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '256kb' }));

// --- Public Key Endpoint ---
app.get('/public-key', (req, res) => {
    try {
        const pub = getPublicKeyPEM();
        res.type('text/plain').send(pub);
    } catch (err) {
        console.error('[GET /public-key] Error:', err);
        res.status(500).send('Failed to read public key');
    }
});

// --- Metrics Endpoint ---
app.get('/metrics', (req, res) => {
    try {
        const metrics = computeMetrics();
        res.json(metrics);
    } catch (err) {
        console.error('[GET /metrics] Error:', err);
        res.status(500).json({ ok: false, error: 'Failed to compute metrics' });
    }
});

// --- Messages Endpoint ---
app.post('/messages', (req, res) => {
    try {
        const payload = validateIncomingPayload(req.body);

        // 1) RSA-decrypt session key
        const sessionKeyBuf = rsaDecryptSessionKey(payload.encKeyB64);
        if (sessionKeyBuf.length !== 32) {
            return res.status(400).json({ ok: false, error: 'Invalid session key length' });
        }

        // 2) Verify HMAC
        const canonical = canonicalStringForHmac(payload);
        const localHmacB64 = computeHmacSHA256(sessionKeyBuf, canonical);
        const hmacOk = cryptoSafeCompareB64(localHmacB64, payload.hmacB64);

        if (!hmacOk) {
            return res.status(400).json({ ok: false, error: 'HMAC verification failed (tampered)' });
        }

        // 3) Decrypt message
        const plaintext = aes256cbcDecrypt(sessionKeyBuf, payload.ivB64, payload.ciphertextB64);

        // 4) Persist log entry
        const entry = {
            ts: new Date().toISOString(),
            department: payload.department,
            studentId: payload.studentId,
            name: payload.name,
            email: payload.email,
            algo: payload.algo,
            plaintext,
            hmac_ok: hmacOk
        };
        appendLog(entry);

        return res.json({
            ok: true,
            received: { department: entry.department, studentId: entry.studentId },
            length: plaintext.length
        });
    } catch (err) {
        console.error('[POST /messages] Error:', err);
        return res.status(500).json({ ok: false, error: 'Server error' });
    }
});

// --- Utility functions ---
function cryptoSafeCompareB64(aB64, bB64) {
    const a = Buffer.from(aB64, 'base64');
    const b = Buffer.from(bB64, 'base64');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
}

function appendLog(entry) {
    let existing = [];
    try {
        if (fs.existsSync(LOG_PATH)) {
            existing = JSON.parse(fs.readFileSync(LOG_PATH, 'utf8'));
        }
    } catch {
        existing = [];
    }
    existing.push(entry);
    fs.writeFileSync(LOG_PATH, JSON.stringify(existing, null, 2), 'utf8');
}

// --- Start server ---
app.listen(PORT, () => {
    console.log(`Secure Messaging Server listening on http://127.0.0.1:${PORT}`);
    console.log('Public key available at GET /public-key');
    console.log('Metrics available at GET /metrics');
});
