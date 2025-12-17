
// server/models.js

export function validateIncomingPayload(body) {
    // Expected fields:
    // department, studentId, ciphertextB64, ivB64, encKeyB64, hmacB64
    const required = ['department', 'studentId', 'ciphertextB64', 'ivB64', 'encKeyB64', 'hmacB64'];
    for (const k of required) {
        if (typeof body[k] !== 'string' || body[k].length === 0) {
            throw new Error(`Missing or invalid field: ${k}`);
        }
    }
    // Optional meta: algo, timestamp, email, name
    return {
        department: body.department,
        studentId: body.studentId,
        name: body.name ?? '',
        email: body.email ?? '',
        ciphertextB64: body.ciphertextB64,
        ivB64: body.ivB64,
        encKeyB64: body.encKeyB64,
        hmacB64: body.hmacB64,
        algo: body.algo ?? 'RSA-OAEP/AES-256-CBC/HMAC-SHA256',
        timestamp: body.timestamp ?? new Date().toISOString()
    };
}

export function canonicalStringForHmac(p) {
    // Stable concatenation—client must compute HMAC over the exact same string.
    // Avoid JSON.stringify differences. Keep order predictable.
    return [
        'department=', p.department,
        '&studentId=', p.studentId,
        '&ivB64=', p.ivB64,
        '&ciphertextB64=', p.ciphertextB64
    ].join('');
}

