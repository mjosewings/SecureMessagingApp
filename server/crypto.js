// server/crypto.js
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

// Fix for __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const KEYS_DIR = path.join(__dirname, '.keys');
const PUB_PATH = path.join(KEYS_DIR, 'public.pem');
const PRIV_PATH = path.join(KEYS_DIR, 'private.pem');

/**
 * Ensure RSA keys exist, generate if missing
 */
export function ensureRsaKeys() {
    if (!fs.existsSync(KEYS_DIR)) fs.mkdirSync(KEYS_DIR, { recursive: true });
    if (fs.existsSync(PUB_PATH) && fs.existsSync(PRIV_PATH)) return;

    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'pkcs1', format: 'pem' },   // PKCS#1 PEM
        privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
    });

    fs.writeFileSync(PUB_PATH, publicKey);
    fs.writeFileSync(PRIV_PATH, privateKey);
    console.log('RSA keys generated.');
}

/**
 * Read public/private key PEM files
 */
export function getPublicKeyPEM() {
    return fs.readFileSync(PUB_PATH, 'utf8');
}

export function getPrivateKeyPEM() {
    return fs.readFileSync(PRIV_PATH, 'utf8');
}

/**
 * RSA-OAEP decrypt session key
 * @param {string} encKeyB64
 * @returns {Buffer} session key
 */
export function rsaDecryptSessionKey(encKeyB64) {
    const privateKey = getPrivateKeyPEM();
    const encBuf = Buffer.from(encKeyB64, 'base64');
    return crypto.privateDecrypt(
        { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
        encBuf
    );
}

/**
 * HMAC-SHA256
 */
export function computeHmacSHA256(keyBuf, canonicalString) {
    return crypto.createHmac('sha256', keyBuf).update(canonicalString).digest('base64');
}

/**
 * AES-256-CBC decrypt
 */
export function aes256cbcDecrypt(keyBuf, ivB64, ciphertextB64) {
    const iv = Buffer.from(ivB64, 'base64');
    const ct = Buffer.from(ciphertextB64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuf, iv);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
    return plain.toString('utf8');
}

/**
 * Optional: verify HMAC
 */
export function verifyHmacSHA256(keyBuf, canonicalString, hmacB64) {
    const computed = computeHmacSHA256(keyBuf, canonicalString);
    return crypto.timingSafeEqual(Buffer.from(computed, 'base64'), Buffer.from(hmacB64, 'base64'));
}
