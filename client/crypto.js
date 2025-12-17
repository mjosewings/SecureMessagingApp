// client/crypto.js
import crypto from 'crypto';

/**
 * Generate a random 32-byte AES session key
 * @returns {Buffer}
 */
export function generateSessionKey() {
    return crypto.randomBytes(32);
}

/**
 * Generate a random 16-byte IV
 * @returns {Buffer}
 */
export function generateIv() {
    return crypto.randomBytes(16);
}

/**
 * AES-256-CBC encrypt plaintext
 * @param {Buffer} keyBuf - 32-byte session key
 * @param {Buffer} iv - 16-byte initialization vector
 * @param {string} plaintext - string to encrypt
 * @returns {Buffer} ciphertext
 */
export function aes256cbcEncrypt(keyBuf, iv, plaintext) {
    const cipher = crypto.createCipheriv('aes-256-cbc', keyBuf, iv);
    const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return ct;
}

/**
 * Compute HMAC-SHA256 over a canonical string
 * @param {Buffer} keyBuf - AES session key
 * @param {string} canonicalString
 * @returns {Buffer} HMAC
 */
export function computeHmacSHA256(keyBuf, canonicalString) {
    return crypto.createHmac('sha256', keyBuf).update(canonicalString).digest();
}

/**
 * Encrypt AES session key with server's RSA public key (RSA-OAEP SHA256)
 * @param {string} serverPublicKeyPem - PEM formatted RSA public key
 * @param {Buffer} sessionKey - 32-byte AES key
 * @returns {Buffer} encrypted key
 */
export function rsaEncryptSessionKey(serverPublicKeyPem, sessionKey) {
    return crypto.publicEncrypt(
        {
            key: serverPublicKeyPem,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        sessionKey
    );
}
