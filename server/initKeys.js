// server/initKeys.js
import { ensureRsaKeys } from './crypto.js';

ensureRsaKeys();
console.log('RSA keys ensured/generated.');
