const crypto = require('node:crypto');
const { promisify } = require('node:util');
const scrypt = promisify(crypto.scrypt);

const SCRYPT_CONFIG = {
  N: 16384, 
  r: 8,     
  p: 1,   
  maxmem: 32 * 1024 * 1024,
  keylen: 64,
};

class HashModule {
  constructor(pepper) {
    if (!pepper || pepper.length < 32) {
      throw new Error("Pepper must be at least 32 bytes of entropy.");
    }
    this.pepper = pepper;
  }

  async hashPassword(password) {
    const hmac = crypto.createHmac('sha384', this.pepper)
      .update(password)
      .digest();

    const salt = crypto.randomBytes(16).toString('hex');

    const derivedKey = await scrypt(hmac, salt, SCRYPT_CONFIG.keylen, SCRYPT_CONFIG);

    return `$s2$${salt}$${derivedKey.toString('base64')}`;
  }

  async verifyPassword(password, storedHash) {
    const [version, salt, hash] = storedHash.split('$').slice(1);
    
    if (version !== 's2') throw new Error("Unsupported hash version");

    const hmac = crypto.createHmac('sha384', this.pepper)
      .update(password)
      .digest();

    const derivedKey = await scrypt(hmac, salt, SCRYPT_CONFIG.keylen, SCRYPT_CONFIG);
    
    return crypto.timingSafeEqual(derivedKey, Buffer.from(hash, 'base64'));
  }
}

module.exports = HashModule;