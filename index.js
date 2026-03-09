const crypto = require('crypto');
const bcrypt = require('bcrypt');

class AuthHash {
    constructor(pepper, costFactor = 15) {
        if (!pepper || Buffer.byteLength(pepper, 'utf8') < 32) {
            throw new Error("Fatal: Pepper must be at least 32 random bytes (256-bit entropy) for maximum security.");
        }

        this.pepper = pepper;
        this.costFactor = Math.max(12, Math.min(18, costFactor));
    }

    preparePassword(password) {
        if (typeof password !== 'string' || password.length === 0) {
            throw new Error("Password must be a non-empty string.");
        }

        return crypto
            .createHmac('sha384', this.pepper)
            .update(password, 'utf8')
            .digest('base64');
    }

    async hashPassword(password) {
        if (typeof password !== 'string' || password.length > 4096) {
            throw new Error("Password must be a non-empty string (max 4096 characters).");
        }

        const processedPassword = this.preparePassword(password);
        return await bcrypt.hash(processedPassword, this.costFactor);
    }

    async verifyPassword(inputPassword, storedHash) {
        if (typeof inputPassword !== 'string' || !storedHash) {
            return false;
        }

        try {
            const processedPassword = this.preparePassword(inputPassword);
            return await bcrypt.compare(processedPassword, storedHash.trim());
        } catch (error) {
            return false;
        }
    }
}

module.exports = AuthHash;