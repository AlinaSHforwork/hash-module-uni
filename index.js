const { createHash, createHmac } = require('crypto');
const bcrypt = require('bcrypt');

class AuthHash {
    constructor(pepper, costFactor = 13) {
        if (!pepper) throw new Error("Fatal: A pepper is required for maximum security.");
        this.pepper = pepper;
        this.costFactor = costFactor;
    }

    preparePassword(password) {
        const preHashed = createHash('sha256').update(password).digest('hex');
        const peppered = createHmac('sha256', this.pepper).update(preHashed).digest('base64');
        return peppered;
    }

    async hashPassword(password) {
        if (!password) throw new Error("Password cannot be empty.");
        
        const processedPassword = this.preparePassword(password);
        return await bcrypt.hash(processedPassword, this.costFactor);
    }

    async verifyPassword(inputPassword, storedHash) {
        if (!inputPassword || !storedHash) return false;

        try {
            const processedPassword = this.preparePassword(inputPassword);
            return await bcrypt.compare(processedPassword, storedHash);
        } catch (error) {
            return false;
        }
    }
}

module.exports = AuthHash;