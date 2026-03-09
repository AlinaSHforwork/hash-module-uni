const fs = require('fs').promises;
const AuthHash = require('./index.js');
const dotenv = require('dotenv');
dotenv.config();

const PEPPER = process.env.PEPPER || 'default_pepper_for_demo'; 
const FILE_PATH = './password.txt';

const auth = new AuthHash(PEPPER);
    
function isValid(pwd) {
    // (?=.*[A-Z]) - minimum one uppercase letter
    // (?=.*[a-z]) - minimum one lowercase letter
    // (?=.*\d)    - minimum one digit
    // (?=.*[\W_]) - minimum one special character
    // .{24,}      - length not less than 24 characters
    return /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{24,}$/.test(pwd);
}

async function start() {
    const inputPassword = process.argv[2];

    if (!inputPassword) {
        return console.log("Write: node use.js 'Password...' ");
    }

    try {
        let storedHash;
        try {
            storedHash = await fs.readFile(FILE_PATH, 'utf8');
        } catch (e) {
            storedHash = null;
        }

        if (!storedHash) {
            if (!isValid(inputPassword)) {
                return console.error("Weak password! Required: 24+ characters, Uppercase letter, Digit, Special character.");
            }

            const newHash = await auth.hashPassword(inputPassword);
            await fs.writeFile(FILE_PATH, newHash);
            console.log("Password verified and saved to password.txt");
            
        } else {
            const isMatch = await auth.verifyPassword(inputPassword, storedHash.trim());
            console.log(isMatch ? "Access granted (true)" : "Invalid password (false)");
        }
    } catch (err) {
        console.error("System error:", err.message);
    }
}

start();