const readline = require('readline');
const fs = require('fs');
const AuthHash = require('./bcryptHash.js');
const HashModule = require('./scryptHash.js');
const { Pool } = require('pg');
const dotenv = require('dotenv');
dotenv.config();

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function ensureTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id         SERIAL PRIMARY KEY,
      username   TEXT NOT NULL UNIQUE,
      hash       TEXT NOT NULL,
      algorithm  TEXT NOT NULL CHECK (algorithm IN ('bcrypt','scrypt')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

const PEPPER = process.env.PEPPER;
if (!PEPPER) { console.error('Fatal: PEPPER is not set in .env'); process.exit(1); }

function makeHasher(algo) {
  return algo === 'scrypt' ? new HashModule(PEPPER) : new AuthHash(PEPPER);
}

function isValid(pwd) {
    // (?=.*[A-Z]) - minimum one uppercase letter
    // (?=.*[a-z]) - minimum one lowercase letter
    // (?=.*\d)    - minimum one digit
    // (?=.*[\W_]) - minimum one special character
    // .{24,}      - length not less than 24 characters
    return /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{24,}$/.test(pwd);
}

function askMasked(rl, prompt = 'Password: ') {
  return new Promise((resolve) => {
    if (!process.stdin.isTTY) {
      rl.question(prompt, (line) => resolve(line.trim()));
      return;
    }
    const originalWriteToOutput = rl._writeToOutput;
    rl._writeToOutput = function (stringToWrite) {
      if (/\r|\n/.test(stringToWrite)) {
        process.stdout.write(stringToWrite);
      } else {
        readline.cursorTo(process.stdout, 0);
        process.stdout.clearLine(0);
        process.stdout.write(prompt + '*'.repeat(rl.line.length));
      }
    };
    const onSigint = () => {
      rl._writeToOutput = originalWriteToOutput;
      process.stdout.write('\n');
      process.exit(1);
    };
    rl.once('SIGINT', onSigint);
    rl.question(prompt, (password) => {
      rl.removeListener('SIGINT', onSigint);
      rl._writeToOutput = originalWriteToOutput;
      resolve(password);
    });
  });
}

function ask(rl, prompt) {
  return new Promise(resolve => rl.question(prompt, resolve));
}

async function main() {
  await ensureTable();

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  let algo = '';
  while (!['bcrypt', 'scrypt'].includes(algo)) {
    algo = (await ask(rl, 'Choose algorithm [bcrypt / scrypt]: ')).trim().toLowerCase();
    if (!['bcrypt', 'scrypt'].includes(algo)) console.log('  Please type bcrypt or scrypt.');
  }

  let username = '';
  while (!username) {
    username = (await ask(rl, 'Username: ')).trim();
    if (!username) console.log('  Username cannot be empty.');
  }
  const password = await askMasked(rl, 'Password: ');
  rl.close();

  if (!password) { console.error('Password cannot be empty.'); process.exit(1); }
  const hasher = makeHasher(algo);

  const { rows } = await pool.query(
    'SELECT hash, algorithm FROM users WHERE username = $1',
    [username]
  );

  if (rows.length === 0) {
    if (!isValid(password)) {
      console.error('Weak password! Required: 24+ characters, uppercase, lowercase, digit, special character.');
      await pool.end();
      process.exit(1);
    }

    const hash = await hasher.hashPassword(password);

    await pool.query(
      'INSERT INTO users (username, hash, algorithm) VALUES ($1, $2, $3)',
      [username, hash, algo]
    );
    console.log(`\nUser "${username}" registered successfully (${algo}).`);

  } else {
    const { hash: storedHash, algorithm: storedAlgo } = rows[0];

    if (storedAlgo !== algo) {
      console.warn(`\nThis user was registered with ${storedAlgo}, not ${algo}. Verifying with ${storedAlgo}.`);
    }

    const verifier = makeHasher(storedAlgo);
    const ok = await verifier.verifyPassword(password, storedHash);

    console.log(ok
      ? `\nAccess granted — welcome, ${username}!`
      : `\nInvalid password.`
    );
  }
  await pool.end();
}

main().catch(err => {
  console.error('System error:', err.message);
  process.exit(1);
});