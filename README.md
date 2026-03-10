## Why This Code is Superior

You can switch between bcrypt (Industry Standard) and scrypt (Memory-Hard) via CLI.

* Pre-hashes passwords with a secret server-side pepper. This prevents bcrypt truncation and adds a layer of protection if the database is leaked.

* Implements scrypt with a tunable cost factor (N=16384) to defeat hardware-accelerated cracking.

* Enforces a 24-character minimum and complex entropy rules (Uppercase, Digits, Special chars).
---

## Quick Start

### 1. Install Dependencies

```bash
npm install 
```

### 2. Put pepper in `.env` :

```.env
PEPPER=
```

generate with: 
`node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`

### 3. Usage

To **save** and **verify** password :

```bash
# Save/Verify using scrypt
node use.js scrypt "Complex_Password_123!@#456"
```

```bash
# Save/Verify using bcrypt
node use.js bcrypt "Complex_Password_123!@#456"
```