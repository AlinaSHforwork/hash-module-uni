## Why This Code is Superior

Standard bcrypt implementation is good, but it has two hidden vulnerabilities: it silently truncates passwords longer than 72 bytes, and it is vulnerable to null-byte injection. This version implements the optimal "Direct HMAC-SHA256 Pepper" pattern to solve both issues, uses a stronger default cost factor of 14, and adds validation for maximum security in 2026.

### Follows OWASP Password Storage Cheat Sheet exactly:
* Direct HMAC-SHA384 pepper (stronger than SHA-256)
* base64 output (always 64 characters – safe under bcrypt limit)
* Default cost 15 (high-security level for 2026 hardware)
* Strict pepper validation (minimum 32 bytes / 256-bit entropy)

---

## Quick Start

### 1. Install Dependencies

```bash
npm install 
```

### 2. Set Up Files

* `index.js`: The hash engine.
* `use.js`: The script that handles your `password.txt` file.

### 3. Put pepper in `.env` :

```.env
PEPPER=
```

generate with: 
`node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`

### 4. Usage

To **save** a new password (if `password.txt` doesn't exist):

```bash
node use.js "your_password"

```

To **verify** against the saved hash:

```bash
node use.js "your_password"
# Output: Access granted (true) or Invalid password (false)

```