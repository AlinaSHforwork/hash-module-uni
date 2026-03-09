## Why This Code is Superior

Standard bcrypt implementation is good, but it has two hidden vulnerabilities: it silently truncates passwords longer than 72 bytes, and it is vulnerable to null-byte injection. This code implements the "Pre-hashed HMAC Pepper" pattern to solve both issues while adding an extra layer of defense against database leaks.

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

### 4. Usage

To **save** a new password (if `password.txt` doesn't exist):

```bash
node use.js "your_password"

```

To **verify** against the saved hash:

```bash
node use.js "your_password"
# Output: true, if wrong password false

```