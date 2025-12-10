# Simple-Crypt Project Report

## Project Overview

**simple-crypt** is a Python library that provides simple, secure encryption and decryption functionality for Python 2.7 and 3. The project is designed to be easy to use while following cryptographic best practices.

- **Repository**: [andrewcooke/simple-crypt](https://github.com/andrewcooke/simple-crypt)
- **PyPI Package**: [simple-crypt](http://pypi.python.org/pypi/simple-crypt)
- **Current Version**: 4.1.7
- **License**: Public Domain
- **Author**: Andrew Cooke (andrew@acooke.org), d10n (david@bitinvert.com)

---

## Key Features

- **Simple API**: Two main functions - `encrypt()` and `decrypt()`
- **Strong Encryption**: Uses AES256 CTR mode
- **Secure Key Derivation**: PBKDF2 with SHA256, 256-bit random salt, and 100,000 iterations
- **Data Integrity**: HMAC with SHA256 to detect tampering
- **Version Compatibility**: Backward compatible for decryption (newer versions can decrypt older data)
- **Cross-Platform**: Works on Python 2.7 and Python 3.x

---

## Installation

### Prerequisites

- Python 2.7 or Python 3.x
- `pycrypto` library (dependency)

### Installation Methods

#### Method 1: Install from PyPI
```bash
pip install simple-crypt
```

#### Method 2: Install from Source
```bash
# Navigate to project directory
cd simple-crypt

# Install the package
pip install .
```

#### Method 3: Development Mode
```bash
pip install -e .
```

### Dependency Installation

The library requires `pycrypto`:
```bash
pip install pycrypto
```

> **Note**: `pycrypto` has C components and requires a full Python installation. On some Unix systems, you may need to install `python-dev` package first.

---

## Usage

### Basic API

The library provides two primary functions:

```python
from simplecrypt import encrypt, decrypt

# Encrypt data
ciphertext = encrypt(password, plaintext)

# Decrypt data
plaintext = decrypt(password, ciphertext)
```

### Example 1: Interactive Encryption

```python
from binascii import hexlify
from getpass import getpass
from sys import stdin
from simplecrypt import encrypt, decrypt

# Read password from user (without displaying it)
password = getpass("password: ")

# Read the plaintext message
print("message: ")
message = stdin.readline()

# Encrypt the plaintext
ciphertext = encrypt(password, message.encode('utf8'))

# Display as hex string
print("ciphertext: %s" % hexlify(ciphertext))

# Decrypt
plaintext = decrypt(password, ciphertext)

# Display results
print("plaintext: %s" % plaintext)
print("plaintext as string: %s" % plaintext.decode('utf8'))
```

**Sample Output:**
```
password: ******
message:
hello world
ciphertext: b'73630001b1c39575390d5720f2a80e7a06fbddbf2c844d6b8eaf845d4a9e140d...'
plaintext: b'hello world\n'
plaintext as string: hello world
```

### Example 2: File Encryption/Decryption

```python
from simplecrypt import encrypt, decrypt
from os.path import exists
from os import unlink

PASSWORD = "secret"
FILENAME = "encrypted.txt"

def read_encrypted(password, filename, string=True):
    with open(filename, 'rb') as input:
        ciphertext = input.read()
        plaintext = decrypt(password, ciphertext)
        if string:
            return plaintext.decode('utf8')
        else:
            return plaintext

def write_encrypted(password, filename, plaintext):
    with open(filename, 'wb') as output:
        ciphertext = encrypt(password, plaintext)
        output.write(ciphertext)

# Example usage
if exists(FILENAME):
    data = read_encrypted(PASSWORD, FILENAME)
    print("read %s from %s" % (data, FILENAME))
else:
    data = "Hello, encrypted world!"
    write_encrypted(PASSWORD, FILENAME, data)
    print("wrote %s to %s" % (data, FILENAME))
```

---

## Technical Details

### Cryptographic Algorithms

The implementation follows recommendations from [Cryptographic Right Answers](http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html):

1. **Key Derivation**
   - PBKDF2 with SHA256
   - 256-bit random salt (increased from 128 bits in v3.0.0)
   - 100,000 iterations (increased from 10,000 in v4.0.0)
   - Generates two 256-bit keys

2. **Encryption**
   - AES256 in CTR (Counter) mode
   - First 64 bits of salt used as message nonce
   - Remaining 64 bits for counter increment

3. **Message Authentication**
   - SHA256 HMAC
   - Covers header, salt, and encrypted message
   - Validated before decryption

4. **Message Format**
   - 4-byte header: "sc" (ASCII) + 2 version bytes
   - 256-bit salt
   - Encrypted data
   - HMAC

### Security Level

- Designed to provide **128 bits of security**
- Protection against birthday collisions on 256-bit HMAC
- AES256 provides additional security against timing attacks

---

## Performance Considerations

### Intentional Slowness

Both encryption and decryption are relatively slow (can take a couple of seconds). This is **by design** for security:

- Makes password guessing attacks impractical
- Each password guess by an attacker also takes several seconds
- Prevents thousands of password attempts per second

> **Note**: This trade-off prioritizes security over speed. If performance is critical for your use case, consider alternatives.

---

## Project Structure

```
simple-crypt/
├── .git/                    # Git repository
├── src/
│   └── simplecrypt/        # Main package directory
│       ├── __init__.py     # Core implementation
│       ├── example-file.py # File encryption example
│       └── ...
├── .gitignore
├── MANIFEST.in
├── README.md               # Main documentation
├── README.txt
├── setup-27-env.sh         # Python 2.7 environment setup
├── setup-30-env.sh         # Python 3.0 environment setup
├── setup-33-env.sh         # Python 3.3 environment setup
└── setup.py                # Package configuration
```

---

## Running Examples

The project includes example scripts in `src/simplecrypt/`:

```bash
# Run the file encryption example
python src/simplecrypt/example-file.py
```

This example demonstrates a countdown program that encrypts/decrypts a file on each run.

---

## Version History

### Version 4.1 (Latest)
- Obscures random number generator output
- Guards against possible RNG compromise

### Version 4.0
- Increased PBKDF iterations to 100,000 (from 10,000)
- Slower but more secure against brute-force attacks
- Reference to python-aead alternative

### Version 3.0
- Increased salt size from 128 to 256 bits
- Better security against collision attacks

### Version 2.0
- Added Python 2.7 support
- Maintained full compatibility with 1.0

---

## Alternatives

For more advanced use cases, consider:

- **[python-aead](https://github.com/Ayrx/python-aead)**: For users who want more control (custom PBKDF rounds, explicit keys)
- **[keyczar](http://www.keyczar.org/)**: Google's cryptography toolkit (uses keystore instead of passwords)

---

## Important Warnings

### 1. Password-Based Encryption Limitations
Modern security practices favor keystore-based approaches (like Google's keyczar) over password-based encryption. However, keyczar doesn't support Python 3 at the time of this writing.

### 2. Password Storage in Memory
Passwords are stored in memory as Python strings, which means:
- Malicious code on the same machine could read passwords
- Passwords could be written to swap space
- **Mitigation**: Run crypto operations in a separate, short-lived process

### 3. Recognizable Headers
All encrypted messages start with a 4-byte header ("sc" + version):
- Adversaries can recognize encrypted data
- **Workaround**: Discard first 4 bytes (breaks version interoperability)

### 4. Memory Limitations
The current implementation:
- Requires entire message to fit in memory
- HMAC validation occurs after full decryption
- **Not suitable** for streaming large files
- Needs better solution for large data (block-level HMAC)

---

## Installation Issues

### Common Problems

**Issue**: `pycrypto` build fails
- **Cause**: Missing C compiler or Python development headers
- **Solution**: 
  - On Ubuntu/Debian: `sudo apt-get install python-dev`
  - On Windows: Install Visual C++ Build Tools
  - Consider using `pycryptodome` as alternative: `pip install pycryptodome`

**Issue**: Permission errors during installation
- **Solution**: Use `--user` flag: `pip install --user simple-crypt`

---

## Use Cases

Simple-crypt is ideal for:

- ✅ Encrypting configuration files
- ✅ Protecting small data files
- ✅ Storing encrypted credentials
- ✅ Simple password-based encryption needs
- ✅ Learning cryptography basics

Not recommended for:

- ❌ Large file encryption (memory constraints)
- ❌ Production systems requiring enterprise-grade crypto
- ❌ High-performance applications
- ❌ Streaming data encryption
- ❌ Key management systems

---

## Testing the Installation

After installation, verify it works:

```python
# Test script
from simplecrypt import encrypt, decrypt

password = "test123"
message = "Hello, Simple-Crypt!"

# Encrypt
ciphertext = encrypt(password, message)
print("Encrypted:", len(ciphertext), "bytes")

# Decrypt
plaintext = decrypt(password, ciphertext)
print("Decrypted:", plaintext.decode('utf8'))

# Verify
assert plaintext.decode('utf8') == message
print("✓ Test passed!")
```

---

## Development Setup

For contributors:

```bash
# Clone the repository
git clone https://github.com/andrewcooke/simple-crypt.git
cd simple-crypt

# Set up virtual environment (Python 3)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e .

# Install dependencies
pip install pycrypto
```

---

## Community & Support

- **Issues & Bugs**: [GitHub Issues](https://github.com/andrewcooke/simple-crypt/issues)
- **Discussions**: 
  - [Hacker News](http://news.ycombinator.com/item?id=4962983)
  - [Code Review StackExchange](http://codereview.stackexchange.com/questions/19910/)
  - [Crypto StackExchange](http://crypto.stackexchange.com/questions/5843/)

---

## License

Released into the **public domain** for any use, but with absolutely no warranty.

© 2012-2015 Andrew Cooke, 2013 d10n

---

## Conclusion

Simple-crypt provides a straightforward, secure way to encrypt and decrypt data in Python. While it has limitations (speed, memory usage), it's perfect for simple use cases where ease of use and security are priorities. For production systems or advanced requirements, consider more robust alternatives like python-aead or keyczar.

**Current Status**: ✅ Production/Stable (v4.1.7)

---

*Report generated on: December 10, 2025*
