\# Cryptographic Encryption Vault



A Python-based file encryption and decryption utility that protects files using \*\*AES-256-GCM authenticated encryption\*\* and \*\*Scrypt-based key derivation\*\*.



\## Features



\- \*\*AES-256-GCM Encryption:\*\* Provides confidentiality and authenticated integrity.

\- \*\*Scrypt Key Derivation:\*\* Derives a 256-bit encryption key from a user-supplied passphrase.

\- \*\*Random Salt and Nonce:\*\* Generates unique cryptographic values for each encrypted file.

\- \*\*Directory Encryption:\*\* Recursively encrypts files while preserving folder structure.

\- \*\*Directory Decryption:\*\* Restores encrypted files to their original directory structure.

\- \*\*Tampering Detection:\*\* Rejects modified or corrupted encrypted files through authenticated decryption.

\- \*\*Wrong Password Protection:\*\* Prevents recovery of plaintext when an incorrect passphrase is supplied.

\- \*\*SHA-256 Logging:\*\* Records file hashes for verification and audit purposes.

\- \*\*Original File Preservation:\*\* Keeps source files unchanged during encryption.



\## Technologies Used



\- Python 3

\- Cryptography library

\- AES-256-GCM

\- Scrypt

\- SHA-256

\- PowerShell



\## Project Structure



```text

Cryptographic-Encryption-Vault/

│

├── src/

│   └── vault.py

│

├── screenshots/

│

├── requirements.txt

├── README.md

├── .gitignore

│

├── test\_data/       (local testing only; excluded from Git)

├── backups/         (reserved for future backup functionality)

└── logs/            (local logs; excluded from Git)

```



\## Installation



\### 1. Clone the repository



```bash

git clone https://github.com/YOUR\_USERNAME/Cryptographic-Encryption-Vault.git

cd Cryptographic-Encryption-Vault

```



\### 2. Create a virtual environment



```bash

python -m venv .venv

```



\### 3. Activate the environment



Windows PowerShell:



```powershell

.\\.venv\\Scripts\\Activate.ps1

```



\### 4. Install dependencies



```bash

pip install -r requirements.txt

```



\## Usage



Run commands from the project root directory.



\### Encrypt a directory



```bash

python src/vault.py encrypt test\_data/original test\_data/encrypted

```



Enter and confirm your master passphrase when prompted.



\### Decrypt a directory



```bash

python src/vault.py decrypt test\_data/encrypted test\_data/recovered

```



Enter the original master passphrase when prompted.



\## Cryptographic Implementation



| Component | Implementation |

|---|---|

| Encryption algorithm | AES-256-GCM |

| Key derivation | Scrypt |

| Derived key length | 256 bits |

| Salt length | 16 bytes |

| Nonce length | 12 bytes |

| Integrity verification | GCM authentication tag |

| Hash algorithm | SHA-256 |



Each encrypted file contains a format identifier, a randomly generated salt, a randomly generated nonce, and authenticated ciphertext.



\## Security Testing



The project includes tests for:



1\. Successful file encryption.

2\. Successful file decryption.

3\. Wrong-passphrase rejection.

4\. Tampering detection.

5\. Recovered-file verification using SHA-256 hashes.



\## Important Security Notes



\- Keep your master passphrase private and secure.

\- Losing the passphrase means encrypted files cannot be recovered by this application.

\- Never use a test passphrase for real confidential data.

\- This project does not currently implement automated key backup or recovery.

\- The application preserves original files; it does not securely erase them.



\## Project Status



\*\*Core encryption, decryption, and tampering-detection functionality implemented and tested.\*\*



\## Author



Dhanmeeswaran G.



Cybersecurity | Cryptography | Python Development



