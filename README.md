<h1>File Encryption software with Authenticated Encryption and Key Management.

<h2>Encrypts and Decrypts files using AES_GCM mode with 256 bit keys for Authenticated Encryption.
<h2>Encrypts the keyfile using ChaCha20-Poly1305 with 256 bit keys derived from PBKDF2 for Authenticated Encryption.

<h3>Encrypt files at your own risk, if you lose your keys and your original file, they will be irrecoverable!</h3>
Multiple keys can be stored securely using the keyring(.kring files), which automatically manage keys.
Multiple keyfiles can be used on a single system, to specify a particular keyfile for the current session, using the *config.json files.
There are two types of config file: temporary and home, the home file is stored at ~/area_confi.json, the temporary ones are to be used ad hoc.

For installation, usage and FAQs look at the project wiki.

You are free to use to code in the repository as allowed by the LICENSE.
