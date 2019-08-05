#File Encryption software with Authenticated Encryption and Key Management.

Encrypts and Decrypts files using AES_GCM mode with 256 bit keys for Authenticated Encryption.
Encrypts the keyfile using ChaCha20-Poly1305 with 256 bit keys derived from PBKDF2 for Authenticated Encryption.

Multiple keys can be stored securely using the keyring(.kring files), which automatically manage keys.
Multiple keyfiles can be used on a single system, to specify a particular keyfile for the current session, using the *config.json files.
There are two types of config file: temporary and home, the home file is stored at ~/area_confi.json, the temporary ones are to be used ad hoc.

For installation, usage and FAQs look at the project wiki at <a href="www.github.com/rehanvipin/area-42/wiki>Wiki</a>.

You are free to use to code in the repository as allowed by the LICENSE.
