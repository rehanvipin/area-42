# File Encryption software with Authenticated Encryption(AEAD) and Key Management.

## Encrypts and Decrypts files using GCM, with AES-256 as block-cipher, for Authenticated Encryption.
## Encrypts the keyring using ChaCha20-Poly1305 with 256 bit keys derived from PBKDF2 for Authenticated Encryption.

### Encrypt files at your own risk, if you lose your keys AND your original file, they will be irrecoverable!</h3>
Multiple keys can be stored securely using the keyring(.kring files), which automatically manage keys.

Multiple keyrings can be used on a single system. To specify a particular keyfile for the current session, use the config.json files.

There are two types of config file: temporary and home, the home file is stored at ~/area_confi.json, the temporary ones are to be used ad hoc.

For installation, usage and FAQs look at the project wiki: [Wiki](https://github.com/rehanvipin/area-42/wiki)

Please read the short license before using the software [LICENSE](https://github.com/rehanvipin/area-42/blob/master/LICENSE.md).

All bugs and requests can be reported under the issues column [Issues](https://github.com/rehanvipin/area-42/issues).
