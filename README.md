# File Encryption and Decryption Program

This C program enables encryption and decryption of files and directories using AES-256-CBC encryption. The key for encryption/decryption is derived from a password using SHA-256 hashing. The program also removes the original file after encryption and the encrypted file after decryption.

## Features

- Encrypt and decrypt individual files.
- Encrypt and decrypt all files within a directory.
- Remove the original file after encryption.
- Remove the encrypted file after decryption.
- Key derived from user-provided password using SHA-256.

## Getting Started

### Prerequisites

- **OpenSSL** library: This program uses OpenSSL for encryption and decryption. Ensure you have OpenSSL installed on your system.

### Compilation

To compile the program, use the following command:

```sh
gcc -o encrypt_decrypt_f_d encrypt_decrypt_f_d.c -lssl -lcrypto
./encrypt_decrypt_f_d
