# AES Encryption and Decryption

This repository contains C code for encrypting and decrypting files using AES-128-CBC encryption algorithm.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Introduction

AES (Advanced Encryption Standard) is a symmetric encryption algorithm widely used to secure sensitive data. This project implements AES-128-CBC mode encryption and decryption in C programming language.

## Features

- Encryption of files using AES-128-CBC algorithm
- Decryption of AES-128-CBC encrypted files
- Automatic handling of padding for input files

## Prerequisites

Before running the code, ensure you have the following prerequisites installed:

- GCC compiler
- Linux environment (for file I/O operations)

## Installation

1. Clone the repository:

```
git clone https://github.com/halloweeks/aes-file-encrypt-decrypt.git
```

2. Compile the code:

```
cd aes-file-encrypt-decrypt
gcc encrypt.c -o encrypt -O2
gcc decrypt.c -o decrypt -O2
```

## Usage

### Encryption

To encrypt a file, run the following command:

```
./encrypt <input_file> <output_file>
```

Example:

```
./encrypt plaintext.txt ciphertext.enc
```

### Decryption

To decrypt an encrypted file, run the following command:

```
./decrypt <input_file> <output_file>
```

Example:

```
./decrypt ciphertext.enc decrypted.txt
```

## Contributing

Contributions are welcome! If you find any bugs or have suggestions for improvement, please open an issue or create a pull request.

## License

This project is licensed under the [MIT License](LICENSE).
