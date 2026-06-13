`casmd5` is a small C library for calculating MD5 hashes.

It provides a simple context-based interface for hashing data all at once or incrementally in chunks.

> **Note:** MD5 is not recommended for cryptographic security, password hashing, digital signatures, or collision-resistant integrity checks. Use it only for compatibility, checksums, fingerprints, or other non-security-critical purposes.

## Features

- Small and simple C implementation
- Context-based hashing API
- Supports incremental hashing
- Produces standard 16-byte MD5 digests
- Easy to include in C projects

## Installation

Clone the repository:

```sh
git clone https://github.com/caspianrz/casmd5.git
cd casmd5
mkdir build
cd build
cmake ..
make
```

Build the library using your preferred build system or compiler setup.

## Usage

Include the public header in your C source file:

```c
#include "casmd5.h"
```

For full API documentation, see the project wiki: [Public API](https://github.com/caspianrz/casmd5/wiki/Public-API)
