simple-quic
===========

A simple API for [QUIC](https://www.chromium.org/quic).

- Chromium commit: b25d2d936da7620ff44ce4a2952f38402efad685
- kku1993 [libquic fork](https://github.com/kku1993/libquic)

This repo is the successor to the
[simple-quic-legacy repo](https://github.com/kku1993/simple-quic-legacy).

The new repo is intended to fix the problem of the `simple-quic-legacy` repo
being too big because static libraries from `libquic` were committed in the
repo.

# How to Build
- Please initialize the repo first:
```
./init_repo.sh
```

- `libquicsock.so`
```
make
```

- `libquicsock.so` in debug mode (with assertions and detailed logging)
```
make clean_all
make debug
```

- Quicsock demo
```
make quicsock_server
make quicsock_client
```

- Quic toy server and client
```
make quic_server
make quic_client
```

- Your own C/C++ code. Note that you have to set `rpath` correctly. Otherwise,
  you need to set your `LD_LIBRARY_PATH` to include the directory where
  `libquicsock.so` is stored.
```
gcc -m64 -O3 -Wall -L. -Wl,-rpath=. -o foo foo.c -lquicsock
```

# External Dependencies
- `libglib2.0-dev`
- `openssl`
- `libevent-2.0.21`

# Why generate a Shared Library
The main reason of making `libquicsock` a shared library is because we currently
depend on both `OpenSSL` and `BoringSSL`.

If we try to link `OpenSSL` statically with `BoringSSL`, we get conflicting
symbols. On the other hand, if we dynamically link `OpenSSL` and just create a
static library with `BoringSSL`, then the parts of the library that uses
`OpenSSL` will not find the symbols they need.

Once we change the `libquic` source to remove dependency on `BoringSSL`, we can
make `libquicsock` a static library.

# Directory Layout
```
certs/            Utilities for certificate/private key generation
chromium/         Dependency source code from Chromium b25d2d9.
                    The directory structure mimics Chromium's so include paths
                    in Chromium sources can be left unmodified.
custom/           Custom code modified from Chromium or original code.
lib/              Contains submodules for libraries to be compiled (libquic).
quicsock/         Source code and headers for libquicsock.
server/           Code for server.
```

# Updating libquic
- To update `libquic`, just update the submodule under `lib/libquic`.
- Be sure to update `chromium` source code to ensure compatibility.

# OpenSSL Dependency
- We replace `boringssl` with `openssl`
- We use `libcrypto` from `boringssl`. In the future we would like to remove
  this dependency.

# TODO
- Use `-lcrypto` instead of `libcrypto.a` from `boringssl`. Currently we need
  both since some code in `libquic` relies on `libcrypto.a`.
