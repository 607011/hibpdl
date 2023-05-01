# HIBPDL++

**Fast, multi-threaded downloader for _';--have i been pwned?_ password hashes**

**HIBPDL++** retrieves all available SHA1 password hashes accessible through the [haveibeenpwned.com](https://haveibeenpwned.com/) API. It converts them into a binary format so that each hash allocates 20 bytes (plus 4 bytes for a number (big-endian) that states how many times the hash was found in leaked password/hash lists).

## Prerequisites

- Git
- CMake ≥ 3.16
- OpenSSL libraries ≥ 1.1.1t

### Windows

```
winget install Git.Git
winget install Kitware.CMake
winget install ShiningLight.OpenSSL
```

### macOS

```
brew install openssl git cmake ninja
```

### Linux (Ubuntu)

```
sudo apt install libssl3 libssl-dev git cmake ninja-build
```

## Build

### macOS

```bash
git clone https://github.com/607011/hibpdl.git hibpdl++
mkdir -p hibpdl++/build
cd hibpdl++/build
git submodule init
git submodule update
cmake -DCMAKE_BUILD_TYPE=Release -G Ninja -DOPENSSL_ROOT_DIR=/opt/homebrew/Cellar/openssl@3/3.1.0 ..
cmake --build .
strip hibpdl
```

### Linux (Ubuntu)

```bash
git clone https://github.com/607011/hibpdl.git hibpdl++
mkdir -p hibpdl++/build
cd hibpdl++/build
git submodule init
git submodule update
cmake -DCMAKE_BUILD_TYPE=Release -G Ninja ..
cmake --build .
strip hibpdl
```

### Windows 11

In Visual Studio Developer Command Prompt:

```bash
git clone https://github.com/607011/hibpdl.git hibpdl++
cd hibpdl++
md build
cd build
git submodule init
git submodule update
cmake -DOPENSSL_ROOT_DIR="C:\Program Files\OpenSSL-Win64" ..
cmake --build . --config Release
```

## Usage

See `hibpdl --help`.

## License

See [LICENSE](LICENSE).

## Copyright

Copyright (c) 2023 Oliver Lau
