# HIBPDL++

**Fast, multi-threaded downloader for _';--have i been pwned?_ password hashes**

This software retrieves all available SHA1 password hashes provided by the [haveibeenpwned.com](https://haveibeenpwned.com/) API. It converts them into a binary format so that each hash merely allocates 20 bytes (plus 4 bytes for a number that states how many times the hash was found in leaked password/hash lists).

## Prerequisites

- Git
- OpenSSL libraries ≥ 1.1.1t

### Windows

Install OpenSSL:

```
winget install OpenSSL
winget install Ninja-build.Ninja
```

If you don't want to use the Ninja build tool, you can omit its installation, but must then replace `Ninja` with `"NMake Makefiles"` in the `cmake` command below.

### macOS

```
brew install openssl git cmake ninja
```

### Linux (Ubuntu)

```
sudo apt install libssl3 git cmake ninja-build
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
cmake -G Ninja -DOPENSSL_ROOT_DIR="C:\Program Files\OpenSSL-Win64" ..
cmake --build . --config Release
```

## Usage

See `hibpdl --help`.

## License

See [LICENSE](LICENSE).

## Copyright

Copyright (c) 2023 Oliver Lau
