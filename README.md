# Lapidarc signature verifier

Every Lapidarc Codex is a PDF delivered with a detached signature file
(`<name>.pdf.sig`). This repository lets anyone check, offline, that a Codex PDF is exactly
the file Lapidarc signed.

- Algorithm: **ML-DSA-65** (FIPS 204), via [liboqs](https://openquantumsafe.org/).
- What is signed: the exact bytes of the PDF file. Nothing is normalised,
  hashed first or re-encoded. Changing a single byte makes the signature fail.
- The `.sig` file is the raw 3309-byte ML-DSA-65 signature.

## Lapidarc public key

| File | Format |
|---|---|
| `lapidarc-public-key.bin` | raw ML-DSA-65 public key, 1952 bytes |
| `lapidarc-public-key.pem` | the same key as a PEM SubjectPublicKeyInfo (OID 2.16.840.1.101.3.4.3.18) |

**Fingerprint (SHA-256 of the 1952 raw key bytes):**

```
24a5dc448888bee7a97245ebc472f4d97e373562eff5a58967db8d16e6292601
```

SHA-256 of the `.pem` file itself:
`4ebb7913301481e8b90e63b71d05083cb62e9e41a537cd434c515bea236ce8e1`

Check it yourself:

```sh
sha256sum lapidarc-public-key.bin          # Linux
shasum -a 256 lapidarc-public-key.bin      # macOS
certutil -hashfile lapidarc-public-key.bin SHA256   # Windows
```

`verify.py` also prints the fingerprint of the key it used, so you can
compare it against the value above every time.

## Usage

```sh
python verify.py document.pdf document.pdf.sig
python verify.py document.pdf document.pdf.sig --key lapidarc-public-key.pem
```

`--key` defaults to `lapidarc-public-key.bin` next to `verify.py`, and
accepts a raw 1952-byte key, a DER SubjectPublicKeyInfo, or a PEM
`PUBLIC KEY` file.

| Exit code | Meaning |
|---|---|
| 0 | **VALID**: the PDF is exactly the file that was signed with this key |
| 1 | **INVALID**: the PDF was changed, or the signature or key does not belong to it |
| 2 | usage or input error (missing file, not an ML-DSA-65 public key, liboqs missing) |

## Install

Requirements: Python 3.9 or newer, and `liboqs-python==0.15.0`
(`requirements.txt`). It is a wrapper around the liboqs C library, which must
be the **same version (0.15.0)**. If liboqs-python cannot find liboqs when it
is first imported, it tries to download and build it itself; the steps below
install it explicitly instead, so verification can then run fully offline.

Tested on Linux (Ubuntu 22.04, Python 3.10, liboqs 0.15.0). The macOS and
Windows steps follow the liboqs and liboqs-python build instructions and have
not yet been tested by us.

### Linux

```sh
sudo apt install build-essential cmake git ninja-build libssl-dev   # Debian/Ubuntu
git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON \
      -DCMAKE_INSTALL_PREFIX="$HOME/.local/liboqs"
cmake --build liboqs/build && cmake --install liboqs/build
export OQS_INSTALL_PATH="$HOME/.local/liboqs"

python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

### macOS

```sh
xcode-select --install
brew install cmake ninja openssl@3
git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON \
      -DCMAKE_INSTALL_PREFIX="$HOME/.local/liboqs"
cmake --build liboqs/build && cmake --install liboqs/build
export OQS_INSTALL_PATH="$HOME/.local/liboqs"

python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

### Windows (PowerShell, Visual Studio Build Tools with C++ and CMake)

```powershell
git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs\build -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX="$env:LOCALAPPDATA\liboqs"
cmake --build liboqs\build --config Release
cmake --install liboqs\build --config Release
$env:OQS_INSTALL_PATH = "$env:LOCALAPPDATA\liboqs"
$env:PATH = "$env:LOCALAPPDATA\liboqs\bin;$env:PATH"

py -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Tests

```sh
python -m unittest discover -s tests -v
```

The tests generate a throwaway ML-DSA-65 keypair, sign a throwaway file, and
check valid, one-byte-modified, appended, wrong-key, modified-signature,
truncated-signature and bad-key cases. They need no network and no real
Lapidarc key.

## Security

See [SECURITY.md](SECURITY.md). Report issues to security@lapidarc.com.

## License

Apache License 2.0. See [LICENSE](LICENSE).
