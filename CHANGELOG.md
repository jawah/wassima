# Changelog

All notable changes to wassima will be documented in this file. This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## 2.0.0 (2025-06-22)

### Removed
- Constant `RUSTLS_LOADED`.
- Native Rust extension in favor of a pure Python solution.
- Optional dependency on Certifi.
- Running `python -m wassima` to debug platform support.

### Added
- Integrated CA bundle to fallback on when no "official" trust store can be loaded.
  A single module shipped along with that library is now a derivative work of CCADB work
  licensed under Community Data License Agreement - Permissive - Version 2.0. It is not
  like copyleft MPL, therefor is compatible with our main MIT license.

### Changed
- Top level functions like `generate_ca_bundle` now integrate intermediate CA on Windows and MacOS.
  You are responsible for trusting the bundle knowing that fact. It will no longer contain only trust anchors.
  On Python defaults, OpenSSL will rebuild the chain and ensure the trust anchors (e.g. root CA/self-signed) is
  there and valid. Passing VERIFY_PARTIAL_CHAIN will shortcircuit that insurance. (#16)

## 1.2.2 (2025-03-07)

### Added
- Support for PyPy 3.11

### Changed
- pyo3 updated from 0.23.4 to 0.23.5

## 1.2.1 (2025-01-20)

### Changed
- No longer fallback on certifi for Windows x86 CPython.

## 1.2.0 (2025-01-12)

### Changed
- pyo3 updated from 0.23.3 to 0.23.4
- rustls-native-certs updated from 0.7 to 0.8

## 1.1.6 (2024-12-26)

### Changed
- pyo3 updated from 0.22.5 to 0.23.3

### Fixed
- Clippy warnings in our Rust code.

### Added
- Initial support for Python 3.13 freethreaded experimental build.

## 1.1.5 (2024-10-27)

### Changed
- pyo3 updated from 0.20.3 to 0.22.5

## 1.1.4 (2024-10-20)

### Changed
- Harmonized requirements in project metadata whether you fetch the pure Python wheel or not. (#8)

## 1.1.3 (2024-10-09)

### Changed
- Bumped `rustls-native-certs` to version 0.7.3

### Added
- Automatic (fallback) installation of `certifi` if native trust store access isn't supported on your platform.
- Ensure `certifi` fallback bundle is loaded even if stored inside a zip-like file.

## 1.1.2 (2024-08-17)

### Changed
- Bumped `rustls-native-certs` to version 0.7.1

### Added
- Explicit support for Python 3.13

## 1.1.1 (2024-04-29)

### Changed
- Bumped `pyo3` to version 0.20.3

### Fixed
- Certifi fallback loading
- Exception if the underlying rust library could not access the OS store

## 1.1.0 (2024-02-20)

### Changed
- Bumped `pyo3` to version 0.20.2
- Bumped `rustls-native-certs` to version 0.7.0
- Bumped `maturin` to version 1.4.0

## 1.0.3 (2023-11-11)

### Added
- Function `register_ca` so that user may register their own custom CA (PEM, and DER accepted) in addition to the system trust store.

### Fixed
- Overrule `SSL_CERT_FILE` environment variable so that system CA is always returned.

### Changed
- Function `create_default_ssl_context` now instantiate an `SSLContext` with the Mozilla Recommended Cipher Suite, instead of your system default.
- Bumped `pyo3` to version 0.20.0

## 1.0.1 (2023-09-26)

### Added
- Expose `__version__`.
- Support for `certifi` fallback if you did not pick up a compatible wheel. Expose constant `RUSTLS_LOADED` as a witness.

## 1.0.0 (2023-09-20)

### Added
- Public functions `root_der_certificates`, `root_pem_certificates`, `generate_ca_bundle`, and `create_default_ssl_context`.
