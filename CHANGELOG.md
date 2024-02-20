# Changelog

All notable changes to wassima will be documented in this file. This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## 1.1.0 (2024-02-20)

## Changed
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
