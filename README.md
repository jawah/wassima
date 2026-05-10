<h1 align="center">Wassima 🔒</h1>

<p align="center">
<small>I named this library after my wife, whom I trust the most. ❤️</small>
</p>

<p align="center">
  <a href="https://pypi.org/project/wassima">
    <img src="https://img.shields.io/pypi/pyversions/wassima.svg?orange=blue" />
  </a>
  <a href="https://pepy.tech/project/wassima/">
    <img alt="Download Count Total" src="https://static.pepy.tech/badge/wassima/month" />
  </a>
</p>

This project offers you a great alternative to the MPL licensed **certifi**.

This project allows you to access your original operating system trust store, thus
helping you to verify the remote peer certificates. It automatically fallback to an
embedded trust store generated from the CCADB trusted source.

It works as-is out-of-the-box for any operating systems out there.
Available on PyPy and Python 3.7+

## ✨ Installation

Using pip:

```sh
pip install wassima -U
```

### Get started

*A)* Create a SSLContext

```python
import wassima

ctx = wassima.create_default_ssl_context()
# ... The context magically contain your system root CAs, the rest is up to you!
```

*B)* Retrieve individually root CAs in a binary form (DER)

```python
import wassima

certs = wassima.root_der_certificates()
# ... It contains a list of certificate represented in bytes
```

*C)* Retrieve individually root CAs in a string form (PEM)

```python
import wassima

certs = wassima.root_pem_certificates()
# ... It contains a list of certificate represented in string
```

*D)* Retrieve a single bundle (concatenated) list of PEM certificates like *certifi* does

```python
import wassima

bundle = wassima.generate_ca_bundle()
# ... It contains a string with all of your root CAs!
# It is not a path but the file content itself.
```

*E) Register your own CA in addition to the system's*

```python
import wassima

# register CA only accept string PEM (one at a time!)
wassima.register_ca(open("./myrootca.pem", "r").read())
bundle = wassima.generate_ca_bundle()
# ... It contains a string with all of your root CAs, PLUS your own 'myrootca.pem'.
# It is not a path but the file content itself.
```

*F) Use a hybrid trust store (OS + embedded CCADB bundle)*

```python
import wassima

# By default, only your OS trust store is used (with the embedded CCADB
# bundle as a fallback when the OS exposes nothing). Pass `hybrid_store=True`
# to force concatenating the embedded CCADB bundle in addition to the OS
# trust store. Useful in containers or appliances that ship with a slim or
# outdated system trust store.
ctx = wassima.create_default_ssl_context(hybrid_store=True)

# Available on every public top-level entry point:
wassima.root_der_certificates(hybrid_store=True)
wassima.root_pem_certificates(hybrid_store=True)
wassima.generate_ca_bundle(hybrid_store=True)
```

On Linux/BSD, when the system trust store has not been updated for at least
3 years, `hybrid_store=True` is implicitly applied so that the result is
never silently outdated.

The output of `root_der_certificates()` (and the upper helpers built on top
of it) is always deduplicated: a given DER certificate is guaranteed to
appear at most once in the resulting list, regardless of how many OS stores
or directories it lives in.

### ⏱️ Cache invalidation

For performance reasons the result of `root_der_certificates()` /
`root_pem_certificates()` is cached. By default, the cache automatically
expires every 12 hours so that any change to the OS trust store (e.g. a CA
rotated overnight by your IT department) is picked up without having to
restart the process.

You can override the TTL at runtime, pass `0` to disable caching entirely:

```python
import wassima

# Force a refresh every hour:
wassima.set_cache_ttl(3600)

# Disable caching (every call recomputes):
wassima.set_cache_ttl(0)

# Restore the default (12 hours):
wassima.set_cache_ttl(wassima.DEFAULT_CACHE_TTL_SECONDS)
```

Setting a new TTL invalidates any pending cached result immediately.
