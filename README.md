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

This project offers you a great alternative to **certifi**. It is a simple yet efficient wrapper
around MIT licensed **rustls-native-certs**.

This project allows you to access your original operating system trust store, thus
helping you to verify the remote peer certificates.

It works as-is out-of-the-box for MacOS, Windows, and Linux. Automatically fallback on Certifi otherwise.
Available on PyPy and Python 3.7+

If your particular operating system is not supported, we will make this happen! Open
an issue on the repository.

For now, it is not supported to call your OS certificate verify native function.
Use your Python native capabilities for it.

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

*C) Register your own CA in addition to the system's*

```python
import wassima

wassima.register_ca(open("./myrootca.pem", "r").read())
bundle = wassima.generate_ca_bundle()
# ... It contains a string with all of your root CAs, PLUS your own 'myrootca.pem'.
# It is not a path but the file content itself.
```
