from __future__ import annotations

from . import RUSTLS_LOADED, generate_ca_bundle

if __name__ == "__main__":
    bundle = generate_ca_bundle()

    if not bundle:
        import platform

        print("System is not supported")
        print("system: ", platform.system())
        print("uname: ", platform.uname())
        print("python: ", platform.python_version_tuple())
        print("implementation: ", platform.python_implementation())
        print("rustls loaded: ", RUSTLS_LOADED)

        exit(1)

    print(bundle)
