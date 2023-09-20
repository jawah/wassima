from __future__ import annotations

from . import generate_ca_bundle

if __name__ == "__main__":
    bundle = generate_ca_bundle()

    if not bundle:
        import platform

        print("System is not supported")
        print("system: ", platform.system())
        print("uname: ", platform.uname())
        print("python: ", platform.python_version_tuple())
        print("implementation: ", platform.python_implementation())

        exit(1)

    print(bundle)
