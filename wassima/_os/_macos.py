from __future__ import annotations

import ctypes
from ctypes import POINTER, byref, c_void_p, c_ulong, c_char_p, c_int32, c_long
import ctypes.util

# Load Security framework
lib_security = ctypes.util.find_library("Security")
lib_corefoundation = ctypes.util.find_library("CoreFoundation")

if lib_security is None or lib_corefoundation is None:
    raise ImportError

security = ctypes.cdll.LoadLibrary(lib_security)
corefoundation = ctypes.cdll.LoadLibrary(lib_corefoundation)

# Basic constants and types (from macOS headers)
CFTypeRef = c_void_p
CFArrayRef = c_void_p
CFDataRef = c_void_p
CFStringRef = c_void_p

# Helper for CoreFoundation release
corefoundation.CFRelease.argtypes = [CFTypeRef]
corefoundation.CFRelease.restype = None


# Helper to convert CFDataRef to bytes
def cfdata_to_bytes(cfdata):
    if not cfdata:
        return b""
    corefoundation.CFDataGetLength.argtypes = [CFDataRef]
    corefoundation.CFDataGetLength.restype = c_ulong
    corefoundation.CFDataGetBytePtr.argtypes = [CFDataRef]
    corefoundation.CFDataGetBytePtr.restype = ctypes.POINTER(ctypes.c_ubyte)
    length = corefoundation.CFDataGetLength(cfdata)
    ptr = corefoundation.CFDataGetBytePtr(cfdata)
    if not ptr:
        return b""
    return ctypes.string_at(ptr, length)


# Helper to extract DER from SecCertificateRef
def sec_certificate_to_der(cert):
    # SecCertificateCopyData returns a retained CFDataRef containing the DER
    security.SecCertificateCopyData.argtypes = [c_void_p]
    security.SecCertificateCopyData.restype = CFDataRef
    cfdata = security.SecCertificateCopyData(cert)
    der = cfdata_to_bytes(cfdata)
    corefoundation.CFRelease(cfdata)
    return der


# Helper to extract DER from SecCertificateRef (list)
def sec_array_to_der_list(sec_array):
    # CFArrayGetCount, CFArrayGetValueAtIndex
    corefoundation.CFArrayGetCount.argtypes = [CFArrayRef]
    corefoundation.CFArrayGetCount.restype = c_long = ctypes.c_long
    count = corefoundation.CFArrayGetCount(sec_array)
    corefoundation.CFArrayGetValueAtIndex.argtypes = [CFArrayRef, c_long]
    corefoundation.CFArrayGetValueAtIndex.restype = c_void_p
    result = []
    for i in range(count):
        cert = corefoundation.CFArrayGetValueAtIndex(sec_array, i)
        der = sec_certificate_to_der(cert)
        result.append(der)
    return result


# Helper: create query dictionary
def create_query_dict(
    class_name: str, is_root: bool | None = None, is_issuer: bool | None = None
):
    # Use CoreFoundation to build a CFDictionary
    # Only relevant keys: kSecClass, kSecClassCertificate, kSecMatchLimit, kSecMatchLimitAll, kSecMatchTrustedOnly, etc.
    # See: /System/Library/Frameworks/Security.framework/Headers/SecItem.h
    # We'll use kSecClassCertificate, kSecMatchTrustedOnly, kSecMatchLimit, kSecMatchLimitAll, kSecMatchSubjectContains, kSecMatchIssuers, kSecReturnRef
    # For roots, we'll filter trusted and self-signed
    # Intermediates: trusted, not self-signed
    # For CRLs: kSecClassCertificateRevocationList (not widely documented, but present).

    # kSecClassCertificate
    kCFTypeDictionaryKeyCallBacks = ctypes.c_void_p.in_dll(
        corefoundation, "kCFTypeDictionaryKeyCallBacks"
    )
    kCFTypeDictionaryValueCallBacks = ctypes.c_void_p.in_dll(
        corefoundation, "kCFTypeDictionaryValueCallBacks"
    )

    # CFString constants
    def cfstr(val):
        corefoundation.CFStringCreateWithCString.argtypes = [
            c_void_p,
            c_char_p,
            c_int32,
        ]
        corefoundation.CFStringCreateWithCString.restype = CFStringRef
        return corefoundation.CFStringCreateWithCString(None, val.encode(), 0)

    # Predefined CFStrings
    kSecClass = cfstr("class")
    kSecClassCertificate = cfstr("cert")
    kSecClassCRL = cfstr("crl")
    kSecMatchLimit = cfstr("m_Limit")
    kSecMatchLimitAll = cfstr("a_LimitAll")
    kSecMatchTrustedOnly = cfstr("m_TrustedOnly")
    kSecReturnRef = cfstr("r_Ref")
    kSecMatchIsRoot = cfstr("m_IsRoot")
    kSecMatchIsIssuer = cfstr("m_IsIssuer")

    keys = []
    values = []

    if class_name == "cert":
        keys.extend([kSecClass, kSecMatchLimit, kSecMatchTrustedOnly, kSecReturnRef])
        values.extend(
            [
                kSecClassCertificate,
                kSecMatchLimitAll,
                ctypes.c_void_p(1),
                ctypes.c_void_p(1),
            ]
        )
        if is_root is not None:
            keys.append(kSecMatchIsRoot)
            values.append(ctypes.c_void_p(1 if is_root else 0))
        if is_issuer is not None:
            keys.append(kSecMatchIsIssuer)
            values.append(ctypes.c_void_p(1 if is_issuer else 0))
    elif class_name == "crl":
        keys.extend([kSecClass, kSecMatchLimit, kSecReturnRef])
        values.extend([kSecClassCRL, kSecMatchLimitAll, ctypes.c_void_p(1)])
    else:
        raise ValueError("Unknown class_name: %s" % class_name)

    # CFDictionaryCreate(CFAllocatorRef, const void **keys, const void **values, CFIndex numValues, ...)
    corefoundation.CFDictionaryCreate.argtypes = [
        c_void_p,
        POINTER(c_void_p),
        POINTER(c_void_p),
        c_long,
        c_void_p,
        c_void_p,
    ]
    corefoundation.CFDictionaryCreate.restype = c_void_p
    arrtype = c_void_p * len(keys)
    dct = corefoundation.CFDictionaryCreate(
        None,
        arrtype(*keys),
        arrtype(*values),
        len(keys),
        kCFTypeDictionaryKeyCallBacks,
        kCFTypeDictionaryValueCallBacks,
    )
    return dct


# Query certificates or CRLs
def secitem_copy_matching(query):
    # SecItemCopyMatching(CFDictionaryRef, CFTypeRef*)
    out = c_void_p()
    res = security.SecItemCopyMatching(query, byref(out))

    if res != 0:  # errSecSuccess
        corefoundation.CFRelease(query)
        raise OSError(f"SecItemCopyMatching failed: {res}")

    corefoundation.CFRelease(query)

    return out.value


def root_der_certificates() -> list[bytes]:
    """
    Returns a list of DER-encoded trusted root CA certificates (self-signed) from the system keychain.
    """
    query = create_query_dict("cert", is_issuer=True)
    result_array = secitem_copy_matching(query)

    if not result_array:
        return []

    ders = sec_array_to_der_list(result_array)

    corefoundation.CFRelease(result_array)

    return ders


def certificate_revocation_lists_der() -> list[bytes]:
    """
    Returns a list of DER-encoded CRLs from the system keychain.
    """
    query = create_query_dict("crl")

    result_array = secitem_copy_matching(query)

    # result_array is a CFArrayRef of SecCertificateRevocationListRef
    corefoundation.CFArrayGetCount.argtypes = [CFArrayRef]
    corefoundation.CFArrayGetCount.restype = c_long = ctypes.c_long

    count = corefoundation.CFArrayGetCount(result_array)

    corefoundation.CFArrayGetValueAtIndex.argtypes = [CFArrayRef, c_long]
    corefoundation.CFArrayGetValueAtIndex.restype = c_void_p

    # CRL objects can be converted to DER using SecCertificateRevocationListCopyData
    security.SecCertificateRevocationListCopyData.argtypes = [c_void_p]
    security.SecCertificateRevocationListCopyData.restype = CFDataRef

    crls = []

    for i in range(count):
        crl_ref = corefoundation.CFArrayGetValueAtIndex(result_array, i)
        crl_data = security.SecCertificateRevocationListCopyData(crl_ref)
        der = cfdata_to_bytes(crl_data)
        corefoundation.CFRelease(crl_data)
        crls.append(der)

    corefoundation.CFRelease(result_array)

    return crls


__all__ = (
    "root_der_certificates",
    "certificate_revocation_lists_der",
)
