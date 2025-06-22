from __future__ import annotations

import ctypes
from ctypes import POINTER, byref, c_int32, c_uint32, c_void_p

# Load frameworks
_core = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
_sec = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")

# Type aliases
CFTypeRef = c_void_p
CFArrayRef = c_void_p
CFDataRef = c_void_p
CFDictionaryRef = c_void_p
OSStatus = c_int32

# CoreFoundation function prototypes
_CFDictionaryCreate = _core.CFDictionaryCreate
_CFDictionaryCreate.argtypes = [c_void_p, POINTER(c_void_p), POINTER(c_void_p), c_uint32, c_void_p, c_void_p]
_CFDictionaryCreate.restype = CFDictionaryRef

_CFArrayGetCount = _core.CFArrayGetCount
_CFArrayGetCount.argtypes = [CFArrayRef]
_CFArrayGetCount.restype = c_uint32

_CFArrayGetValueAtIndex = _core.CFArrayGetValueAtIndex
_CFArrayGetValueAtIndex.argtypes = [CFArrayRef, c_uint32]
_CFArrayGetValueAtIndex.restype = CFTypeRef

_CFDataGetLength = _core.CFDataGetLength
_CFDataGetLength.argtypes = [CFDataRef]
_CFDataGetLength.restype = c_uint32

_CFDataGetBytePtr = _core.CFDataGetBytePtr
_CFDataGetBytePtr.argtypes = [CFDataRef]
_CFDataGetBytePtr.restype = ctypes.POINTER(ctypes.c_ubyte)

_CFRelease = _core.CFRelease
_CFRelease.argtypes = [c_void_p]
_CFRelease.restype = None

# Security function prototypes
_SecItemCopyMatching = _sec.SecItemCopyMatching
_SecItemCopyMatching.argtypes = [CFDictionaryRef, POINTER(CFTypeRef)]
_SecItemCopyMatching.restype = OSStatus

_SecCertificateCopyData = _sec.SecCertificateCopyData
_SecCertificateCopyData.argtypes = [CFTypeRef]
_SecCertificateCopyData.restype = CFDataRef

_SecTrustSettingsCopyCertificates = _sec.SecTrustSettingsCopyCertificates
_SecTrustSettingsCopyCertificates.argtypes = [c_int32, POINTER(CFArrayRef)]
_SecTrustSettingsCopyCertificates.restype = OSStatus

# CF callbacks & boolean constants
_kCFTypeDictKeyCallBacks = c_void_p.in_dll(_core, "kCFTypeDictionaryKeyCallBacks")
_kCFTypeDictValueCallBacks = c_void_p.in_dll(_core, "kCFTypeDictionaryValueCallBacks")
_kCFBooleanTrue = c_void_p.in_dll(_core, "kCFBooleanTrue")
_kSecBooleanTrue = _kCFBooleanTrue

# SecItem constants
_kSecClass = c_void_p.in_dll(_sec, "kSecClass")
_kSecClassCertificate = c_void_p.in_dll(_sec, "kSecClassCertificate")
_kSecMatchLimit = c_void_p.in_dll(_sec, "kSecMatchLimit")
_kSecMatchLimitAll = c_void_p.in_dll(_sec, "kSecMatchLimitAll")
_kSecMatchTrustedOnly = c_void_p.in_dll(_sec, "kSecMatchTrustedOnly")
_kSecReturnRef = c_void_p.in_dll(_sec, "kSecReturnRef")


# Helper: build a CFDictionary for SecItem queries
def _make_query(keys: list[c_void_p], values: list[c_void_p]) -> CFDictionaryRef:
    count = len(keys)
    KeyArr = (c_void_p * count)(*keys)
    ValArr = (c_void_p * count)(*values)
    return _CFDictionaryCreate(  # type: ignore[no-any-return]
        None,
        KeyArr,
        ValArr,
        count,
        _kCFTypeDictKeyCallBacks,
        _kCFTypeDictValueCallBacks,
    )


# Helper: perform SecItemCopyMatching and return CFTypeRef list


def _query_refs(query: CFDictionaryRef) -> list[CFTypeRef]:
    result = CFTypeRef()
    status = _SecItemCopyMatching(query, byref(result))

    if status != 0:
        raise OSError(f"SecItemCopyMatching failed with status={status}")  # Defensive: OOM?

    array_ref = CFArrayRef(result.value)
    count = _CFArrayGetCount(array_ref)
    items = [_CFArrayGetValueAtIndex(array_ref, i) for i in range(count)]
    # Note: No CFRelease() calls to avoid premature deallocation
    return items


# Convert CFDataRef to Python bytes
def _data_to_bytes(data_ref: c_void_p) -> bytes:
    length = _CFDataGetLength(data_ref)
    ptr = _CFDataGetBytePtr(data_ref)
    data = bytes(ctypes.string_at(ptr, length))
    _CFRelease(data_ref)
    return data


# Public: retrieve DER-encoded trusted certificates
def root_der_certificates() -> list[bytes]:
    """
    Returns a list of DER-encoded certificates trusted for TLS server auth,
    covering system roots, admin, user trust settings, and personal CAs.
    """
    certificates: list[bytes] = []

    # 1) System/user/admin trust settings
    for domain in (0, 1, 2):
        cert_array = CFArrayRef()
        status = _SecTrustSettingsCopyCertificates(domain, byref(cert_array))
        if status == 0:
            count = _CFArrayGetCount(cert_array)
            for i in range(count):
                cert_ref = _CFArrayGetValueAtIndex(cert_array, i)
                certificates.append(_data_to_bytes(_SecCertificateCopyData(cert_ref)))

    # 2) Personal CA certificates from keychain marked trusted
    query = _make_query(
        keys=[_kSecClass, _kSecMatchLimit, _kSecMatchTrustedOnly, _kSecReturnRef],
        values=[_kSecClassCertificate, _kSecMatchLimitAll, _kSecBooleanTrue, _kSecReturnRef],
    )

    try:
        cert_refs = _query_refs(query)
        for c in cert_refs:
            certificates.append(_data_to_bytes(_SecCertificateCopyData(c)))
    except OSError:  # Defensive: OOM?
        pass

    return certificates
