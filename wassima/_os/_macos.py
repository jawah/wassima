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
# Alias for SecItem boolean
_kSecBooleanTrue = _kCFBooleanTrue

# SecItem constants
_kSecClass = c_void_p.in_dll(_sec, "kSecClass")
_kSecClassCertificate = c_void_p.in_dll(_sec, "kSecClassCertificate")
try:
    _kSecClassCertificateRevocationList = c_void_p.in_dll(_sec, "kSecClassCertificateRevocationList")
except ValueError:
    _kSecClassCertificateRevocationList = _core.CFStringCreateWithCString(
        None, b"kSecClassCertificateRevocationList", 0x08000100
    )
_kSecMatchLimit = c_void_p.in_dll(_sec, "kSecMatchLimit")
_kSecMatchLimitAll = c_void_p.in_dll(_sec, "kSecMatchLimitAll")
_kSecMatchTrustedOnly = c_void_p.in_dll(_sec, "kSecMatchTrustedOnly")
_kSecReturnRef = c_void_p.in_dll(_sec, "kSecReturnRef")
_kSecReturnData = c_void_p.in_dll(_sec, "kSecReturnData")


# Helper: build a CFDictionary for SecItem queries
def _make_query(keys, values):
    count = len(keys)
    KeyArr = (c_void_p * count)(*keys)
    ValArr = (c_void_p * count)(*values)
    return _CFDictionaryCreate(None, KeyArr, ValArr, count, _kCFTypeDictKeyCallBacks, _kCFTypeDictValueCallBacks)


# Helper: perform SecItemCopyMatching and return CFTypeRef list
def _query_refs(query):
    result = CFTypeRef()
    status = _SecItemCopyMatching(query, byref(result))
    if status != 0:
        raise OSError(status, "SecItemCopyMatching failed")
    arr = CFArrayRef(result.value)
    cnt = _CFArrayGetCount(arr)
    return [_CFArrayGetValueAtIndex(arr, i) for i in range(cnt)]


# Helper: convert CFDataRef to Python bytes
def _data_to_bytes(data_ref):
    length = _CFDataGetLength(data_ref)
    ptr = _CFDataGetBytePtr(data_ref)
    return bytes(ctypes.string_at(ptr, length))


# Public: retrieve DER-encoded trusted certificates


def root_der_certificates() -> list[bytes]:
    """
    Returns a list of DER-encoded certificates trusted for TLS server auth,
    including system roots and any user/admin trust settings.
    """
    ders = []
    # Iterate trust domains: 0 = system, 1 = user, 2 = admin
    for domain in (0, 1, 2):
        cert_array = CFArrayRef()
        status = _SecTrustSettingsCopyCertificates(domain, byref(cert_array))
        if status != 0:
            continue
        count = _CFArrayGetCount(cert_array)
        for i in range(count):
            cert_ref = _CFArrayGetValueAtIndex(cert_array, i)
            ders.append(_data_to_bytes(_SecCertificateCopyData(cert_ref)))
    return ders


# Public: retrieve DER-encoded CRLs


def certificate_revocation_lists_der() -> list[bytes]:
    """
    Returns all CRLs found in system and user keychains, in DER.
    """
    query = _make_query(
        keys=[_kSecClass, _kSecMatchLimit, _kSecReturnData],
        values=[_kSecClassCertificateRevocationList, _kSecMatchLimitAll, _kSecBooleanTrue],
    )
    try:
        data_refs = _query_refs(query)
        return [_data_to_bytes(d) for d in data_refs]
    except OSError:
        return []
