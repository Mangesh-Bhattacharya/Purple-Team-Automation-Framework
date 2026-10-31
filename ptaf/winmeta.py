"""Windows PE version-resource metadata (OriginalFileName and friends), read with ctypes only.

Why this exists: running PTAF's rule checker over the 3,161 public SigmaHQ rules showed that one
field, ``OriginalFileName``, was the ONLY thing blocking 527 of the 1,383 process-creation rules
(38%). It comes from the executable's embedded version resource, the same place Sysmon reads it,
and it is what defeats the classic "rename the binary" evasion: ``cmd.exe`` copied to ``notes.txt.exe``
still reports ``OriginalFileName: Cmd.Exe``.

No third-party packages are used. On any non-Windows platform every function returns an empty dict,
so callers never need to branch. Results are cached per path because reading a file's version block
costs a disk read, and a process-creation sensor sees the same few thousand images repeatedly.
"""

from __future__ import annotations

import sys
from functools import lru_cache

#: version-resource string name -> the Sigma/Sysmon field name rules use
FIELD_MAP = {
    "OriginalFilename": "OriginalFileName",
    "FileDescription": "Description",
    "ProductName": "Product",
    "CompanyName": "Company",
    "FileVersion": "FileVersion",
}
#: the fields this module can supply (used by the rule-compatibility check)
FIELDS = frozenset(FIELD_MAP.values())


def clean_original_file_name(name: str) -> str:
    """Strip the ``.MUI`` suffix Windows adds for language-resource binaries.

    On current Windows the string tables of many system binaries live in separate ``.mui`` files, and
    the API then reports ``Cmd.Exe.MUI`` for ``cmd.exe``. Sysmon and every Sigma rule expect
    ``Cmd.Exe``. (Found by CI on a real Windows runner: the unrenamed binary and its renamed copy
    disagreed.)
    """
    return name[:-4] if name.lower().endswith(".mui") else name


@lru_cache(maxsize=4096)
def version_info(path: str) -> dict[str, str]:
    """``{"OriginalFileName": ..., "Description": ..., ...}`` for an executable, or ``{}``.

    Never raises: a missing file, a binary without a version resource, or an access error all give
    an empty dict, which simply means those rule fields will not match (reported, not guessed).
    """
    if sys.platform != "win32" or not path:
        return {}
    try:
        import ctypes
        from ctypes import wintypes

        ver = ctypes.WinDLL("version", use_last_error=True)
        ver.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
        ver.GetFileVersionInfoSizeW.restype = wintypes.DWORD
        ver.GetFileVersionInfoW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        ]  # fmt: skip
        ver.GetFileVersionInfoW.restype = wintypes.BOOL
        ver.VerQueryValueW.argtypes = [
            ctypes.c_void_p, wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT),
        ]  # fmt: skip
        ver.VerQueryValueW.restype = wintypes.BOOL

        size = ver.GetFileVersionInfoSizeW(path, None)
        if not size:
            return {}
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(path, 0, size, buf):
            return {}

        ptr, length = ctypes.c_void_p(), wintypes.UINT()
        translations = [(0x0409, 0x04B0), (0x0409, 0x0000)]  # US English, Unicode / neutral
        if ver.VerQueryValueW(
            buf, "\\VarFileInfo\\Translation", ctypes.byref(ptr), ctypes.byref(length)
        ):
            words = ctypes.cast(ptr, ctypes.POINTER(wintypes.WORD))
            found = [(words[i], words[i + 1]) for i in range(0, length.value // 2 - 1, 2)]
            translations = found + translations

        out: dict[str, str] = {}
        for lang, codepage in translations:
            for key, name in FIELD_MAP.items():
                if name in out:
                    continue
                block = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\{key}"
                if (
                    ver.VerQueryValueW(buf, block, ctypes.byref(ptr), ctypes.byref(length))
                    and length.value
                ):
                    text = ctypes.wstring_at(ptr.value, length.value).rstrip("\x00").strip()
                    if text:
                        out[name] = (
                            clean_original_file_name(text) if name == "OriginalFileName" else text
                        )
            if len(out) == len(FIELD_MAP):
                break
        return out
    except Exception:  # noqa: BLE001 - metadata is best effort; the sensor must never fail on it
        return {}
