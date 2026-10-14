"""Build the local seed corpora for `cargo fuzz` (fuzz/corpus/<target>/).

Seeds come from PE files on this machine and are never committed (fuzz/.gitignore).
usage: python tools/fuzz_seeds.py [extra.exe ...]
needs: pip install pefile
"""
import glob
import hashlib
import os
import sys

import pefile

ROOT = os.path.join(os.path.dirname(__file__), '..', 'fuzz', 'corpus')
SYS = os.path.join(os.environ.get('WINDIR', r'C:\Windows'), 'System32')
FILES = [os.path.join(SYS, n) for n in ('notepad.exe', 'calc.exe', 'kernel32.dll', 'user32.dll', 'shell32.dll',
                                         'mscoree.dll', 'drivers\\null.sys', 'cmd.exe', 'regedit.exe')]
FILES += glob.glob(os.path.join(os.environ.get('WINDIR', r'C:\Windows'), 'Microsoft.NET', 'Framework64', 'v4*', 'System.dll'))[:1]
FILES += sys.argv[1:]
MAX = 1 << 20  # libFuzzer works best with small inputs


def put(target, data):
    if not data or len(data) > MAX:
        return
    d = os.path.join(ROOT, target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, hashlib.sha1(data).hexdigest()), 'wb') as f:
        f.write(data)


def resources(pe):
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        return
    for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for n in getattr(t, 'directory', None) and t.directory.entries or []:
            for lang in getattr(n, 'directory', None) and n.directory.entries or []:
                ds = lang.data.struct
                yield t.id, pe.get_data(ds.OffsetToData, ds.Size)


for path in FILES:
    if not os.path.isfile(path):
        continue
    raw = open(path, 'rb').read()
    put('parse_pe', raw)
    put('analyze', raw)
    try:
        pe = pefile.PE(data=raw)
    except pefile.PEFormatError:
        continue
    sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    if sec.Size:
        put('certificate', raw[sec.VirtualAddress + 8:sec.VirtualAddress + sec.Size])
    kept = {}
    for rtype, blob in resources(pe):
        # a few of each type: version (16), manifest (24), dialog (5), menu (4), string (6), message (11), group icon (14)
        if rtype in (4, 5, 6, 11, 12, 14, 16, 24) and kept.get(rtype, 0) < 3:
            kept[rtype] = kept.get(rtype, 0) + 1
            put('resources', blob)
for name in ('parse_pe', 'certificate', 'dotnet', 'resources', 'analyze'):
    d = os.path.join(ROOT, name)
    print(name, len(os.listdir(d)) if os.path.isdir(d) else 0)
