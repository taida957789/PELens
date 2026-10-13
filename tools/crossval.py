"""Cross-validate pestudio-rs parsing against Python pefile (T9.2).

usage: python tools/crossval.py [count]
Builds the `summary` example, samples System32/SysWOW64 images and compares
section/import/delay-import/export/resource counts. pefile caps exports at 8192,
so larger export tables are reported as expected differences.
"""
import os, subprocess, sys, tempfile, glob
import pefile

count = int(sys.argv[1]) if len(sys.argv) > 1 else 250
files = sorted(glob.glob('C:/Windows/System32/*.dll') + glob.glob('C:/Windows/System32/*.exe') + glob.glob('C:/Windows/SysWOW64/*.dll'))
files = files[::max(1, len(files) // count)][:count]
lst = tempfile.NamedTemporaryFile('w', delete=False, suffix='.txt')
lst.write('\n'.join(files)); lst.close()
out = subprocess.run(['cargo', 'run', '-q', '--release', '-p', 'pe-parser', '--example', 'summary', '--', lst.name], capture_output=True, text=True).stdout
rs = {l.split('|')[0]: l.strip().split('|')[1:] for l in out.splitlines() if '|' in l}
bad = expected = 0
for p in files:
    try:
        pe = pefile.PE(p)
    except Exception:
        continue
    ni = sum(len(d.imports) for d in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []))
    nd = sum(len(d.imports) for d in getattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT', []))
    ne = len({s.ordinal for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.address}) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
    nr = 0
    for t in getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', None).entries if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else []:
        for n in (t.directory.entries if hasattr(t, 'directory') else []):
            nr += len(n.directory.entries) if hasattr(n, 'directory') else 1
    exp = [str(len(pe.sections)), str(ni), str(nd), str(ne), str(nr)]
    got = rs.get(p)
    if got is None or got[:5] != exp:
        if got and got[:3] == exp[:3] and int(got[3]) > 8192 >= int(exp[3]):
            expected += 1
            continue
        bad += 1
        print('MISMATCH', p, 'rust', got, 'pefile', exp)
print(f'checked {len(rs)} files, mismatches {bad}, expected pefile-cap differences {expected}')
os.unlink(lst.name)
