#!/usr/bin/env python3
"""BioShock 1 ConfigINI.IBF extractor/repacker.
Xbox 360: UTF-16BE names and big-endian int32 payload lengths.
PC: UTF-16LE names and little-endian int32 payload lengths.
"""
from __future__ import annotations
import argparse, hashlib, json, struct, sys
from io import BytesIO
from pathlib import Path

MAGIC = "bioshock-ibf-manifest-v1"
MAX_NAME_UNITS = 255
MAX_PAYLOAD = 0x7fffffff

def sha256(b): return hashlib.sha256(b).hexdigest()
def read_exact(f, n):
    b=f.read(n)
    if len(b)!=n: raise ValueError(f"truncated archive: expected {n} bytes, got {len(b)}")
    return b

def safe_name(name):
    if not name or name in {'.','..'} or '\x00' in name or '/' in name or '\\' in name:
        raise ValueError(f"unsafe/non-flat filename: {name!r}")
    return name

def parse_bytes(raw, order):
    enc = 'utf-16-be' if order=='big' else 'utf-16-le'
    fmt = '>i' if order=='big' else '<i'
    f=BytesIO(raw); entries=[]; i=0
    while True:
        pos=f.tell(); x=f.read(1)
        if not x: break
        units=x[0]
        if units==0:
            if f.read(1): raise ValueError(f"trailing data after terminator at 0x{pos:x}")
            break
        if units>MAX_NAME_UNITS: raise ValueError(f"entry {i}: invalid filename length {units}")
        rawname=read_exact(f, units*2)
        try: decoded=rawname.decode(enc)
        except UnicodeDecodeError as e: raise ValueError(f"entry {i}: invalid filename encoding") from e
        if not decoded.endswith('\x00'): raise ValueError(f"entry {i}: missing filename NUL")
        name=safe_name(decoded[:-1])
        size=struct.unpack(fmt,read_exact(f,4))[0]
        if size<0 or size>MAX_PAYLOAD: raise ValueError(f"entry {i} {name!r}: invalid payload size {size}")
        data=read_exact(f,size)
        entries.append({'name':name,'data':data,'offset':pos}); i+=1
    if not entries: raise ValueError('archive contains no entries')
    names=[x['name'].casefold() for x in entries]
    if len(names)!=len(set(names)): raise ValueError('duplicate filenames')
    return entries

def parse_archive(path, byteorder='auto'):
    raw=Path(path).read_bytes()
    orders=[byteorder] if byteorder!='auto' else ['big','little']
    err=None
    for o in orders:
        try: return parse_bytes(raw,o)
        except ValueError as e: err=e
    raise err

def extract(archive,outdir,force=False,byteorder='auto'):
    entries=parse_archive(archive,byteorder)
    outdir=Path(outdir)
    if outdir.exists() and any(outdir.iterdir()) and not force: raise ValueError(f'output directory is not empty: {outdir} (use --force)')
    outdir.mkdir(parents=True,exist_ok=True)
    # Auto is resolved from the actual archive, but the manifest can be changed
    # by the user only deliberately; default pack is Xbox 360 big-endian.
    if byteorder != 'auto':
        resolved = byteorder
    else:
        try:
            parse_bytes(Path(archive).read_bytes(), 'big')
            resolved = 'big'
        except ValueError:
            resolved = 'little'
    manifest={'format':MAGIC,'byteorder':resolved,'entries':[]}
    for e in entries:
        (outdir/e['name']).write_bytes(e['data'])
        manifest['entries'].append({'name':e['name'],'size':len(e['data']),'sha256':sha256(e['data'])})
    (outdir/'ibf_manifest.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(f'Extracted {len(entries)} entries to {outdir} ({resolved}-endian)')

def pack(indir,output,allow_extra=False,terminator=False,byteorder='big'):
    indir=Path(indir); m=json.loads((indir/'ibf_manifest.json').read_text(encoding='utf-8'))
    if m.get('format')!=MAGIC: raise ValueError('unsupported or invalid manifest')
    entries=m.get('entries');
    if not isinstance(entries,list) or not entries: raise ValueError('manifest has no entries')
    names=[e.get('name') for e in entries]
    if len(set(n.casefold() for n in names))!=len(names): raise ValueError('manifest has duplicate filenames')
    files={p.name:p for p in indir.iterdir() if p.is_file() and p.name!='ibf_manifest.json'}
    missing=[n for n in names if n not in files]; extra=sorted(set(files)-set(names))
    if missing: raise ValueError('missing extracted files: '+', '.join(missing))
    if extra and not allow_extra: raise ValueError('unexpected files (use --allow-extra): '+', '.join(extra))
    enc='utf-16-be' if byteorder=='big' else 'utf-16-le'; fmt='>i' if byteorder=='big' else '<i'
    tmp=Path(output).with_name(Path(output).name+'.tmp')
    with tmp.open('wb') as f:
        for n in names:
            n=safe_name(n); encoded=(n+'\x00').encode(enc); units=len(encoded)//2
            if units>MAX_NAME_UNITS: raise ValueError(f'filename too long: {n!r}')
            data=files[n].read_bytes()
            if len(data)>MAX_PAYLOAD: raise ValueError(f'file too large: {n}')
            f.write(bytes([units])); f.write(encoded); f.write(struct.pack(fmt,len(data))); f.write(data)
        if terminator: f.write(b'\x00')
    tmp.replace(output)
    print(f'Packed {len(names)} entries into {output} ({Path(output).stat().st_size} bytes, {byteorder}-endian)')

def verify(archive,byteorder='auto'):
    e=parse_archive(archive,byteorder); print(f'OK: {archive} — {len(e)} entries')
    for i,x in enumerate(e): print(f"{i:4d} {x['name']:<32} {len(x['data']):>9} bytes  {sha256(x['data'])}")

def main():
    ap=argparse.ArgumentParser(description='BioShock 1 Xbox 360 IBF extractor/repacker')
    sp=ap.add_subparsers(dest='cmd',required=True)
    p=sp.add_parser('extract'); p.add_argument('archive',type=Path); p.add_argument('outdir',type=Path); p.add_argument('--force',action='store_true'); p.add_argument('--byteorder',choices=['auto','little','big'],default='auto')
    p=sp.add_parser('pack'); p.add_argument('indir',type=Path); p.add_argument('output',type=Path); p.add_argument('--allow-extra',action='store_true'); p.add_argument('--terminator',action='store_true'); p.add_argument('--byteorder',choices=['little','big'],default='big',help='big is Xbox 360; little is PC')
    p=sp.add_parser('verify'); p.add_argument('archive',type=Path); p.add_argument('--byteorder',choices=['auto','little','big'],default='auto')
    a=ap.parse_args()
    try:
        if a.cmd=='extract': extract(a.archive,a.outdir,a.force,a.byteorder)
        elif a.cmd=='pack': pack(a.indir,a.output,a.allow_extra,a.terminator,a.byteorder)
        else: verify(a.archive,a.byteorder)
    except (OSError,ValueError,json.JSONDecodeError) as e: print('ERROR:',e,file=sys.stderr); return 2
    return 0
if __name__=='__main__': raise SystemExit(main())
