"""Deterministic app globe assets, Python standard library only."""
from pathlib import Path
import math, struct, zlib
ROOT = Path(__file__).resolve().parents[1] / "desktop/src-tauri/icons"
def png(n):
    raw=bytearray()
    for y in range(n):
        raw.append(0)
        for x in range(n):
            u=(x+.5)/n;v=(y+.5)/n
            dx=u-.46;dy=v-.46;r=math.hypot(dx,dy)
            c=(236,246,241,255)
            edge=math.hypot(max(abs(u-.5)-.30,0),max(abs(v-.5)-.30,0))
            if edge>.18:c=(0,0,0,0)
            globe=abs(r-.30)<.014
            meridian=abs((dx/.14)**2+(dy/.30)**2-1)<.13
            lat=r<.30 and min(abs(dy),abs(dy-.135),abs(dy+.135))<.010
            if globe or meridian or lat:c=(24,122,108,255)
            badge=math.hypot(u-.76,v-.76)
            if badge<.117:c=(250,253,251,255)
            if badge<.089:c=(28,158,112,255)
            raw.extend(c)
    def chunk(t,b):return struct.pack('>I',len(b))+t+b+struct.pack('>I',zlib.crc32(t+b)&0xffffffff)
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',n,n,8,6,0,0,0))+chunk(b'IDAT',zlib.compress(bytes(raw),9))+chunk(b'IEND',b'')
ROOT.mkdir(exist_ok=True)
(ROOT/'icon.png').write_bytes(png(256))
images=[(n,png(n)) for n in [32,64,256]]
header=struct.pack('<HHH',0,1,len(images));offset=6+16*len(images);entries=bytearray();payload=bytearray()
for n,data in images:
    entries.extend(struct.pack('<BBBBHHII',0 if n==256 else n,0 if n==256 else n,0,0,1,32,len(data),offset));payload.extend(data);offset+=len(data)
(ROOT/'icon.ico').write_bytes(header+entries+payload)
