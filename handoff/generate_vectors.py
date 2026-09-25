#!/usr/bin/env python3
"""Independent stdlib-only encoder for WP3 wire vectors."""
import hashlib, json, pathlib, sys

def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24,n])
    if n < 65536: return bytes([major << 5 | 25])+n.to_bytes(2,'big')
    if n < 2**32: return bytes([major << 5 | 26])+n.to_bytes(4,'big')
    return bytes([major << 5 | 27])+n.to_bytes(8,'big')
def cb(v):
    if isinstance(v,int): return head(0,v)
    if isinstance(v,bytes): return head(2,len(v))+v
    if isinstance(v,str):
        b=v.encode();return head(3,len(b))+b
    if isinstance(v,list): return head(4,len(v))+b''.join(map(cb,v))
    if v is None:return b'\xf6'
    raise TypeError(type(v))
def digest(v):return hashlib.sha256(cb(v)).digest()
def rep(x):return bytes([x])*32
pre,cand=rep(0xe7),rep(0xca)
ctx=['UNICITY_HANDOFF_CONTEXT',2,3,7,0,10,1,b'\x00',pre,cand]
body=[2,3,8,10,[['stake-a','root-a',b'\x02'+bytes([1])*32,1]],1,rep(0x5a),rep(0x77),pre]
bid=digest(body)
summary,parent=rep(0x11),rep(0x22)
fid=digest(['UNICITY_HANDOFF_FROZEN',bid,summary,parent,cand,0,pre])
freeze=['UNICITY_HANDOFF_FREEZE',2,cb(ctx),bid,summary,parent,fid]
tr=rep(0x33)
record=['UNICITY_ORDERED_HANDOFF_RECORD',1,3,7,pre,0,'commit',6,[fid,bid,10,tr]]
cid=digest(record)
commit=['UNICITY_HANDOFF_COMMIT',2,fid,bid,6,10,tr,cid]
ack=['UNICITY_HANDOFF_ACK',2,fid,cid,parent,parent,tr,41]
genesis=['UNICITY_EPOCH_GENESIS',1,3,8,bid,10,cid,6,rep(0x44),rep(0x55),fid,tr]
vectors={k:cb(v).hex() for k,v in [('context',ctx),('freeze',freeze),('commit',commit),('ack',ack),('epoch_genesis',genesis)]}
vectors['genesis_id']=digest(genesis).hex()
p=pathlib.Path(__file__).parent/'testdata/wire.json'
out=json.dumps(vectors,indent=2,sort_keys=True)+'\n'
if '--check' in sys.argv:
    if p.read_text()!=out:raise SystemExit('vectors differ')
else:p.write_text(out)
