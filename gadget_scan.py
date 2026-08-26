#!/usr/bin/env python3
# Extract JOP/ROP gadgets from the Mi Box S kernel (kernel_elf) for building
# commit_creds(prepare_kernel_cred(0)). Uses capstone.
import sys, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

KERNEL = "F:/down/player6/update_miboxs_a12/boot.img.dump/kernel_elf"
OUT = "I:/云盘缓存/down/miboxs/RIPMaliUtgard/gadgets_kernel.txt"

def load_exec_sections(path):
    data = open(path,'rb').read()
    assert data[:4]==b'\x7fELF' and data[4]==2
    e_shoff=struct.unpack_from('<Q',data,0x28)[0]
    e_shentsize=struct.unpack_from('<H',data,0x3a)[0]
    e_shnum=struct.unpack_from('<H',data,0x3c)[0]
    secs=[]
    for i in range(e_shnum):
        o=e_shoff+i*e_shentsize
        sh_name,sh_type,sh_flags,sh_addr,sh_offset,sh_size,sh_link,sh_info,sh_addralign,sh_entsize=\
            struct.unpack_from('<IIQQQQIIQQ',data,o)
        secs.append((sh_addr,sh_offset,sh_size,sh_flags))
    exe=[]
    for va,off,size,flags in secs:
        if flags&0x4 and size>0:  # SHF_EXECINSTR
            exe.append((va,data[off:off+size]))
    return exe

md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
md.detail=True

from collections import deque, defaultdict
cats=defaultdict(list)   # category -> list of (addr, gadget_str)
def add(cat,addr,gstr):
    if len(cats[cat])<40:
        cats[cat].append((addr,gstr))

for va,blob in load_exec_sections(KERNEL):
    win=deque(maxlen=6)
    for ins in md.disasm(blob,va):
        win.append(ins)
        m=ins.mnemonic
        if m in ('ret','br','blr'):
            g=[(i.mnemonic,i.op_str) for i in win]
            gstr=' ; '.join(('%s %s'%(mm,oo)).strip() for mm,oo in g)
            ops=[o for _,o in g]
            fullm=[mm for mm,_ in g]
            # category 1: load reg from [x1...] then blr that reg  (JOP entry/link)
            if m=='blr':
                tgt=ins.op_str
                for j,i in enumerate(g):
                    if i[0]=='ldr' and ('['+tgt in i[1].replace(' ','') or (tgt+'，' in i[1]) ):
                        pass
                # simpler: if any ldr loads a reg whose name == blr target reg
                # detect: last is blr xN ; some earlier ldr xN,[...]
                for i in g:
                    if i[0]=='ldr' and i[1].split(',')[0].strip()==tgt:
                        add('ldr_then_blr_x',ins.address,gstr); break
            # category 2: mov x0 to 0 then ret
            if m=='ret':
                for i in g:
                    if (i[0]=='mov' and 'xzr' in i[1]) or (i[0]=='movz' and '#0' in i[1]):
                        if i[1].split(',')[0].strip() in ('x0','w0'):
                            add('set0_ret',ins.address,gstr); break
                # ldp x29,x30,[sp],#imm ; ret  (clean return)
                if any(i[0]=='ldp' and 'x29' in i[1] and 'x30' in i[1] for i in g):
                    add('ldp_ret',ins.address,gstr)
                # generic mov xA,xB ; ret  (register move)
                for i in g:
                    if i[0]=='mov' and m=='ret' and i[1].split(',')[0].strip() in ('x0','x1','x19','x20','x21','x22'):
                        add('mov_ret_%s'%i[1].split(',')[0].strip(),ins.address,gstr); break
                # add xA,xB,#imm ; ret
                for i in g:
                    if i[0]=='add' and m=='ret':
                        add('add_ret',ins.address,gstr); break

with open(OUT,'w') as f:
    f.write("Mi Box S kernel JOP gadget candidates (capstone)\n")
    for cat in sorted(cats):
        f.write("\n=== %s (%d) ===\n"%(cat,len(cats[cat])))
        for addr,gstr in cats[cat]:
            f.write("  %018x : %s\n"%(addr,gstr))

print("written", OUT)
for cat in sorted(cats):
    print("=== %s : %d samples ==="%(cat,len(cats[cat])))
    for addr,gstr in cats[cat][:6]:
        print("  %018x : %s"%(addr,gstr))
