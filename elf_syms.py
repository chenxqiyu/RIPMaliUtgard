#!/usr/bin/env python3
# Pure-stdlib ELF64 symbol-table extractor. No external deps.
# Usage: elf_syms.py <kernel_elf> [substring1 substring2 ...]
import sys, struct

def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: elf_syms.py <file> [substrings...]\n")
        sys.exit(1)
    path = sys.argv[1]
    targets = sys.argv[2:] or None
    with open(path, 'rb') as f:
        data = f.read()
    assert data[:4] == b'\x7fELF', "not an ELF file"
    assert data[4] == 2, "need ELF64 (EI_CLASS=2), got %d" % data[4]
    ei_data = data[5]  # 1 = little endian
    endian = '<' if ei_data == 1 else '>'
    e_shoff = struct.unpack_from(endian+'Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from(endian+'H', data, 0x3a)[0]
    e_shnum = struct.unpack_from(endian+'H', data, 0x3c)[0]
    e_shstrndx = struct.unpack_from(endian+'H', data, 0x3e)[0]
    e_type = struct.unpack_from(endian+'H', data, 0x10)[0]

    def sh(i):
        off = e_shoff + i*e_shentsize
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
         sh_link, sh_info, sh_addralign, sh_entsize) = struct.unpack_from(
            endian+'IIQQQQIIQQ', data, off)
        return dict(name=sh_name, type=sh_type, flags=sh_flags, addr=sh_addr,
                    offset=sh_offset, size=sh_size, link=sh_link, info=sh_info,
                    addralign=sh_addralign, entsize=sh_entsize)

    sections = [sh(i) for i in range(e_shnum)]
    symtab = next((s for s in sections if s['type'] == 2), None)  # SHT_SYMTAB
    if symtab is None:
        sys.stderr.write("no SYMTAB section found\n")
        sys.exit(1)
    strtab = sections[symtab['link']]
    strdata = data[strtab['offset']:strtab['offset']+strtab['size']]

    def getstr(off):
        end = strdata.find(b'\x00', off)
        return strdata[off:end].decode('latin-1')

    # Build section lookup for file-offset resolution of symbol virtual addrs.
    def file_offset_for_va(va):
        for s in sections:
            if s['addr'] and s['addr'] <= va < s['addr'] + s['size'] and s['offset']:
                return s['offset'] + (va - s['addr'])
        return None

    symentsize = 24  # ELF64 Sym
    n = symtab['size'] // symentsize
    results = []
    for i in range(n):
        base = symtab['offset'] + i*symentsize
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
            endian+'IBBHQQ', data, base)
        name = getstr(st_name) if st_name else ''
        if not name:
            continue
        if targets is None or any(t in name for t in targets):
            results.append((name, st_value, st_size, st_info, st_shndx))
    results.sort(key=lambda r: r[1])
    print("e_type=0x%x (2=EXEC,1=REL)  shnum=%d  symtab_syms=%d  matched=%d"
          % (e_type, e_shnum, n, len(results)))
    for name, val, sz, info, shndx in results:
        bind = (info >> 4) & 0xf
        typ = info & 0xf
        tname = {0:'NOT',1:'OBJ',2:'FUN',3:'SEC',4:'FILE',5:'COM',6:'TLS',10:'GNU_IFUNC'}.get(typ,'?')
        print("%018x  sz=%-5x  %s/%s  shndx=%-4d  %s" %
              (val, sz, {0:'LOC',1:'GLOB',2:'WEAK'}.get(bind,'?'), tname, shndx, name))
    # Optional: dump bytes of matched FUNC symbols for gadget analysis.
    if '--bytes' in targets:
        return
    if '--dump' in sys.argv:
        for name, val, sz, info, shndx in results:
            if (info & 0xf) in (1, 2, 10) and sz > 0:  # FUNC/OBJECT/GNU_IFUNC
                fo = file_offset_for_va(val)
                if fo is not None:
                    chunk = data[fo:fo+min(sz, 64)]
                    print("\n### %s @ %018x (sz=%d)" % (name, val, sz))
                    print(chunk.hex())

if __name__ == '__main__':
    main()
