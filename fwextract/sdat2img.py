#!/usr/bin/env python3
# sdat2img for Android block-image transfer lists (handles 'new'/'zero').
# Outputs a raw ext4 image that can be opened with 7z.
import sys, os

def sdat2img(transfer_list, new_dat, out_img):
    with open(transfer_list, 'r') as f:
        lines = f.read().splitlines()
    version = int(lines[0])
    total_blocks = int(lines[1])
    # version>=2 has 4 header lines: version, total, stash_max, stash_needed
    start = 4 if version >= 2 else 2
    with open(new_dat, 'rb') as f:
        data = f.read()
    bs = 4096
    out = open(out_img, 'wb')
    out.truncate(total_blocks * bs)
    off = 0
    for i in range(start, len(lines)):
        line = lines[i].strip()
        if not line:
            continue
        parts0 = line.split()
        cmd = parts0[0]
        rest = parts0[1].split(',') if len(parts0) > 1 else []
        if cmd == 'new':
            count = int(rest[0])
            blocks = [int(x) for x in rest[1:1 + count]]
            for b in blocks:
                out.seek(b * bs)
                out.write(data[off:off + bs])
                off += bs
        elif cmd == 'zero':
            count = int(rest[0])
            blocks = [int(x) for x in rest[1:1 + count]]
            for b in blocks:
                out.seek(b * bs)
                out.write(b'\x00' * bs)
        else:
            # erase / copy / move -> ignored for full OTA extraction
            pass
    out.close()
    print(f"[*] image size = {total_blocks*bs} bytes ({total_blocks} blocks)")
    print(f"[*] data consumed from new_dat = {off} / {len(data)} bytes")
    # ext4 superblock magic 0xEF53 at offset 0x438
    with open(out_img, 'rb') as f:
        f.seek(0x438)
        magic = f.read(2)
    print(f"[*] ext4 magic @0x438 = {magic.hex()} (want '53ef')")

if __name__ == '__main__':
    base = r'F:\down\player6\update_miboxs_a12'
    tl = os.path.join(base, 'vendor.transfer.list')
    dat = os.path.join(base, 'vendor.new.dat')
    out = sys.argv[1] if len(sys.argv) > 1 else r'I:\云盘缓存\down\miboxs\RIPMaliUtgard\fwextract\vendor.img'
    os.makedirs(os.path.dirname(out), exist_ok=True)
    sdat2img(tl, dat, out)
