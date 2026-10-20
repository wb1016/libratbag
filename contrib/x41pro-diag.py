#!/usr/bin/env python3
"""
X-41 Pro diagnostic: report descriptor + query sweep (v2).

Phase 1  dumps each node's HID report descriptor (fixes the size-field issue)
         -> real report IDs + which node is the config interface (vendor 0xffa0).
Phase 2  sweeps the query using the *discovered* report IDs across addresses
         and prints every non-zero response.

Run as root:
    sudo python3 contrib/x41pro-diag.py
"""

import os
import sys
import glob
import time
import fcntl
import struct

USB_VID = "36b7"
USB_PID = "fd15"
HID_MAX_DESCRIPTOR_SIZE = 4096


def _IOC(d, t, n, s):
    return (d << 30) | (t << 8) | n | (s << 16)


HIDIOCGRDESC = _IOC(2, 0x48, 0x01, 4 + HID_MAX_DESCRIPTOR_SIZE)
HIDIOCSFEATURE = lambda n: _IOC(3, 0x48, 0x06, n)
HIDIOCGFEATURE = lambda n: _IOC(3, 0x48, 0x07, n)


def usb_ids(real):
    p = real
    for _ in range(12):
        iv = os.path.join(p, "idVendor")
        ip = os.path.join(p, "idProduct")
        if os.path.exists(iv) and os.path.exists(ip):
            return open(iv).read().strip(), open(ip).read().strip()
        p = os.path.dirname(p)
    return None, None


def find_nodes():
    out = []
    for dev in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        name = os.path.basename(dev)
        real = os.path.realpath(dev + "/device")
        vid, pid = usb_ids(real)
        if vid == USB_VID and pid == USB_PID:
            out.append((name, "/dev/" + name))
    return out


def parse_rdesc(desc):
    repids, pages = [], []
    i = 0
    while i < len(desc):
        b = desc[i]
        if b == 0xFE:
            i += 3 + desc[i + 1]
            continue
        size = {0: 0, 1: 1, 2: 2, 3: 4}[b & 0x03]
        typ = (b >> 2) & 0x03
        tag = (b >> 4) & 0x0F
        val = int.from_bytes(desc[i + 1:i + 1 + size], "little") if size else 0
        if typ == 1:  # global
            if tag == 0:
                pages.append(val)
            if tag == 8:
                repids.append(val)
        i += 1 + size
    return repids, pages


def dump_rdesc(fd, name):
    buf = bytearray(4 + HID_MAX_DESCRIPTOR_SIZE)
    struct.pack_into("<I", buf, 0, HID_MAX_DESCRIPTOR_SIZE)  # set capacity
    try:
        fcntl.ioctl(fd, HIDIOCGRDESC, buf)
    except OSError as e:
        print("  %s: HIDIOCGRDESC failed: %s" % (name, e))
        return [], []
    size = struct.unpack("<I", bytes(buf[:4]))[0]
    desc = bytes(buf[4:4 + size])
    repids, pages = parse_rdesc(desc)
    vpages = sorted({p for p in pages if p >= 0xFF00})
    print("  %s: %d-byte descriptor" % (name, size))
    print("     report IDs : %s" % ([hex(x) for x in repids] or "(none = unnumbered)"))
    print("     usage pages: %s%s" % (
        [hex(p) for p in sorted(set(pages))],
        "   <-- VENDOR 0x%x" % vpages[0] if vpages else ""))
    return repids, vpages


def query(fd, send_id, resp_id, addr, b1=0xf2):
    req = bytearray(16)
    req[0] = send_id
    req[1] = b1
    req[2] = addr & 0xFF
    req[3] = (addr >> 8) & 0xFF
    req[4] = 0x04
    try:
        fcntl.ioctl(fd, HIDIOCSFEATURE(16), req)
    except OSError:
        return None
    time.sleep(0.008)
    resp = bytearray(64)
    resp[0] = resp_id
    try:
        fcntl.ioctl(fd, HIDIOCGFEATURE(64), resp)
    except OSError:
        return None
    return bytes(resp)


def sweep(fd, name, repids):
    ids = repids if repids else [0x00, 0x01, 0x02, 0x03]
    print("\n--- query sweep on %s (report IDs %s) ---" % (name, [hex(x) for x in ids]))
    found = 0
    for sid in ids:
        for rid in ids:
            for addr in range(0x00, 0x300, 4):
                r = query(fd, sid, rid, addr)
                if r is not None and any(r[1:]):
                    print("    SEND=0x%02x RESP=0x%02x addr 0x%03x: %s" % (sid, rid, addr, r[:24].hex()))
                    found += 1
                    if found > 30:
                        print("    ...(truncated)")
                        return True
    if not found:
        print("    no non-zero data for any report-ID pair.")
    return found > 0


def main():
    if os.geteuid() != 0:
        print("ERROR: run as root (sudo %s)" % sys.argv[0])
        return 1
    nodes = find_nodes()
    if not nodes:
        print("ERROR: no hidraw node for %s:%s" % (USB_VID, USB_PID))
        return 1

    print("=== Phase 1: report descriptors ===")
    info = {}
    for name, devnode in nodes:
        try:
            fd = os.open(devnode, os.O_RDWR | os.O_NONBLOCK)
        except OSError as e:
            print("  %s: open failed %s" % (name, e))
            continue
        repids, vpages = dump_rdesc(fd, name)
        info[name] = (fd, repids, bool(vpages))

    print("\n=== Phase 2: query sweep (discovered report IDs) ===")
    # prefer vendor-page (config) node
    order = [n for n, (_, _, v) in info.items() if v] + [n for n in info if not info[n][2]]
    hit = False
    for name in order:
        fd, repids, _ = info[name]
        if sweep(fd, name, repids):
            hit = True
            break

    if not hit:
        print("\nAll empty -> query framing is wrong. Next: capture RDCfg.exe")
        print("traffic (wine + ioctl shim, or usbmon) to get the true framing.")

    for fd, _, _ in info.values():
        try:
            os.close(fd)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
