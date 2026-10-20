#!/usr/bin/env python3
"""
Dump the E-YOOSO X-41 Pro button config records (QuerySingleButton).

Issues the vendor feature-report query the Windows tool uses to read a button's
config, for each of the 11 button slots in profile 0, and dumps the raw 64-byte
responses. Since we know each slot's physical button + default action, the
record layout falls straight out of the raw bytes.

QuerySingleButton (recovered from RDCfg.exe):
  send (16 B):  02 F2 <addr:u16> 04 00 ...
  sleep 10 ms
  get  (64 B):  report id 0x03 (or 0x02) -> raw button config record
  addr = table[profile] + 0x42 + button*4
  table = {64, 256, 432, 608, 784}  (5 profiles)

Run as root:
    sudo python3 contrib/x41pro-dumpconfig.py

Output is printed and saved to /tmp/opencode/x41-config-dump.json.
"""

import os
import sys
import glob
import time
import json
import fcntl

USB_VID = "36b7"
USB_PID = "fd15"
OUT_PATH = "/tmp/opencode/x41-config-dump.json"

PROFILE_TABLE = [64, 256, 432, 608, 784]   # 5 profiles
NUM_BUTTONS = 11
PROFILE = 0

# report-id schemes to try for the response read
RESP_IDS = [0x03, 0x02, 0x00]


def _IOC(dir_, type_, nr, size):
    return (dir_ << 30) | (type_ << 8) | nr | (size << 16)


def HIDIOCSFEATURE(length):
    return _IOC(3, 0x48, 0x06, length)


def HIDIOCGFEATURE(length):
    return _IOC(3, 0x48, 0x07, length)


def usb_ids_for(realpath):
    p = realpath
    for _ in range(12):
        iv = os.path.join(p, "idVendor")
        ip = os.path.join(p, "idProduct")
        if os.path.exists(iv) and os.path.exists(ip):
            try:
                with open(iv) as f:
                    vid = f.read().strip()
                with open(ip) as f:
                    pid = f.read().strip()
                return vid, pid
            except OSError:
                return None, None
        parent = os.path.dirname(p)
        if parent == p:
            break
        p = parent
    return None, None


def find_hidraw_nodes():
    found = []
    for dev in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        name = os.path.basename(dev)
        real = os.path.realpath(os.path.join(dev, "device"))
        vid, pid = usb_ids_for(real)
        if vid == USB_VID and pid == USB_PID:
            found.append((name, "/dev/" + name))
    return found


def query_button(fd, resp_id, addr):
    req = bytearray(16)
    req[0] = 0x02          # report id (command)
    req[1] = 0xf2          # family = query
    req[2] = addr & 0xff   # addr lo
    req[3] = (addr >> 8) & 0xff  # addr hi
    req[4] = 0x04
    try:
        fcntl.ioctl(fd, HIDIOCSFEATURE(16), req)
    except OSError:
        return None
    time.sleep(0.01)
    resp = bytearray(64)
    resp[0] = resp_id
    try:
        fcntl.ioctl(fd, HIDIOCGFEATURE(64), resp)
    except OSError:
        return None
    return bytes(resp)


def main():
    if os.geteuid() != 0:
        print("ERROR: run as root (sudo %s)" % sys.argv[0])
        return 1

    nodes = find_hidraw_nodes()
    if not nodes:
        print("ERROR: no hidraw node for USB %s:%s" % (USB_VID, USB_PID))
        return 1
    print("hidraw node(s): " + ", ".join(n for n, _ in nodes))

    results = {"profile": PROFILE, "nodes": [n for n, _ in nodes], "buttons": {}}

    for name, devnode in nodes:
        try:
            fd = os.open(devnode, os.O_RDWR | os.O_NONBLOCK)
        except OSError as e:
            print("  skip %s: %s" % (devnode, e))
            continue

        print("\n=== node %s (%s) ===" % (name, devnode))
        node_res = {}
        for btn in range(NUM_BUTTONS):
            addr = PROFILE_TABLE[PROFILE] + 0x42 + btn * 4
            # try response report ids until we get plausible data
            got = None
            used_id = None
            for rid in RESP_IDS:
                r = query_button(fd, rid, addr)
                if r is not None and any(r[1:]):
                    got = r
                    used_id = rid
                    break
            if got is None:
                # still record whatever came back (even if mostly zero)
                got = query_button(fd, RESP_IDS[0], addr)
                used_id = RESP_IDS[0]
            if got is None:
                print("  btn %2d addr=0x%02x: <query failed>" % (btn, addr))
                continue
            hexs = got.hex()
            print("  btn %2d addr=0x%02x [resp id=0x%02x]: %s" % (btn, addr, used_id, hexs))
            node_res[str(btn)] = {"addr": hex(addr), "resp_id": used_id, "raw": hexs}

        if node_res:
            results["buttons"][name] = node_res
        os.close(fd)

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w") as f:
        json.dump(results, f, indent=2)
    print("\nSaved to %s" % OUT_PATH)
    print("Paste the output (or JSON) back for record-layout analysis.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
