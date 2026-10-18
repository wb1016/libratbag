#!/usr/bin/env python3
"""
Interactive button/input-report calibration for the E-YOOSO X-41 Pro.

Prompts you to press each physical control one at a time and captures the raw
HID *input reports* the mouse emits. From those we recover:
  - the input report byte layout (which byte/bit = buttons, wheel, ...)
  - the physical-button -> HID button-bit numbering
  - wheel up/down and DPI button encoding

Run as root (hidraw nodes are root-only):

    sudo python3 contrib/x41pro-calibrate.py

Then press ENTER at each prompt and do the requested action once
(press + release; for the wheel, one notch of scroll).

Output is printed and saved to /tmp/opencode/x41-calibration.json.
"""

import os
import sys
import glob
import time
import json
import select

USB_VID = "36b7"
USB_PID = "fd15"
OUT_PATH = "/tmp/opencode/x41-calibration.json"

# Ordered calibration script: (key, prompt shown to the user)
CONTROLS = [
    ("left_click",   "LEFT click (press + release the left button)"),
    ("right_click",  "RIGHT click (press + release the right button)"),
    ("wheel_click",  "WHEEL click (press the wheel / middle button)"),
    ("wheel_up",     "WHEEL UP (scroll the wheel UP one notch)"),
    ("wheel_down",   "WHEEL DOWN (scroll the wheel DOWN one notch)"),
    ("dpi_up",       "DPI UP button"),
    ("dpi_down",     "DPI DOWN button"),
    ("double_click", "DOUBLE-CLICK button"),
    ("prev",         "PREV / Back button"),
    ("next",         "NEXT / Forward button"),
    ("macro1",       "MACRO 1 button"),
    ("macro2",       "MACRO 2 button"),
    ("macro3",       "MACRO 3 button"),
]


def usb_ids_for(realpath):
    """Walk up from a hidraw sysfs device looking for idVendor/idProduct."""
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
    """Return [(name, /dev/hidrawN)] for every hidraw node of our USB device."""
    found = []
    for dev in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        name = os.path.basename(dev)
        real = os.path.realpath(os.path.join(dev, "device"))
        vid, pid = usb_ids_for(real)
        if vid == USB_VID and pid == USB_PID:
            found.append((name, "/dev/" + name))
    return found


def open_nonblock(path):
    return os.open(path, os.O_RDONLY | os.O_NONBLOCK)


def drain(fds, duration):
    """Read and discard reports for `duration` seconds (returns count)."""
    end = time.time() + duration
    n = 0
    while time.time() < end:
        r, _, _ = select.select(fds, [], [], 0.05)
        for fd in r:
            try:
                if os.read(fd, 64):
                    n += 1
            except BlockingIOError:
                pass
    return n


def capture(fds, max_wait=20.0, settle=0.6):
    """
    Capture reports until activity is seen and then the line goes quiet.
    Returns (all_reports, per_fd_map). Reports are raw bytes.
    """
    reports = []
    saw_activity = False
    last_activity = time.time()
    end = time.time() + max_wait

    while time.time() < end:
        r, _, _ = select.select(fds, [], [], 0.1)
        now = time.time()
        for fd in r:
            try:
                data = os.read(fd, 64)
            except BlockingIOError:
                continue
            if not data:
                continue
            reports.append((fd, data))
            saw_activity = True
            last_activity = now
        if saw_activity and (now - last_activity) >= settle:
            break

    return reports


def byte_diff(a, b):
    """Return list of (index, a_byte, b_byte) where the two reports differ."""
    diffs = []
    for i in range(max(len(a), len(b))):
        av = a[i] if i < len(a) else None
        bv = b[i] if i < len(b) else None
        if av != bv:
            diffs.append((i, av, bv))
    return diffs


def pick_idle(fds):
    """Establish an idle baseline report (most common report while untouched)."""
    print("\n[baseline] Do NOT touch the mouse for 1 second...")
    counts = {}
    end = time.time() + 1.0
    while time.time() < end:
        r, _, _ = select.select(fds, [], [], 0.1)
        for fd in r:
            try:
                data = os.read(fd, 64)
            except BlockingIOError:
                continue
            if data:
                counts[data] = counts.get(data, 0) + 1
    if not counts:
        return None
    # most common report = idle
    return max(counts.items(), key=lambda kv: kv[1])[0]


def main():
    if os.geteuid() != 0:
        print("ERROR: must run as root to read /dev/hidraw* (try: sudo %s)" % sys.argv[0])
        return 1

    nodes = find_hidraw_nodes()
    if not nodes:
        print("ERROR: no /dev/hidraw* node found for USB %s:%s." % (USB_VID, USB_PID))
        print("       Is the mouse plugged in? Check with: lsusb | grep -i %s" % USB_VID)
        return 1

    print("Found X-41 Pro hidraw node(s): " + ", ".join(n for n, _ in nodes))
    fds = []
    for name, devnode in nodes:
        try:
            fd = open_nonblock(devnode)
            fds.append(fd)
            print("  opened %s (fd %d)" % (devnode, fd))
        except OSError as e:
            print("  could not open %s: %s" % (devnode, e))
    if not fds:
        return 1

    idle = pick_idle(fds)
    if idle is None:
        print("WARNING: no idle reports captured; diffs will be less useful.")
        idle = b""
    print("Idle baseline (%d bytes): %s" % (len(idle), idle.hex()))

    results = {"idle": idle.hex(), "nodes": [n for n, _ in nodes], "controls": {}}

    for key, prompt in CONTROLS:
        print("\n-----------------------------------------------------------")
        input("Press ENTER, then: %s\n(then return here)..." % prompt)
        drain(fds, 0.3)  # clear stale reports
        reps = capture(fds)
        if not reps:
            print("  !! no reports captured for %s" % key)
            results["controls"][key] = {"reports": [], "diffs": []}
            continue

        rep_hex = [d.hex() for _, d in reps]
        # Compute diffs vs idle for the distinct reports
        distinct = []
        for _, d in reps:
            if d not in distinct:
                distinct.append(d)
        diffs = [byte_diff(idle, d) for d in distinct]

        results["controls"][key] = {
            "reports": rep_hex,
            "distinct": [d.hex() for d in distinct],
            "diffs_vs_idle": [
                [[i, av, bv] for (i, av, bv) in dd] for dd in diffs
            ],
        }

        print("  captured %d report(s), %d distinct:" % (len(reps), len(distinct)))
        for d in distinct:
            print("    %s" % d.hex())
        for d in distinct:
            dd = byte_diff(idle, d)
            if dd:
                pretty = " ".join("[%d]:%s->%s" % (i,
                                   "??" if av is None else "%02x" % av,
                                   "??" if bv is None else "%02x" % bv)
                                  for (i, av, bv) in dd)
                print("    diff vs idle: %s" % pretty)

    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w") as f:
        json.dump(results, f, indent=2)
    print("\nSaved calibration to %s" % OUT_PATH)
    print("Please paste the output above (or the JSON) back for analysis.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
