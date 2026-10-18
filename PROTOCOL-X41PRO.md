# E-YOOSO X-41 Pro — HID protocol notes (from RDCfg.exe reverse engineering)

Status: recovered statically from `X-41 PRO Gaming Mouse/RDCfg.exe` + `HidDevice.dll`.
Target: build a libratbag driver (`driver-redragon.c`) so the mouse works in Piper.

## 1. Identity

| Field | Value | Source |
|---|---|---|
| Vendor | E-YOOSO (Redragon OEM; app is `RDCfg.exe`, mutex `REDRAGON Gaming Mouse Mutex-`) | strings |
| USB VID | `0x04D9` (Holtek) | `Config.ini [Mouse_List]` VID=1241 |
| USB PIDs | `0xFC49`, `0xFC56`, `0xFC3F` (3 fw variants) | PID=64585/64598/64575 |
| Config HID collection | Usage Page `0xFFA0` (vendor), Usage `1` | USAGEPAGE_1=65440, USAGE_1=1 |
| Device interfaces matched | `mi_02`, collections `col01`/`col02` | regex `HID#VID_(..)&PID_(..)&mi_02&col01/col02` |
| Firmware version ranges | `0xFC49`: 0x300–0x3FF · `0xFC56`: 0x100–0x1FF · `0xFC3F`: 0x000–0x000 | VER_MIN/VER_MAX |

Confirm exact PID + report descriptor with `lsusb -v` / `usbhid` on the real device.

## 2. Transport

- Config is done **entirely over HID feature reports** (no output/input reports for config).
  Windows side uses `HidD_SetFeature` / `HidD_GetFeature` and `hid_send_feature_report` /
  `hid_get_feature_report` (hidapi). Wrappers in `HidDevice.dll`
  (`HidDevice_SetMultiFeature`, `HidDevice_GetMultiFeature`, `HidDevice_MultiWrite`).
- **Report size = 64 bytes (0x40).**
- Linux equivalent: `hidraw` + `HIDIOCSFEATURE` / `HIDIOCGFEATURE` (what libratbag drivers use).
- Two code wrappers in `RDCfg.exe`:
  - `0x485128` = `hid_send_feature_report(handle, buf, len)`
  - `0x485120` = `hid_get_feature_report(handle, buf, len)`

## 3. Feature-report framing (payload bytes)

```
byte[0] : type / direction  0x02 = host->device command or query-request
                            0x03 = device->host response (read)
byte[1] : command family    0xF1 = "set" (e.g. poll rate)
                            0xF2 = query / read
                            0xF3 = button / keymap refresh
byte[2..]: opcode + payload (family-specific)
```

> OPEN ITEM: whether `byte[0]` is a true HID report ID or the first payload byte must be
> confirmed against the report descriptor (`lsusb -v`). If the descriptor declares report IDs,
> `byte[0]` is the report ID and the family byte shifts to `byte[0]`.

### Multi-part sequencing
- Multi-chunk writes insert a **50 ms** delay between chunks (`Sleep(0x32)`).
- Query request→response inserts a **10 ms** delay (`Sleep(0x0a)`).

## 4. Command families & opcodes (decompiled via r2ghidra — verified)

Feature report sizes: **16 bytes (0x10)** for query + simple set; **64 bytes (0x40)** for
button/LED bulk writes. `byte[0]` = type, `byte[1]` = family, `byte[2]` = opcode.

### Query (family `0xF2`) — read a value
```
send(16B): 02 F2 <opcode> <lo> <hi> ...
sleep(10ms)
get(16B):  02 F2 <...data...>       # response (report-id byte may read back 0x02 or 0x03)
```
Query opcodes (`byte[2]`):
- **LED state:** `opcode = 0x49 + index*8`; request trailer `04 07`.
- **Poll rate:** `opcode = 0x32`; request trailer byte `05`. Response bytes map to the
  per-stage poll-rate values.
- **Single button:** `byte[2..3] = config address` = `0x42 + buttonIndex*4 + stride*4`;
  trailer `04`. Response is the button record.

### Set — poll rate (family `0xF1`)
```
02 F1 02 <value> ...      (16B)     # value = report-rate code
```
A follow-up `02 F1 02 04` is sent to latch. Multi-chunk sets use `Sleep(50ms)` between.

### Button / keymap refresh (family `0xF3`) — 64-byte report, multi-chunk
First chunk header `02 F3 48 04`, then per-button records at `buf[11..]`:
```
buf[11] = 0x80                      # record marker
buf[12..] = button function bytes   # action type + keycode / macro slot
```
Trailing "empty" chunk header `02 F3 02 04` completes the refresh.

### LED (family `0xF3`, type byte `0x03`) — 64-byte report
Header `03 F3 46 04 32 ...`; per-zone 8-byte records with RGB via three colour bytes and
**brightness encoded as `9 - raw`** (raw from the vendor config `LED_MODE_*_bright`), plus a
mode byte. Log: `slotSendLedState iProfile=%d i=%d r=%d g=%d b=%d`.

### Other commands (opcodes still to pin)
- `SendKeyMapMode` (button/keymap mode), `SendScrollSpeed`, `Send dpi led Refesh`
  (per-DPI-stage LED colour), `QueryDpi` (DPI read), `SetSingle/Combo/FireKeyValue` (macro
  key encoding).

> OPEN ITEM: `byte[0]` reads as `0x02` on requests and `0x02`/`0x03` on responses/LED. This
> is either a true HID report ID or a message-type byte on a single report. The driver
> probes `ratbag_hidraw_has_report()` + the vendor usage page to adapt. Confirm with
> `lsusb -v`.

## 5. Input reports (from live button capture)

The mouse emits 8-byte HID input reports on the mouse interface:

| Byte | Meaning |
|---|---|
| `byte[0]` | button bitmask: bit0=left, bit1=right, bit2=wheel-click, bit3=prev, bit4=next |
| `byte[1]`,`byte[2]` | vendor codes for non-standard buttons (DPI/macro) |
| `byte[3..5]` | x/y motion (0 when only a button is pressed) |
| `byte[6]` | wheel (0x01=up, 0xff=down) |
| `byte[7]` | 0 |

Observed per control:
```
left        01 00 00 00 00 00 00 00
right       02 00 00 00 00 00 00 00
wheel-click 04 00 00 00 00 00 00 00
prev        08 00 00 00 00 00 00 00
next        10 00 00 00 00 00 00 00
wheel-up    00 00 00 00 00 00 01 00
wheel-down  00 00 00 00 00 00 ff 00
dpi-up      08 02 02 00 00 00 00 00
dpi-down    08 02 01 00 00 00 00 00
double-click 01 00 00 00 00 00 00 00   (emits left-click)
macro1      00 00 e2 00 00 00 00 00
macro2      00 00 e0 00 00 00 00 00
macro3      00 00 e1 00 00 00 00 00
```

## 6. Button map & action codes (from Default.bin + input capture)

There are **11 remappable buttons** (wheel up/down are the scroll axis, not buttons).
The config slots (indices 0..10) map to physical buttons with these default
action codes (Default.bin `M1..M11 = 1,2,3,4,5,12,48,49,6,6,6`):

| idx | physical | input | device action code | ratbag action |
|----:|---|---|---:|---|
| 0 | left | `byte0` 0x01 | 1 | BUTTON 1 |
| 1 | right | `byte0` 0x02 | 2 | BUTTON 2 |
| 2 | wheel-click | `byte0` 0x04 | 3 | BUTTON 3 (middle) |
| 3 | prev/back | `byte0` 0x08 | 4 | BUTTON 4 |
| 4 | next/fwd | `byte0` 0x10 | 5 | BUTTON 5 |
| 5 | dpi-up | `08 02 02` | 12 | SPECIAL_RESOLUTION_UP |
| 6 | dpi-down | `08 02 01` | 48 | SPECIAL_RESOLUTION_DOWN |
| 7 | double-click | (emits left) | 49 | SPECIAL_DOUBLECLICK |
| 8 | macro1 | `00 00 e2` | 6 | MACRO |
| 9 | macro2 | `00 00 e0` | 6 | MACRO |
| 10 | macro3 | `00 00 e1` | 6 | MACRO |

Device action-code table (the `Fun` value written into a button record):
`1=left, 2=right, 3=middle, 4=prev, 5=next, 6=macro, 12=dpi-up, 48=dpi-down,
49=double-click`. The idx 5/6/7 → 12/48/49 assignment is inferred from
Default.bin ordering; confirm against QuerySingleButton read-back.

> REMAINING CALIBRATION: the exact **feature-report button record** packing
> (where the action code + macro KeyInfo `map/L/H` land in the 64-byte write) is
> still approximate. Recover it by dumping QuerySingleButton responses per index
> (the driver already logs raw query bytes) or a usbmon capture, then finalise
> `redragon_set_button()`.

## 7. Config data model (from `Config.ini` / `*.prof` — plain INI)

Profiles: 5 (`PROFILE_0..4`).
Per profile:
- `pollrate`
- `dpi` (active stage), `DPICount=5`, per stage `DPI_INFO_n_{used,link,x,y,xy}` — X/Y can be
  linked or independent
- `BUTTON_INFO_n_{ID,Fun,LoopNumber,KeyNumber,Res1..3}` + `BUTTON_INFO_n_KeyInfo_m_{map,L,H}`
  (up to 64 key slots per button → macro with per-key low/high timing bytes)
- LED: `LED_MODE_m_{RGB,h,s,v,bright,breath}` (8 modes), `LedMode`, zones (Light=2)
- Misc: `AngleValue` (angle snapping), `LiftHigh`/`LIFT` (lift-off distance),
  `scrollspeed`/`scrollispage`, `mousespeed`, `dbclickspeed`, `accelenable`

Product descriptor (`Default.bin [PRODUCT]`): `Count=11` (buttons), `DPICount=5`, `Light=2`,
`Wheel=22`, per-button default function codes `M1..M11`, macro timing `M<n>L/M<n>R`, etc.

## 6. libratbag feature fit

| X-41 Pro | libratbag API | Fit |
|---|---|---|
| 5 profiles | profiles | clean |
| 5 DPI stages, linked/separate X/Y | resolution list + `RATBAG_RESOLUTION_CAP_SEPARATE_XY_RESOLUTION` | clean |
| poll rate | `report_rate` + list | clean |
| 11-button remap | button action BUTTON/SPECIAL/KEY/NONE | clean |
| macros (KeyInfo + LoopNumber) | MACRO key-press/release/wait | clean |
| LED RGB + brightness + breath | LED color + ON/OFF/BREATHING/CYCLE + duration | core clean |
| angle snapping (`AngleValue`) | `ratbag_profile_set_angle_snapping` | clean |
| lift height (`LiftHigh`) | *not in API* | gap (drop / extend) |
| scroll speed | *not in API* | gap (drop / extend) |
| exotic multi-zone RGB modes | LED model per-zone color+mode | partial |

## 7. Remaining RE / validation

- Nail exact opcode + payload offset for every command (DPI set, LED set, macro upload,
  profile select/write) — extend the disassembly pass per `Send*`/`Query*`.
- Resolve report-ID question + full report descriptor via `lsusb -v` or USB capture.
- Ground-truth: run `RDCfg.exe` under Wine w/ USB passthrough, or capture with
  usbmon/Wireshark, and diff against the static model.
