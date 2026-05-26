# BTMETER BT-100-APP Bluetooth Protocol Specification

**Device:** BTMETER BT-100-APP Anemometer  
**Protocol:** Bluetooth Low Energy (BLE 4.0+), GATT Notifications + Write Commands  
**Status:** Reverse-engineered — confirmed fields marked ✓, inferred fields marked ~, unknown fields marked ?  
**Last Updated:** 2026-05-26  
**Data Basis:**
- Session 1: 735 notification packets via gatttool (guided test), temp 27.1°C
- Session 2: 932 notification packets via Android HCI snoop (Intelligent Anemometer app), temp 29.7–29.9°C
- Command protocol captured from app session

---

## 1. Device Identification

| Field                | Value                         |
|----------------------|-------------------------------|
| MAC Address          | `01:B6:EC:FF:C4:FC`           |
| BLE Address Type     | Public                        |
| Advertising Name     | `Anemometer`                  |
| RSSI (at ~0.5 m)     | −55 to −65 dBm (typical)      |
| Advertising Interval | Slow; allow **15–20 s** scan window before connecting |
| Pairing Required     | No — unauthenticated, unencrypted |

### 1.1 ManufacturerData

The BLE advertising record contains a ManufacturerData payload that includes the string `-866B`.
This value is also present in the **HoldPeak HP-866B-APP** anemometer, confirming that the two
devices share the same firmware and BLE protocol.

### 1.2 Compatible Devices

| Model               | Manufacturer | Confirmed |
|---------------------|--------------|-----------|
| BTMETER BT-100-APP  | BTMETER      | ✓ (primary device) |
| HoldPeak HP-866B-APP | HoldPeak    | ~ (ManufacturerData match) |

**Companion App:** *Intelligent Anemometer* by Shenzhen ElinkThings  
**Android Package:** `aicare.net.cn.ianemometer`

---

## 2. GATT Service Map ✓ CONFIRMED

### 2.1 Services

| Service UUID | Handle Range | Description |
|--------------|-------------|-------------|
| `0x1800`     | 0x0001–0x000a | Generic Access Profile (standard) |
| `0x1801`     | 0x000b       | Generic Attribute Profile (standard) |
| `0xffb0`     | 0x000c–0x0013 | **Custom — sensor data + command** |
| `0xfee0`     | 0x0014–0x001c | Custom — OTA/configuration (Jieli SmartLink) |

### 2.2 Service 0xffb0 — Sensor Data + Command

| Handle  | Char UUID | Direction | Description |
|---------|-----------|-----------|-------------|
| `0x000c`| —         | ?         | Unknown (no UUID returned) |
| `0x000d`| —         | ?         | Unknown (no UUID returned) |
| `0x000e`| `0xffb1`  | Decl.     | Characteristic declaration |
| `0x000f`| `0xffb1`  | **NOTIFY**| **Wind / sensor data notifications** |
| `0x0010`| `0x2902`  | Write     | CCCD — write `0x0100` to enable notifications |
| `0x0011`| `0xffb2`  | Decl.     | Characteristic declaration |
| `0x0012`| `0xffb2`  | ?         | Read attempted → ATT Error (not readable) |
| `0x0013`| `0xffb3`  | **Write** | **Command channel** (Write Without Response) |

### 2.3 Service 0xfee0 — OTA/Configuration (Jieli SmartLink)

| Handle  | Char UUID | Direction | Description |
|---------|-----------|-----------|-------------|
| `0x0015–0x0016` | —      | ?   | Unknown |
| `0x0017–0x0018` | `0xfee1` | ? | Unknown |
| `0x0019`        | —      | —   | Descriptor |
| `0x001a–0x001b` | `0xfee2` | ? | Unknown |
| `0x001c`        | `0xfee3` | — | Descriptor |

### 2.4 Connection Procedure

```
1. LE scan for ≥15 seconds (advertising interval is slow)
2. Connect:  gatttool -b 01:B6:EC:FF:C4:FC -t public -I
             → connect
3. Enable notifications:
             char-write-req 0x0010 0100
4. Receive notifications on handle 0x000f
   • First ~25 s: Type A packets (startup / raw sensor readings)
   • After ~25 s:  Type B packets (operational / computed wind)
```

**No pairing or PIN required.**

---

## 3. Notification Packet Format

Every notification on handle `0x000f` is exactly **14 bytes**.

There are **two packet types**, distinguished by `byte[1]`:

| byte[1] | Type | Description |
|---------|------|-------------|
| `0x41`  | A    | Startup / raw sensor readings (~25 s after connect) |
| `0x42`  | B    | Operational / computed wind (steady-state) |

### 3.1 Common Header / Footer (both types) ✓

```
Offset  Len  Field        Value   Notes
------  ---  -----        -----   -----
 [0]     1   Header-1     0xA5    Fixed magic byte 1
 [1]     1   Packet-Type  0x41/42 'A'=startup, 'B'=operational
[12]     1   Checksum     0xXX    sum(bytes[0:12]) & 0xFF
[13]     1   Footer       0xAA    Fixed footer
```

**Validity check:**
```python
len(data) == 14 and data[0] == 0xA5 and data[13] == 0xAA
    and sum(data[:12]) & 0xFF == data[12]
```

### 3.2 Type A Packet Layout (byte[1] = 0x41) ✓ / ~

Sent for approximately the first 25 seconds after connection. Contains raw sensor ADC values
from the dual-element thermal anemometer (wind + temperature simultaneously affect both channels).

```
Offset  Len  Field        Value    Notes
------  ---  -----        -----    -----
 [0]     1   Header-1     0xA5     Fixed
 [1]     1   Type         0x41     'A'
 [2:4]   2   Ch-A         0xXX XX  Primary channel (15-bit: (b[2]&0x7F)<<8|b[3])
                                   At zero wind: encodes temperature
                                   During wind: encodes wind + temp cross-sensitivity
 [4:6]   2   Ch-B         0xXX XX  Secondary channel (15-bit: (b[4]&0x7F)<<8|b[5])
                                   Complementary to Ch-A
 [6]     1   Type-Marker  0x0F     Constant for type A
 [7]     1   Type-Marker  0x0F     Constant for type A
 [8]     1   Fixed        0x00     Always 0x00
 [9]     1   Status       0xXX     See §4.4
[10]     1   Fixed        0x0F     Always 0x0F
[11]     1   Activity     0xXX     Wind activity code (§4.5)
[12]     1   Checksum     0xXX     sum(bytes[0:12]) & 0xFF
[13]     1   Footer       0xAA     Fixed
```

**Temperature extraction from Type A (zero-wind only):** ~
```
ch_a_raw = (byte[2] & 0x7F) << 8 | byte[3]
temp_C   = 27.1 + (16381 - ch_a_raw) / 197.7
```
Calibrated from two points: 27.1°C → ch_a_raw=16381; 29.7°C → ch_a_raw=15867.  
This formula is only valid at zero wind (byte[11]=0x00). During wind, ch_a_raw reflects
both wind speed and temperature.

### 3.3 Type B Packet Layout (byte[1] = 0x42) ✓

Sent continuously after the initial ~25 s startup phase. Contains computed wind speed
(temperature-compensated by the device's microcontroller).

```
Offset  Len  Field        Value    Notes
------  ---  -----        -----    -----
 [0]     1   Header-1     0xA5     Fixed
 [1]     1   Type         0x42     'B'
 [2:4]   2   Wind         0xXX XX  Wind speed (15-bit: (b[2]&0x7F)<<8|b[3])
 [4:6]   2   Mode-Mark    0xBF EC  Constant 0xBFEC in all observed packets
 [6]     1   Type-Marker  0x0D     Constant for type B
 [7]     1   Type-Marker  0x0B     Constant for type B
 [8]     1   Fixed        0x00     Always 0x00
 [9]     1   Status       0xXX     See §4.4
[10]     1   Fixed        0x0F     Always 0x0F
[11]     1   Activity     0xXX     Wind activity code (§4.5)
[12]     1   Checksum     0xXX     sum(bytes[0:12]) & 0xFF
[13]     1   Footer       0xAA     Fixed
```

---

## 4. Field Definitions

### 4.1 Wind Speed — Type B bytes[2:4] ✓ CONFIRMED

**15-bit unsigned integer (bit 7 of byte[2] unused):**
```
wind_raw = (byte[2] & 0x7F) << 8 | byte[3]
```

**Zero-wind baseline:** `14333` (raw value at 0.0 m/s display)

**Wind speed formulas:**
```python
wind_m_s   = max(0.0, (wind_raw - 14333) / 2477.3)
wind_km_h  = wind_m_s * 3.6
wind_ft_min = wind_m_s * 196.85
```

**Verification data:**

| Condition         | Display (m/s) | Peak wind_raw | Delta  | Computed      |
|-------------------|---------------|---------------|--------|---------------|
| No wind (indoors) | 0.0           | ~15089        | ~756   | 0.31 (noise)  |
| Light blow        | 2.7 (session 2) | ~21057     | ~6724  | 2.72 ✓        |
| Hard blow (peak)  | 7.4 (session 1) | 32665      | 18332  | 7.40 ✓        |
| Hard blow (peak)  | 7.0 (session 2) | 31473      | 17140  | 6.92 ✓        |

**Scale derivation (session 1):** display=7.4 m/s; delta=18332 → scale=18332/7.4=**2477.3**

### 4.2 Temperature — Type A bytes[2:4] ~ PARTIALLY DECODED

Temperature is encoded in the Type A channel Ch-A at zero wind:
```
ch_a_raw = (byte[2] & 0x7F) << 8 | byte[3]
temp_C   = 27.1 + (16381 - ch_a_raw) / 197.7
```

**Two-point calibration:**

| Temperature (display) | ch_a_raw | Formula result |
|----------------------|----------|----------------|
| 27.1°C (80.7°F)      | 16381    | 27.1°C ✓       |
| 29.7°C (85.5°F)      | 15867    | 29.7°C ✓       |

**Important limitations:**
- Only valid during zero-wind conditions (byte[11]=0x00 in Type A)
- During wind, ch_a_raw is dominated by wind cooling, not temperature
- The formula constants depend on device calibration and may vary unit-to-unit
- Temperature is NOT transmitted in Type B operational packets

**Temperature in steady state:** The app extracts temperature from the Type A startup packets
(first ~25 s) and displays it. Temperature is not re-transmitted during normal Type B operation.

### 4.3 Fixed / Mode Fields ✓ CONFIRMED

| Field      | Type A | Type B | Notes |
|------------|--------|--------|-------|
| bytes[6:7] | `0F 0F` | `0D 0B` | Packet type marker (previously misidentified as constant) |
| byte[8]    | `0x00` | `0x00` | Always zero |
| byte[10]   | `0x0F` | `0x0F` | Always 0x0F |
| bytes[4:5] in Type B | — | `0xBFEC` | Constant mode marker |

### 4.4 Status Byte — byte[9] ? UNKNOWN

Three values observed across all packets:

| Value | Binary     | Context |
|-------|------------|---------|
| 0x01  | 0b00000001 | Normal / baseline |
| 0x03  | 0b00000011 | Elevated temperature; also appears in high-wind transitions |
| 0x11  | 0b00010001 | High-wind burst (bit 4 set; correlates with byte[11] ≥ 0x07) |

Bit 4 (0x10) appears set only during extreme-wind events.

### 4.5 Wind Activity Code — byte[11] ✓ CONFIRMED

A Beaufort-scale-like activity indicator. Values follow a bit-accumulation pattern (1→3→7→F):

| Value | Description | Approx. Wind |
|-------|-------------|-------------|
| 0x00  | Calm        | 0.0–0.3 m/s (display shows 0.0) |
| 0x01  | Light       | 0.3–3.5 m/s (approx.) |
| 0x03  | Moderate    | 3.5–6.0 m/s (approx.) |
| 0x07  | Strong      | 6.0–7.5 m/s (approx.) |
| 0x0F  | Extreme     | Gust / post-peak decay |

Values 0x02, 0x05, 0x09–0x0E not observed. The progression 0→1→3→7→F is a bitmask pattern.

Note: byte[11] reflects the **displayed** wind category, not the instantaneous sensor reading.
The device applies internal filtering; ch_a_raw / wind_raw may show non-zero values even
when byte[11]=0x00.

### 4.6 Checksum — byte[12] ✓ CONFIRMED

```
byte[12] = sum(bytes[0:12]) & 0xFF
```

Verified against all 932 notification packets with zero failures.

---

## 5. Command Protocol ✓ CONFIRMED

The app sends commands to handle `0x0013` (characteristic `0xffb3`, service `0xffb0`).

### 5.1 Command Frame Format

```
55 55 [cmd_id] [data...] [checksum] AA AA

Header:   0x55 0x55
cmd_id:   1-byte command identifier
data:     variable-length payload (0 or more bytes)
checksum: XOR of all bytes from cmd_id through last data byte (inclusive)
footer:   0xAA 0xAA
```

**Checksum computation:**
```python
payload = [cmd_id] + data_bytes
checksum = 0
for b in payload:
    checksum ^= b
frame = [0x55, 0x55] + payload + [checksum, 0xAA, 0xAA]
```

### 5.2 Observed Commands

Commands were observed at ~2094 s into the session (triggered by a specific app action,
likely "Sync" or data-upload):

| cmd_id | Data              | Inferred Purpose |
|--------|-------------------|-----------------|
| `0x01` | `07 00 01 00 00 00 00 00` | Configure measurement range / mode |
| `0x03` | `01 01`           | Confirm / apply configuration |
| `0x13` | `06 01 90 01 80 00 01` | Set parameters |
| `0x21` | `01 03`           | Configure unit or filter |
| `0x23` | `01 01`           | Initialize |
| `0x85` | `36 [page_2B] 00 00 01 [48× 0x00]` | Bulk data transfer (calibration/config table, sequential pages 0x0000–0x00N) |

**Command 0x85 pattern:** Sent in sequential pages where bytes[1:3] of data is a 2-byte little-endian page number (0x0000, 0x0001, 0x0002, …). Likely uploads a Beaufort scale threshold table or factory calibration data.

---

## 6. Packet Examples

### 6.1 Type A — Idle (27.1°C, zero wind)
```
Hex:  A5 41 BF FD BD EA 0F 0F 00 01 0F 00 77 AA
Idx:  [0][1][2][3][4][5][6][7][8][9][A][B][C][D]

Type:     0x41 (A - startup)
ch_a_raw: (0xBF & 0x7F) << 8 | 0xFD = 63*256+253 = 16381
temp_C:   27.1 + (16381-16381)/197.7 = 27.1°C ✓
ch_b_raw: (0xBD & 0x7F) << 8 | 0xEA = 61*256+234 = 15850
bytes[6:7]: 0x0F 0x0F (type A marker)
byte[11]: 0x00 (calm)
checksum: sum(A5,41,BF,FD,BD,EA,0F,0F,00,01,0F,00) & 0xFF = 0x77 ✓
```

### 6.2 Type A — Idle (29.7°C, zero wind)
```
Hex:  A5 41 BD FB BE E4 0F 0F 00 01 0F 00 6E AA

ch_a_raw: (0xBD & 0x7F) << 8 | 0xFB = 61*256+251 = 15867
temp_C:   27.1 + (16381-15867)/197.7 = 27.1 + 2.60 = 29.7°C ✓
ch_b_raw: (0xBE & 0x7F) << 8 | 0xE4 = 62*256+228 = 16100
```

### 6.3 Type B — Idle (29.7°C, zero wind)
```
Hex:  A5 42 BA F1 BF EC 0D 0B 00 01 0F 00 65 AA

Type:     0x42 (B - operational)
wind_raw: (0xBA & 0x7F) << 8 | 0xF1 = 58*256+241 = 15089
wind_m_s: (15089-14333)/2477.3 = 756/2477.3 = 0.31 m/s (noise; display=0.0)
bytes[4:5]: 0xBFEC (constant type B mode marker)
bytes[6:7]: 0x0D 0x0B (type B marker)
byte[11]: 0x00 (calm)
checksum: 0x65 ✓
```

### 6.4 Type B — Hard Blow Peak (7.0 m/s)
```
Hex:  A5 42 FA F1 BF EC 0D 0B 00 01 0F 03 41 AA

wind_raw: (0xFA & 0x7F) << 8 | 0xF1 = 122*256+241 = 31473
wind_m_s: (31473-14333)/2477.3 = 17140/2477.3 = 6.92 m/s ≈ 7.0 display ✓
byte[11]: 0x03 (moderate-strong activity)
```

---

## 7. Type A → Type B Transition

The device sends Type A (raw) packets immediately after connection, then switches to
Type B (computed) packets after approximately 25 seconds.

**Observed transition (session 2):**
```
t=55–79 s:  Type A packets (byte[1]=0x41, bytes[6:7]=0x0F0F)
t=80 s+:    Type B packets (byte[1]=0x42, bytes[6:7]=0x0D0B)
```

**Hypothesis:** The anemometer element requires thermal stabilization (~25 s warm-up).
During warm-up the device transmits raw ADC values (Type A). Once the element reaches
operating temperature, it switches to transmitting temperature-compensated wind speed (Type B).

---

## 8. Unit Switching

The device supports three display units selectable via the physical button. Unit selection
affects the **display** only; the BLE wind_raw value is always in native units. Conversion
must be done by the receiving application using the wind_m_s formula.

Unit-mode packets observed (Type B, idle):

| Unit  | bytes[4:5] observed |
|-------|---------------------|
| m/s   | `0xBFEC` (16364)    |
| km/h  | `0xBFEC` (16364)    |
| ft/min | `0xB7EC` (47084)  |

ft/min mode produces a distinct bytes[4:5] value, which may signal to the app to apply a
different display conversion. Primary wind formula (m/s) remains correct regardless.

---

## 9. Connection Notes

### 9.1 Advertising

- The device advertises at a **slow interval** (~500–2000 ms). Allow 15–20 s scan time.
- BlueZ requires the device to appear in a recent scan before `gatttool` can connect.

### 9.2 Auto-Disconnect

The device powers off after ~5 minutes of inactivity (no button presses, no wind).
This terminates the BLE connection. Reconnection requires a fresh scan.

### 9.3 Notification Rate

~5–7 Hz in Type A and Type B modes.

### 9.4 Second Service (0xfee0 / Jieli SmartLink)

The Jieli SmartLink service (`0xfee0`) with characteristics `0xfee1`, `0xfee2`, `0xfee3`
appears on this device. The app wrote to handle `0x001a` (char `0xfee2`) during the bulk
data upload session at ~2094 s. This service likely handles OTA firmware updates and is
not needed for sensor data reading.

---

## 10. Known Unknowns

| Field / Aspect            | Status | Open Question |
|---------------------------|--------|---------------|
| Handle 0x000c/0x000d      | ?      | UUID and purpose; no UUID returned during discovery |
| Handle 0x0012 (char 0xffb2) | ?    | Returns ATT error; role unknown |
| byte[9] (status byte)     | ~      | 3 values; bit 4 = high-wind flag; bits 0-1 = temperature band |
| Type A channel formula    | ~      | Temperature calibration uses 2 points only; may vary by unit |
| Temperature in Type B     | ?      | Not found in notification data; may only be available in Type A startup |
| Command protocol full map | ~      | 6 command IDs decoded; 0x85 payload structure partially known |
| Service 0xfee0 full role  | ?      | Jieli SmartLink — OTA / config; content unknown |
| BT-600WM-APP protocol     | ?      | Future device; pressure, altitude, humidity, dew point |

---

## 11. Python Decoder

```python
def decode_btmeter_packet(data: bytes) -> dict | None:
    """Decode a 14-byte BTMETER BT-100-APP notification packet."""
    if len(data) != 14:
        return None
    if data[0] != 0xA5 or data[13] != 0xAA:
        return None
    if sum(data[:12]) & 0xFF != data[12]:
        return None

    packet_type = data[1]  # 0x41 = Type A (startup), 0x42 = Type B (operational)
    activity = data[11]    # 0x00/0x01/0x03/0x07/0x0F

    if packet_type == 0x42:
        # Type B: computed wind speed in bytes[2:3]
        wind_raw = (data[2] & 0x7F) << 8 | data[3]
        wind_m_s = max(0.0, (wind_raw - 14333) / 2477.3)
        temp_c = None  # not available in Type B
    elif packet_type == 0x41:
        # Type A: raw sensor; wind unreliable; temperature at zero wind
        ch_a_raw = (data[2] & 0x7F) << 8 | data[3]
        wind_raw = ch_a_raw
        wind_m_s = None  # not directly readable from Type A
        if activity == 0x00:  # zero-wind condition only
            temp_c = 27.1 + (16381 - ch_a_raw) / 197.7
        else:
            temp_c = None
    else:
        return None  # unknown type

    return {
        "packet_type": hex(packet_type),
        "wind_raw": wind_raw,
        "wind_m_s": wind_m_s,
        "wind_km_h": wind_m_s * 3.6 if wind_m_s is not None else None,
        "wind_ft_min": wind_m_s * 196.85 if wind_m_s is not None else None,
        "temp_c": temp_c,
        "activity": activity,
        "status": data[9],
    }


def build_command(cmd_id: int, data: bytes = b"") -> bytes:
    """Build a write command for handle 0x0013."""
    payload = bytes([cmd_id]) + data
    checksum = 0
    for b in payload:
        checksum ^= b
    return b"\x55\x55" + payload + bytes([checksum]) + b"\xaa\xaa"
```

---

## 12. Recommended Next Steps

1. **Decode handle 0x000c/0x000d**: Issue a Read Request to handle 0x000d and record the response.
2. **Calibrate temperature formula**: Record Type A ch_a_raw at 3+ known temperatures (use a reference thermometer). The 197.7 units/°C slope may be device-specific.
3. **Map command 0x85 table**: Record the full 0x85 bulk data at different calibration states to decode the threshold table structure.
4. **Test BT-600WM-APP**: Repeat this process; expect the same GATT map with additional fields in bytes[2:12] for pressure, altitude, humidity, dew point.
5. **Unit command**: Determine if changing units via app sends a command on handle 0x0013, or if the button press is purely local to the device.

---

## Appendix A: Test Data Summary

| Session | Source | Temp | Packets | Max Wind |
|---------|--------|------|---------|----------|
| 1 (guided) | gatttool (computer BLE) | 27.1°C | 735 | 7.4 m/s |
| 2 (app)    | Android HCI snoop | 29.7–29.9°C | 932 | 7.0 m/s |

Session 2 breakdown by type:
- Type A (0x41): 50 packets, t=55–80 s
- Type B (0x42): 553 packets (session window), t=80–356 s

Raw data: `btmeter-test-results.json` (session 1), `btsnoop_hci.log` (session 2)  
Analysis scripts: `btmeter-test.py`, `btmeter-analyze-hci.py`
