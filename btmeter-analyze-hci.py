#!/usr/bin/env python3
"""
btmeter-analyze-hci.py — Analyze btsnoop_hci.log from Intelligent Anemometer app session.

Usage:
    python3 btmeter-analyze-hci.py <btsnoop_hci.log>

Requires: tshark (Wireshark) in PATH

Outputs:
    - GATT service/characteristic UUID map
    - All write commands sent by app
    - All notification packets decoded
    - Temperature field identification
    - JSON summary: btmeter-hci-analysis.json
"""

import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional

DEVICE_MAC = "01:b6:ec:ff:c4:fc"  # lowercase for tshark matching
TARGET_HANDLE = "0x000f"
WIND_BASELINE = 14333
WIND_SCALE = 2477.3
PACKET_LEN = 14

# ── Colours ───────────────────────────────────────────────────────────────────
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
C = "\033[96m"; BOLD = "\033[1m"; DIM = "\033[2m"; RST = "\033[0m"

def banner(title: str) -> None:
    bar = "═" * 68
    print(f"\n{BOLD}{B}{bar}{RST}\n{BOLD}{B}  {title}{RST}\n{BOLD}{B}{bar}{RST}")

def section(title: str) -> None:
    print(f"\n{BOLD}{C}── {title} {'─' * (60 - len(title))}{RST}")

def ok(msg: str) -> None:
    print(f"{G}  ✓{RST} {msg}")

def info(msg: str) -> None:
    print(f"{B}  ·{RST} {msg}")

def warn(msg: str) -> None:
    print(f"{Y}  ⚠{RST}  {msg}")


# ── tshark helpers ────────────────────────────────────────────────────────────

def run_tshark(logfile: str, display_filter: str, fields: list[str]) -> list[dict]:
    """Run tshark with given filter and field list, return list of field dicts."""
    cmd = [
        "tshark", "-r", logfile,
        "-Y", display_filter,
        "-T", "fields",
        "-E", "separator=|",
        "-E", "header=y",
    ]
    for f in fields:
        cmd += ["-e", f]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        print(f"{R}  tshark timed out{RST}")
        return []

    if result.returncode != 0 and not result.stdout:
        print(f"{R}  tshark error: {result.stderr[:300]}{RST}")
        return []

    lines = result.stdout.strip().splitlines()
    if not lines:
        return []

    headers = lines[0].split("|")
    rows = []
    for line in lines[1:]:
        parts = line.split("|")
        row = dict(zip(headers, parts + [""] * max(0, len(headers) - len(parts))))
        rows.append(row)
    return rows


def run_tshark_json(logfile: str, display_filter: str) -> list[dict]:
    """Run tshark and return parsed JSON output."""
    cmd = ["tshark", "-r", logfile, "-Y", display_filter, "-T", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return []
    if result.returncode != 0 and not result.stdout:
        return []
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []


# ── Packet decoding ───────────────────────────────────────────────────────────

def decode_notification(hex_str: str) -> Optional[dict]:
    """Decode a 14-byte BTMETER notification payload."""
    clean = hex_str.replace(":", "").replace(" ", "").lower()
    if len(clean) != PACKET_LEN * 2:
        return None
    try:
        data = bytes.fromhex(clean)
    except ValueError:
        return None
    if data[0] != 0xA5 or data[1] != 0x41:
        return None
    if data[13] != 0xAA:
        return None
    if sum(data[:12]) & 0xFF != data[12]:
        return None

    wind_raw = (data[2] & 0x7F) << 8 | data[3]
    wind_m_s = (wind_raw - WIND_BASELINE) / WIND_SCALE

    return {
        "raw": clean,
        "wind_raw": wind_raw,
        "wind_delta": wind_raw - WIND_BASELINE,
        "wind_m_s": round(wind_m_s, 2),
        "wind_km_h": round(wind_m_s * 3.6, 2),
        "b2": data[2],
        "b3": data[3],
        "b4": data[4],
        "b5": data[5],
        "b4_5": (data[4] << 8) | data[5],
        "b6": data[6],
        "b7": data[7],
        "b8": data[8],
        "b9": data[9],
        "b10": data[10],
        "b11": data[11],
        "checksum_ok": True,
        # Speculative temp interpretations — we'll print all candidates
        "temp_cand_9_10_be": ((data[9] << 8) | data[10]) / 10.0,
        "temp_cand_4_5_be": ((data[4] << 8) | data[5]) / 10.0,
        "temp_cand_b9_only": data[9],
    }


# ── GATT analysis ─────────────────────────────────────────────────────────────

def analyze_gatt(logfile: str) -> dict:
    """Extract GATT service/characteristic map from the capture."""
    section("GATT Service Discovery")

    # Get all GATT packets for broad view
    fields = [
        "frame.number", "frame.time_relative",
        "btatt.opcode", "btatt.handle",
        "btatt.value", "btle_adv.bd_addr",
        "btgatt.uuid16", "btgatt.uuid128",
    ]

    rows = run_tshark(
        logfile,
        "btatt",
        fields,
    )
    info(f"Total BTATT frames: {len(rows)}")

    # Extract Read by Group Type responses (service discovery)
    service_map = {}
    char_map = {}
    write_cmds = []
    notifications = []

    # Run a wider JSON pass to get full layer detail
    frames = run_tshark_json(logfile, "btatt")

    for frame in frames:
        layers = frame.get("_source", {}).get("layers", {})
        btatt = layers.get("btatt", {})
        if not btatt:
            continue

        opcode_str = btatt.get("btatt.opcode", "")
        handle_str = btatt.get("btatt.handle", "")
        value_str  = btatt.get("btatt.value", "")

        # opcode 0x1b = Handle Value Notification
        # opcode 0x52 = Write Command
        # opcode 0x12 = Write Request
        # opcode 0x1d = Read by Group Type Response (services)
        # opcode 0x09 = Read by Type Response (characteristics)

        try:
            opcode = int(opcode_str, 16) if opcode_str.startswith("0x") else int(opcode_str)
        except (ValueError, AttributeError):
            opcode = -1

        if opcode == 0x1b:  # notification
            decoded = decode_notification(value_str)
            if decoded:
                decoded["handle"] = handle_str
                notifications.append(decoded)

        elif opcode in (0x52, 0x12):  # write command / write request
            write_cmds.append({
                "opcode": hex(opcode),
                "handle": handle_str,
                "value": value_str,
                "frame": frame.get("_source", {}).get("layers", {}).get("frame", {}).get("frame.number", "?"),
            })

    return {
        "gatt_frames": len(frames),
        "notifications": notifications,
        "write_commands": write_cmds,
    }


def extract_uuid_map(logfile: str) -> dict:
    """Use tshark dissectors to get handle→UUID map."""
    section("Handle → UUID Map")

    # tshark can output the handle-uuid mapping via specific fields
    fields = [
        "frame.number",
        "btatt.opcode",
        "btatt.handle",
        "btatt.characteristic_uuid16",
        "btatt.characteristic_uuid128",
        "btatt.service_uuid16",
        "btatt.service_uuid128",
        "btatt.uuid16",
        "btatt.uuid128",
        "btatt.value",
    ]

    rows = run_tshark(logfile, "btatt", fields)
    handle_map = {}
    for row in rows:
        h = row.get("btatt.handle", "").strip()
        u16 = row.get("btatt.uuid16", "").strip()
        u128 = row.get("btatt.characteristic_uuid128", "").strip() or row.get("btatt.uuid128", "").strip()
        if h and (u16 or u128):
            handle_map[h] = {"uuid16": u16, "uuid128": u128}

    if handle_map:
        ok(f"Found {len(handle_map)} handle-to-UUID mappings:")
        for h, uuids in sorted(handle_map.items()):
            u = uuids.get("uuid128") or uuids.get("uuid16") or "?"
            print(f"    handle {h:6s} → {u}")
    else:
        warn("No handle→UUID mappings extracted (may need broader filter)")

    return handle_map


def analyze_temperature(notifications: list[dict]) -> None:
    """Try to identify the temperature field by looking for changing values."""
    section("Temperature Field Analysis")

    if not notifications:
        warn("No notifications to analyze")
        return

    # Collect all unique values for each candidate field
    candidates = {
        "b9": set(),
        "b10": set(),
        "b9_b10_be_div10": set(),
        "b4": set(),
        "b5": set(),
        "b4_b5_be_div10": set(),
        "b4_5": set(),
    }

    for n in notifications:
        candidates["b9"].add(n["b9"])
        candidates["b10"].add(n["b10"])
        candidates["b9_b10_be_div10"].add(n["temp_cand_9_10_be"])
        candidates["b4"].add(n["b4"])
        candidates["b5"].add(n["b5"])
        candidates["b4_b5_be_div10"].add(n["temp_cand_4_5_be"])
        candidates["b4_5"].add(n["b4_5"])

    info(f"Unique values per field across {len(notifications)} notification packets:")
    print(f"  {'Field':25s}  {'# unique':8s}  Values (up to 10)")
    print(f"  {'─'*25}  {'─'*8}  {'─'*40}")
    for name, vals in candidates.items():
        sorted_vals = sorted(vals)[:10]
        ellipsis = "..." if len(vals) > 10 else ""
        print(f"  {name:25s}  {len(vals):8d}  {sorted_vals}{ellipsis}")

    print()
    info("Fields with MORE unique values are better temperature candidates (temperature changes continuously).")
    info("Fields with only 1–3 unique values are likely status/flags, not temperature.")

    # Check if any field looks like a plausible temperature
    print()
    section("Plausible Temperature Candidates (15–40°C range)")
    for n in notifications[:5]:
        print(f"  Sample packet: {n['raw']}")
        print(f"    bytes[9:10] big-endian / 10 = {n['temp_cand_9_10_be']:.1f}°C  ({n['temp_cand_9_10_be']*1.8+32:.1f}°F)")
        print(f"    bytes[4:5] big-endian / 10  = {n['temp_cand_4_5_be']:.1f}°C  ({n['temp_cand_4_5_be']*1.8+32:.1f}°F)")
        break


def analyze_writes(write_commands: list[dict]) -> None:
    """Summarize write commands sent by the app."""
    section("Write Commands from App")

    if not write_commands:
        warn("No write commands captured")
        return

    ok(f"Found {len(write_commands)} write commands:")
    seen = set()
    for w in write_commands:
        key = (w["handle"], w["value"])
        if key not in seen:
            seen.add(key)
            print(f"    handle {w['handle']:8s}  value: {w['value']}")


def print_notification_summary(notifications: list[dict]) -> None:
    """Print a sample of decoded notifications."""
    section(f"Notification Packets ({len(notifications)} total)")

    if not notifications:
        warn("No valid BTMETER notifications found")
        return

    # Find unique packet types by b11 activity code
    by_b11 = defaultdict(list)
    for n in notifications:
        by_b11[n["b11"]].append(n)

    ok(f"Activity code distribution (byte[11]):")
    for b11, pkts in sorted(by_b11.items()):
        wind_vals = [p["wind_m_s"] for p in pkts]
        print(f"    b11=0x{b11:02X}  count={len(pkts):4d}  wind: {min(wind_vals):.2f}–{max(wind_vals):.2f} m/s")

    print()
    info("First 5 decoded notifications:")
    for n in notifications[:5]:
        raw = n["raw"]
        print(f"    {' '.join(raw[i:i+2].upper() for i in range(0, len(raw), 2))}")
        print(f"      wind={n['wind_m_s']:5.2f} m/s  b9=0x{n['b9']:02X}  b10=0x{n['b10']:02X}  b11=0x{n['b11']:02X}  b4_5=0x{n['b4_5']:04X}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <btsnoop_hci.log>")
        sys.exit(1)

    logfile = sys.argv[1]
    if not Path(logfile).exists():
        print(f"{R}File not found: {logfile}{RST}")
        sys.exit(1)

    banner("BTMETER BT-100-APP — HCI Snoop Analysis")
    info(f"Input: {logfile}")
    info(f"tshark version check...")
    subprocess.run(["tshark", "--version"], capture_output=True)

    # Phase 1: Extract GATT map
    handle_map = extract_uuid_map(logfile)

    # Phase 2: Analyze all GATT traffic
    result = analyze_gatt(logfile)
    notifications = result["notifications"]
    write_cmds = result["write_commands"]

    # Phase 3: Temperature analysis
    analyze_temperature(notifications)

    # Phase 4: Write commands
    analyze_writes(write_cmds)

    # Phase 5: Notification summary
    print_notification_summary(notifications)

    # Save results
    output = {
        "logfile": logfile,
        "handle_uuid_map": handle_map,
        "write_commands": write_cmds,
        "notification_count": len(notifications),
        "notifications": notifications,
    }

    outfile = Path("btmeter-hci-analysis.json")
    outfile.write_text(json.dumps(output, indent=2))
    ok(f"\nFull analysis saved to: {outfile}")

    banner("Done")


if __name__ == "__main__":
    main()
