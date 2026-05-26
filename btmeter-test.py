#!/usr/bin/env python3
"""
btmeter-test.py — BTMETER BT-100-APP Interactive Protocol Test Script

Guides the user step-by-step through BLE sniffing and correlation tests
to produce a verified protocol specification.

Usage: python3 btmeter-test.py [--mac AA:BB:CC:DD:EE:FF]
"""

import argparse
import json
import queue
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Device constants ──────────────────────────────────────────────────────────
DEFAULT_MAC = "01:B6:EC:FF:C4:FC"
ADDR_TYPE = "public"
NOTIFY_HANDLE = "0x000f"
CCCD_HANDLE = "0x0010"

# Known protocol values (confirmed via prior analysis)
PACKET_LEN = 14
PACKET_HEADER = (0xA5, 0x41)
PACKET_FOOTER = 0xAA
WIND_ZERO_BASELINE = 14333   # (byte[2]&0x7F)<<8|byte[3] at zero wind
TEMP_SCALE = 10.0            # bytes[9:11] big-endian / 10.0 = °C

RESULTS_FILE = Path("btmeter-test-results.json")

# ── Terminal colours ──────────────────────────────────────────────────────────
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
C = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RST = "\033[0m"


# ── Formatting helpers ────────────────────────────────────────────────────────

def header(title: str) -> None:
    bar = "═" * 62
    print(f"\n{BOLD}{B}{bar}{RST}")
    print(f"{BOLD}{B}  {title}{RST}")
    print(f"{BOLD}{B}{bar}{RST}")


def step(n: int, title: str) -> None:
    print(f"\n{BOLD}{C}┌─ Step {n}: {title}{RST}")


def info(msg: str) -> None:
    print(f"{G}  ✓{RST} {msg}")


def note(msg: str) -> None:
    print(f"{B}  ·{RST} {msg}")


def warn(msg: str) -> None:
    print(f"{Y}  ⚠{RST}  {msg}")


def error(msg: str) -> None:
    print(f"{R}  ✗{RST} {msg}")


def ask(prompt: str) -> str:
    return input(f"\n{BOLD}  ▶ {prompt}{RST}").strip()


def pause(prompt: str = "Press ENTER to continue...") -> None:
    input(f"\n{BOLD}  ▶ {prompt}{RST}")


# ── Packet decoding ───────────────────────────────────────────────────────────

def decode_packet(data: bytes) -> Optional[dict]:
    """
    Decode a 14-byte BTMETER notification packet.

    Format (confirmed):
      [0]    0xA5  — header byte 1
      [1]    0x41  — header byte 2
      [2:4]        — wind speed (15-bit: (b[2]&0x7F)<<8 | b[3])
      [4:8]        — unknown (slow-changing; likely second measurement)
      [8]    0x00  — status/flags
      [9:11]       — temperature big-endian uint16 / 10.0 = °C
      [11]         — wind activity indicator (0=calm, 1=moderate, 3=heavy)
      [12]         — checksum = sum(bytes[0:12]) & 0xFF
      [13]   0xAA  — footer
    """
    if len(data) != PACKET_LEN:
        return None
    if data[0] != PACKET_HEADER[0] or data[1] != PACKET_HEADER[1]:
        return None
    if data[PACKET_LEN - 1] != PACKET_FOOTER:
        return None
    if sum(data[:12]) & 0xFF != data[12]:
        return None

    wind_raw = ((data[2] & 0x7F) << 8) | data[3]
    wind_delta = wind_raw - WIND_ZERO_BASELINE
    temp_raw = (data[9] << 8) | data[10]
    temp_c = temp_raw / TEMP_SCALE
    temp_f = temp_c * 1.8 + 32.0

    return {
        "ts": datetime.now().isoformat(timespec="milliseconds"),
        "raw": data.hex(),
        "b2": data[2],
        "b3": data[3],
        "b4_5": (data[4] << 8) | data[5],
        "b6_7": (data[6] << 8) | data[7],
        "b8": data[8],
        "b11": data[11],
        "wind_raw": wind_raw,
        "wind_delta": wind_delta,
        "temp_raw": temp_raw,
        "temp_c": temp_c,
        "temp_f": temp_f,
    }


def parse_notify_line(line: str) -> Optional[bytes]:
    """Extract the payload bytes from a gatttool notification line."""
    m = re.search(r"handle = 0x000f value: ([\da-f ]+)", line, re.IGNORECASE)
    if not m:
        return None
    try:
        return bytes.fromhex(m.group(1).replace(" ", ""))
    except ValueError:
        return None


# ── GATTtool session ──────────────────────────────────────────────────────────

class GattSession:
    """Wraps gatttool in interactive mode with a background reader thread."""

    def __init__(self, mac: str) -> None:
        self.mac = mac
        self._proc: Optional[subprocess.Popen] = None
        self._q: queue.Queue = queue.Queue()
        self._alive = False

    def start(self) -> None:
        self._proc = subprocess.Popen(
            ["gatttool", "-b", self.mac, "-t", ADDR_TYPE, "-I"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self._alive = True
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self) -> None:
        while self._alive and self._proc:
            line = self._proc.stdout.readline()
            if not line:
                break
            clean = re.sub(r"\x1b\[[0-9;]*[mK]|\[K", "", line).strip()
            if clean:
                self._q.put(clean)

    def _send(self, cmd: str) -> None:
        if self._proc and self._proc.stdin:
            self._proc.stdin.write(cmd + "\n")
            self._proc.stdin.flush()

    def _wait_for(self, pattern: str, timeout: float = 15.0) -> Optional[str]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                line = self._q.get(timeout=min(0.4, remaining))
                if re.search(pattern, line, re.IGNORECASE):
                    return line
            except queue.Empty:
                pass
        return None

    def connect(self, timeout: float = 14.0) -> bool:
        self._send("connect")
        return self._wait_for(r"Connection successful", timeout) is not None

    def enable_notify(self) -> None:
        self._send(f"char-write-req {CCCD_HANDLE} 0100")
        time.sleep(0.5)

    def collect(self, duration: float, label: str, scale: Optional[float] = None) -> list:
        """
        Collect and decode packets for `duration` seconds.
        Prints a live summary line for each unique packet type seen.
        Returns list of decoded packet dicts.
        """
        packets = []
        last_raw = None
        deadline = time.monotonic() + duration
        printed_header = False

        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                line = self._q.get(timeout=min(0.3, remaining))
            except queue.Empty:
                continue

            raw = parse_notify_line(line)
            if raw is None:
                continue

            pkt = decode_packet(raw)
            if pkt is None:
                warn(f"Bad/unrecognised packet: {raw.hex()}")
                continue

            pkt["label"] = label
            packets.append(pkt)

            if raw == last_raw:
                continue
            last_raw = raw

            if not printed_header:
                print(f"\n  {'TIME':<12} {'RAW[2:4]':<9} {'ΔWIND':>7} {'ACT':>4}  "
                      f"{'b4_5':>6}  {'TEMP_C':>7}  {'TEMP_F':>7}"
                      + (f"  {'M/S':>6}" if scale else ""))
                print(f"  {'-'*74}")
                printed_header = True

            delta = pkt["wind_delta"]
            act = pkt["b11"]
            tc = pkt["temp_c"]
            tf = pkt["temp_f"]
            b45 = pkt["b4_5"]
            t_str = pkt["ts"][11:23]
            raw23 = f"{pkt['b2']:02x} {pkt['b3']:02x}"
            wind_mark = f"{R}💨{RST}" if delta > 2000 else "  "

            mps_str = ""
            if scale and delta > 0:
                mps_str = f"  {delta / scale:6.2f}"
            elif scale:
                mps_str = f"  {'--':>6}"

            print(f"  {t_str:<12} {raw23:<9} {delta:+7d} {act:4d}  "
                  f"{b45:6d}  {tc:7.1f}  {tf:7.1f}{wind_mark}{mps_str}")

        return packets

    def write_ffb1(self, payload_hex: str) -> bool:
        """Write to the FFB1 command characteristic (handle 0x000D)."""
        self._send(f"char-write-req 0x000d {payload_hex}")
        result = self._wait_for(r"written successfully|error", timeout=5.0)
        return result is not None and "error" not in result.lower()

    def stop(self) -> None:
        self._alive = False
        self._send("disconnect")
        time.sleep(0.3)
        self._send("quit")
        if self._proc:
            try:
                self._proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self._proc.kill()


# ── BLE scanning ──────────────────────────────────────────────────────────────

def scan_for_device(mac: str, timeout: int = 25) -> bool:
    """
    Start a bluetoothctl BLE scan and return True when `mac` appears
    in the device cache.
    """
    subprocess.run(["bluetoothctl", "power", "on"],
                   capture_output=True, timeout=5)

    scan_proc = subprocess.Popen(
        ["bluetoothctl", "scan", "le"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    found = False
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(2)
        r = subprocess.run(["bluetoothctl", "devices"],
                           capture_output=True, text=True, timeout=5)
        if mac in r.stdout:
            found = True
            break
        remaining = int(deadline - time.monotonic())
        print(f"    Scanning... {remaining}s left   ", end="\r", flush=True)

    scan_proc.terminate()
    try:
        scan_proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        scan_proc.kill()

    subprocess.run(["bluetoothctl", "scan", "off"],
                   capture_output=True, timeout=5)
    print()  # clear the \r line
    return found


# ── Stats helper ──────────────────────────────────────────────────────────────

def stats(packets: list) -> dict:
    if not packets:
        return {}
    deltas = [p["wind_delta"] for p in packets]
    tc = [p["temp_c"] for p in packets]
    b45 = [p["b4_5"] for p in packets]
    acts = [p["b11"] for p in packets]
    return {
        "count": len(packets),
        "wind_delta_min": min(deltas),
        "wind_delta_max": max(deltas),
        "wind_delta_mean": round(sum(deltas) / len(deltas), 1),
        "temp_c_min": min(tc),
        "temp_c_max": max(tc),
        "temp_c_mean": round(sum(tc) / len(tc), 2),
        "b4_5_values": sorted(set(b45)),
        "activity_counts": {hex(v): acts.count(v) for v in sorted(set(acts))},
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="BTMETER BT-100-APP Protocol Test")
    parser.add_argument("--mac", default=DEFAULT_MAC,
                        help=f"Device MAC address (default: {DEFAULT_MAC})")
    parser.add_argument("--skip-scan", action="store_true",
                        help="Skip BLE scan (device already in BlueZ cache)")
    args = parser.parse_args()

    mac = args.mac
    results: dict = {
        "device_mac": mac,
        "started": datetime.now().isoformat(),
        "protocol_constants": {
            "packet_len": PACKET_LEN,
            "header": list(PACKET_HEADER),
            "footer": PACKET_FOOTER,
            "checksum": "sum(bytes[0:12]) & 0xFF",
            "temp_formula": "uint16_BE(bytes[9:11]) / 10.0 = °C",
            "wind_formula": "(byte[2]&0x7F)<<8|byte[3] - baseline",
            "wind_baseline": WIND_ZERO_BASELINE,
        },
        "phases": {},
        "all_packets": [],
    }
    wind_scale: Optional[float] = None  # raw units per m/s, determined during test

    # ── Intro ─────────────────────────────────────────────────────────────────
    header("BTMETER BT-100-APP  —  Interactive Protocol Test")
    print(f"""
  Device : {mac}  ("Anemometer")
  Output : {RESULTS_FILE.resolve()}

  Known protocol (confirmed):
    Packet  : 14 bytes · header A5 41 · footer AA
    Checksum: sum(bytes[0:12]) & 0xFF
    Temp    : bytes[9:11] big-endian uint16 / 10.0  → °C
    Wind    : 15-bit = (byte[2]&0x7F)<<8|byte[3], zero={WIND_ZERO_BASELINE}
    byte[11]: activity indicator (0=calm · 1=moderate · 3=heavy)

  Still unknown:
    • Wind speed scale factor (raw units → physical unit)
    • Meaning of bytes[4:7]

  This script will resolve those unknowns via correlation tests.
""")

    # ── Step 1: Power on ──────────────────────────────────────────────────────
    step(1, "Power on the device")
    note("Turn on the BTMETER BT-100-APP anemometer.")
    note("Wait for it to show a stable reading on its display.")
    note("Keep it still — no wind from fans, vents, or movement.")
    pause("Device is on and showing a stable reading — press ENTER...")

    # ── Step 2: Scan ──────────────────────────────────────────────────────────
    step(2, "Scan for device over BLE")

    if args.skip_scan:
        info("Scan skipped (--skip-scan)")
    else:
        found = False
        for attempt in range(1, 4):
            note(f"Scan attempt {attempt}/3  (up to 25 seconds)...")
            if scan_for_device(mac, timeout=25):
                found = True
                break
            if attempt < 3:
                warn("Device not found. Make sure it is on and within ~5 m.")
                pause("Press ENTER to try again...")

        if not found:
            error("Device not found after 3 scans. Try power-cycling it.")
            sys.exit(1)

        info(f"Device found: {mac}")

    # ── Step 3: Connect ───────────────────────────────────────────────────────
    step(3, "Connect via GATT")

    sess = GattSession(mac)
    sess.start()

    connected = False
    for attempt in range(1, 4):
        note(f"Connection attempt {attempt}/3...")
        if sess.connect(timeout=15):
            connected = True
            break
        warn("Connection failed — re-scanning to refresh device cache...")
        scan_for_device(mac, timeout=15)

    if not connected:
        error("Could not connect. Try power-cycling the device.")
        sys.exit(1)

    info("Connected successfully")
    note("Enabling notifications on FFB2 (0x000F)...")
    sess.enable_notify()

    # Wait for first packet
    time.sleep(1)
    note("Waiting for first data packet...")
    if sess._wait_for(r"Notification handle", timeout=8):
        info("Data is flowing ✓")
    else:
        warn("No packets yet — continuing; data may start after a moment.")

    # ── Step 4: Baseline ──────────────────────────────────────────────────────
    step(4, "Baseline capture — calm, no wind")
    note("Keep the device completely still.")
    note("Do NOT breathe or blow toward it. No fans or AC airflow nearby.")
    pause("Press ENTER to start 20-second baseline capture...")

    print()
    note("Capturing baseline (20 seconds)...")
    baseline = sess.collect(20.0, "baseline")
    results["all_packets"].extend(baseline)

    if baseline:
        s = stats(baseline)
        results["phases"]["baseline"] = s
        info(f"Baseline: {s['count']} packets")
        info(f"Wind delta range: [{s['wind_delta_min']}, {s['wind_delta_max']}]  "
             f"(~0 expected)")
        info(f"Temperature: {s['temp_c_mean']:.1f}°C = {s['temp_c_mean']*1.8+32:.1f}°F")
        note(f"b4_5 values seen: {s['b4_5_values']}")
    else:
        warn("No packets received during baseline.")

    # ── Step 5: Read display — baseline ───────────────────────────────────────
    step(5, "Read display — current values")
    note("Look at the device display RIGHT NOW.")

    d_wind_str = ask("Wind speed displayed (e.g. 0.0): ")
    d_wind_unit = ask("Wind unit shown (m/s / mph / km/h / ft/min / knots / B for Beaufort): ").lower()
    d_temp_str = ask("Temperature displayed (e.g. 80.7): ")
    d_temp_unit = ask("Temperature unit (F / C): ").upper()

    results["display_baseline"] = {
        "wind": d_wind_str,
        "wind_unit": d_wind_unit,
        "temp": d_temp_str,
        "temp_unit": d_temp_unit,
    }

    # Verify temperature
    try:
        t_disp = float(d_temp_str)
        t_disp_c = (t_disp - 32) / 1.8 if d_temp_unit == "F" else t_disp
        if baseline:
            decoded_c = baseline[-1]["temp_c"]
            diff = abs(decoded_c - t_disp_c)
            if diff < 0.5:
                info(f"Temperature match: decoded {decoded_c:.1f}°C ↔ display {t_disp_c:.1f}°C  (Δ={diff:.2f}°C ✓)")
            else:
                warn(f"Temperature mismatch: decoded {decoded_c:.1f}°C vs display {t_disp_c:.1f}°C  (Δ={diff:.1f}°C)")
    except ValueError:
        warn("Could not parse temperature for comparison.")

    # ── Step 6: Light blow test ───────────────────────────────────────────────
    step(6, "Light blow test")
    note("This calibrates the wind scale with a gentle, steady puff.")
    note("Point the cups TOWARD your mouth, about 20–30 cm away.")
    note("Blow GENTLY and steadily — aim for the lowest reading above 0.")
    note("Watch the display; you want 0.3–1.0 m/s (or local equivalent).")
    pause("Press ENTER, then immediately start your gentle blow...")

    print()
    note("Capturing light blow (15 seconds)...")
    light_blow = sess.collect(15.0, "light_blow")
    results["all_packets"].extend(light_blow)

    if light_blow:
        s = stats(light_blow)
        results["phases"]["light_blow"] = s
        peak_delta_light = s["wind_delta_max"]
        info(f"Light blow: {s['count']} packets,  peak delta = {peak_delta_light}")

    d_light_wind = ask("What did the display show at peak during the light blow? ")
    results["display_light_blow"] = {"wind": d_light_wind, "unit": d_wind_unit}

    # ── Step 7: Hard blow test ────────────────────────────────────────────────
    step(7, "Hard blow test")
    note("Now blow as HARD as you can into the cups.")
    note("Sustain it for 3–4 seconds, then stop completely.")
    note("Watch the display for the peak reading.")
    pause("Press ENTER, then IMMEDIATELY blow hard...")

    print()
    note("Capturing hard blow + decay (25 seconds)...")
    hard_blow = sess.collect(25.0, "hard_blow")
    results["all_packets"].extend(hard_blow)

    if hard_blow:
        s = stats(hard_blow)
        results["phases"]["hard_blow"] = s
        peak_delta_hard = s["wind_delta_max"]
        info(f"Hard blow: {s['count']} packets,  peak delta = {peak_delta_hard}")
        note(f"Activity bytes seen: {s['activity_counts']}")
        note(f"b4_5 range: {s['b4_5_values']}")

    d_hard_wind = ask("What was the PEAK wind speed on the display during the hard blow? ")
    results["display_hard_blow"] = {"wind": d_hard_wind, "unit": d_wind_unit}

    # ── Compute wind scale ────────────────────────────────────────────────────
    print()
    note("Computing wind speed scale factor...")

    try:
        peak_mps = float(d_hard_wind)
        if d_wind_unit == "mph":
            peak_mps *= 0.44704
        elif d_wind_unit in ("km/h", "kmh", "kph"):
            peak_mps /= 3.6
        elif d_wind_unit in ("ft/min", "fpm"):
            peak_mps *= 0.00508
        elif d_wind_unit == "knots":
            peak_mps *= 0.514444
        elif d_wind_unit == "b":
            peak_mps = None
            warn("Beaufort scale: cannot compute exact m/s. Skipping scale calc.")

        if peak_mps and hard_blow:
            peak_delta = max(p["wind_delta"] for p in hard_blow)
            if peak_delta > 0:
                wind_scale = peak_delta / peak_mps
                res_mps = peak_mps / peak_delta
                info(f"Wind scale: {wind_scale:.1f} raw units per m/s")
                info(f"Resolution: {res_mps:.4f} m/s per raw unit")
                results["wind_scale_units_per_mps"] = wind_scale
                results["wind_formula_verified"] = (
                    f"wind_m_s = ((byte[2]&0x7F)<<8|byte[3] - {WIND_ZERO_BASELINE}) "
                    f"/ {wind_scale:.1f}"
                )
    except ValueError:
        warn("Could not parse hard blow speed for scale calculation.")

    # ── Step 8: Check stored max ──────────────────────────────────────────────
    step(8, "Read stored MAX wind speed from display")
    note("Many anemometers remember the session maximum.")
    note("Check your device for a MAX mode (try the MODE or SET button).")

    d_max_wind = ask("MAX wind speed stored on device display (or 'none' if not available): ")
    if d_max_wind.lower() != "none":
        results["display_max_stored"] = {"wind": d_max_wind, "unit": d_wind_unit}

    # ── Step 9: Temperature variation ─────────────────────────────────────────
    step(9, "Temperature variation test (optional)")
    note("Wrap both palms tightly around the meter body (avoid the cups).")
    note("Your body heat will slowly warm the temperature sensor.")
    note("This confirms the bytes[9:11] temperature encoding.")

    do_temp = ask("Run this test? (y/N): ").lower()
    if do_temp == "y":
        note("Hold the meter. Watch the display temperature rise.")
        pause("Press ENTER when the display temperature has risen at least 0.5°: ")

        print()
        note("Capturing warmed temperature (20 seconds)...")
        temp_var = sess.collect(20.0, "temp_variation")
        results["all_packets"].extend(temp_var)

        if temp_var:
            s = stats(temp_var)
            results["phases"]["temp_variation"] = s
            d_temp2 = ask("What temperature is the display showing now? ")
            results["display_temp_warmed"] = {"temp": d_temp2, "unit": d_temp_unit}
            info(f"Decoded temp range: {s['temp_c_min']:.1f}°C – {s['temp_c_max']:.1f}°C")

    # ── Step 10: Unit switching ───────────────────────────────────────────────
    step(10, "Wind unit switching test (optional)")
    note("If the device has a button to cycle wind units (m/s → mph → km/h ...)")
    note("this test will capture what changes in the packet for each unit.")
    note("Watch bytes[4:5] and byte[9] — one of them is likely the unit code.")

    do_units = ask("Can your device switch wind speed units? (y/N): ").lower()
    if do_units == "y":
        note("Switch to each unit using the device button. Press ENTER for each.")

        for unit_label in ["m/s", "km/h", "mph", "ft/min", "knots", "Beaufort"]:
            resp = ask(f"Switch device to {unit_label}, then press ENTER  (or 's' to skip): ").lower()
            if resp == "s":
                continue
            note(f"Capturing 10 seconds in '{unit_label}' mode...")
            unit_pkts = sess.collect(10.0, f"unit_{unit_label}")
            results["all_packets"].extend(unit_pkts)
            if unit_pkts:
                s = stats(unit_pkts)
                results["phases"][f"unit_{unit_label}"] = s
                note(f"  b4_5={s['b4_5_values']}  activity={s['activity_counts']}")

            resp2 = ask("Continue to next unit? (Y/n): ").lower()
            if resp2 == "n":
                break

    # ── Step 11: FFB1 command probe ───────────────────────────────────────────
    step(11, "FFB1 command probe (optional)")
    note("FFB1 (handle 0x000D) is write-only — the app sends commands here.")
    note("We will try a few candidate command bytes and watch for responses.")
    note("Any change in FFB2 notifications after a write = command worked.")

    do_probe = ask("Run FFB1 command probe? (y/N): ").lower()
    if do_probe == "y":
        # Try a small set of plausible commands based on the response packet format
        # Response header is A5 41, so commands are likely A5 40 xx ... AA
        candidates = [
            ("a54000000000000000000000aa", "request data (00)"),
            ("a540010000000000000000ab aa", "mode 1"),
            ("a540020000000000000000ac aa", "mode 2"),
            ("a5400000000000000000006faa", "known-style packet"),
        ]
        note("Writing candidate commands to FFB1, watching for packet changes...")
        print()

        for cmd_hex, label in candidates:
            cmd_clean = cmd_hex.replace(" ", "")
            note(f"Sending: {cmd_clean}  ({label})")
            before_pkts = sess.collect(2.0, "probe_before")
            ok = sess.write_ffb1(cmd_clean)
            after_pkts = sess.collect(4.0, f"probe_{label}")
            results["all_packets"].extend(before_pkts + after_pkts)

            if after_pkts and before_pkts:
                before_b45 = {p["b4_5"] for p in before_pkts}
                after_b45 = {p["b4_5"] for p in after_pkts}
                if before_b45 != after_b45:
                    info(f"  → b4_5 changed! {before_b45} → {after_b45}")
                else:
                    note(f"  → No change in b4_5")

            pause("Press ENTER for next command...")

    # ── Step 12: Disconnect ───────────────────────────────────────────────────
    step(12, "Disconnect")
    note("Disconnecting from device...")
    sess.stop()
    info("Disconnected.")

    # ── Save results ──────────────────────────────────────────────────────────
    step(13, "Save and summarise")

    results["completed"] = datetime.now().isoformat()
    results["total_packets"] = len(results["all_packets"])
    RESULTS_FILE.write_text(json.dumps(results, indent=2))
    info(f"Results saved → {RESULTS_FILE.resolve()}")

    # ── Summary ───────────────────────────────────────────────────────────────
    header("Test Complete — Summary")

    all_pkts = results["all_packets"]
    if all_pkts:
        all_deltas = [p["wind_delta"] for p in all_pkts]
        all_tc = [p["temp_c"] for p in all_pkts]
        print(f"""
  Packets collected : {len(all_pkts)}
  Temperature range : {min(all_tc):.1f}°C – {max(all_tc):.1f}°C
  Wind delta range  : {min(all_deltas)} – {max(all_deltas)}
  Zero baseline     : {WIND_ZERO_BASELINE}
""")

    if "wind_scale_units_per_mps" in results:
        sc = results["wind_scale_units_per_mps"]
        print(f"  {BOLD}Verified wind formula:{RST}")
        print(f"    raw15  = (byte[2] & 0x7F) << 8 | byte[3]")
        print(f"    wind_m_s = (raw15 - {WIND_ZERO_BASELINE}) / {sc:.1f}")

    print(f"""
  {BOLD}Confirmed protocol constants:{RST}
    Header    : 0xA5 0x41
    Footer    : 0xAA
    Checksum  : sum(bytes[0:12]) & 0xFF
    Temp (°C) : (bytes[9]<<8 | bytes[10]) / 10.0
    Wind raw  : (byte[2]&0x7F)<<8 | byte[3]
    byte[11]  : 0=calm  1=moderate  3=heavy

  Full data  : {RESULTS_FILE.resolve()}
""")


if __name__ == "__main__":
    main()
