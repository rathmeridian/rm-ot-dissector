# otdissect — passive OT/ICS dissector

A read-only network dissector for OT/ICS assessments. It reads a PCAP (or a
live mirror/TAP feed), and produces an asset inventory, a communications map,
an inferred Purdue-level model, and a findings report.

**It never transmits.** The only thing it touches the wire for is asking
`tshark` to read packets. There is no active/scanning code path — by design,
so it's safe to point at fragile production OT and defensible in scoping docs.

## What it produces

| File | Contents |
|---|---|
| `inventory.csv` | Flat asset list (IP, MAC, vendor, device, level, roles) |
| `inventory.json` | Same, machine-readable, plus Modbus/DNP3/BACnet detail |
| `comms.dot` | Graphviz communications map, coloured by Purdue level |
| `comms.png` / `comms.svg` | Auto-rendered map (when graphviz `dot` is present) |
| `report.md` | Summary, inventory, protocol detail, and findings |
| `report.html` | Self-contained, styled, client-facing report (inline map) |

## Build

```sh
make                       # needs a C compiler only
# or: gcc -O2 -Wall -o otdissect dissector.c
```

**Runtime dependency:** `tshark` (Wireshark CLI) on your PATH. Optional:
Graphviz (`dot`) to render the comms map to an image.

## Run

```sh
./otdissect -r capture.pcap -o out/        # analyse a saved capture
./otdissect -i eth0 -d 60   -o out/        # 60s passive live read of a mirror port
dot -Tpng out/comms.dot -o out/comms.png   # render the map (optional)
```

## How it works (v0.1 → v0.4)

- **v0.1 ingest** — shells out to `tshark -T fields` (so it leans on Wireshark's
  mature OT dissectors instead of hand-rolled parsing), builds a flow table and
  a flat asset list. MAC→vendor is resolved by tshark (`-N m`).
- **v0.2 enrichment** — per-protocol detail: Modbus function codes (incl. 128+
  exception replies) + register ranges, DNP3 app function codes (incl. 129/130
  responses) + logical addresses, BACnet device instance + confirmed/unconfirmed
  services, and ENIP/CIP device/product identity.
- **v0.3 model** — infers each host's role (serves vs. drives an OT protocol)
  and from that a Purdue level, builds the comms graph, and auto-renders it to
  PNG/SVG when graphviz is installed.
- **v0.4 report** — writes the artefacts above plus a styled `report.html` for
  client delivery, including findings such as Level 1 devices reachable from IT,
  protocol bridges, and skip-level traffic.

Field names are preflighted against your installed `tshark` (`-G fields`), so
any field your Wireshark build doesn't support is dropped rather than failing
the whole run — safe to extend `REQ[]` with new protocol fields.

Purdue levels are an *inference* from traffic role, not ground truth — treat
them as a hypothesis to validate against drawings and asset owners.

## Protocols recognised

Modbus/TCP (502), DNP3 (20000), S7comm (102), EtherNet/IP (44818 / 2222),
BACnet (47808), OPC-UA (4840). Add more in `classify_port()` and the `FIELDS[]`
list.

---

## Home lab to develop and test against

Start fully virtual; add hardware only when you want demo props or vendor
realism. **Keep the whole lab on an isolated segment — never bridged to your
home LAN, and never near real OT.**

### Software core (do this first)

- **GRFICSv2** — free VirtualBox virtual ICS (a simulated chemical process with
  real PLC logic, an HMI, Modbus + EtherNet/IP). Best source of *process-realistic*
  traffic to dissect. Capture its traffic to a PCAP and run otdissect against it.
- **OpenPLC Runtime** — soft PLC speaking Modbus/TCP, DNP3, ENIP. Run on a VM or
  a Raspberry Pi. Drive it with **ScadaBR** or a `pymodbus` master.
- **Conpot** — ICS honeypot that doubles as a second-vendor device simulator.

### Generate a quick test capture without GRFICS

On an isolated host, in one terminal run a soft Modbus slave, in another poll it,
and capture loopback with tshark:

```sh
pip install pymodbus
# slave:
python -m pymodbus.server --host 127.0.0.1 --port 5020 &
# capture:
tshark -i lo -f "tcp port 5020" -w lab.pcap &
# master (reads a few registers in a loop):
python -c "from pymodbus.client import ModbusTcpClient as C; c=C('127.0.0.1',port=5020)
import time
for _ in range(20): c.read_holding_registers(100,count=4); time.sleep(0.2)"
```

(Port 5020 is a non-privileged stand-in; for real protocol-port detection run the
slave on 502 with privileges, or rewrite the port in the capture.)

### The capture workflow worth rehearsing

The point of the lab isn't just generating traffic — it's practising how you'll
capture passively on a client site:

- **Managed switch with port mirroring (SPAN)** — any cheap smart switch
  (Netgear GS305E, TP-Link Easy Smart) supports it. Mirror the PLC↔HMI link to a
  port, plug in the box running otdissect, confirm you see traffic you're not
  party to. This is the exact on-site deployment pattern.
- **Throwing Star LAN Tap** (~€15–40, 10/100) — passive hardware tap with no
  powered parts, so it *cannot* inject. Good for learning inline tapping.

### Optional hardware for realism/demos

- A used **Siemens S7-1200** (S7comm) or **Allen-Bradley Micro820** (ENIP/CIP)
  gives genuine vendor traffic and OUIs.
- A **Raspberry Pi** running OpenPLC as a cheap always-on target.

### Suggested topology

```
[HMI VM: ScadaBR / GRFICS HMI] ──┐
                                 ├── [managed switch, SPAN → box running otdissect]
[PLC: OpenPLC VM or Pi] ─────────┘
```

Generate process traffic → capture via SPAN (or to PCAP) → run otdissect →
read `report.md`.
