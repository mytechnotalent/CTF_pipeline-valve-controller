# OPERATION IRON VEIN - Requirements & Grading Criteria

```
+--------------------------------------------------------------------------------+
|                                                                                |
|                    OPERATION IRON VEIN                                         |
|                                                                                |
|                 REQUIREMENTS & GRADING CRITERIA                                |
|                                                                                |
|   TARGET: NorthPharma SCADA pipeline valve controller                          |
|   ARTIFACT: ACT-III.bin / ACT-III.uf2 (compromised)                            |
|   CREW: FROSTLINE            OPERATIVE: NIGHTINGALE                            |
|                                                                                |
+--------------------------------------------------------------------------------+
```

---

## Project Overview

NorthPharma runs the cold chain that keeps a vaccine lot viable, and its SCADA
pipeline valve controller built on a Pico 2 is the hand at the end of the line. A
contractor called **FROSTLINE** planted an implant in the controller image:
a covert beacon, a logic bomb, a reserved-sector persistence marker, and an
inverted valve command authorization verdict. Operative **NIGHTINGALE**
recovered the compromised image as `ACT-III.bin`.

Students are the reverse-engineering reserve. They reverse engineer `ACT-III.bin`
with Ghidra, find and patch all four defects, defeat the CoreDebug `DHCSR`
anti-debug under GDB to observe the payload, export a corrected image, flash it
to a real Pico 2, and prove the corrected behavior on the breadboard. The machine
check is `scripts/verify_ctf.py`.

The challenge is a standalone capstone exercise and contains no answer,
constant, address, bug, or patch belonging to any other course assignment.

---

## Learning Objectives

- Decode an ARM Cortex-M33 vector and boot table and identify the reset handler
  and initial stack pointer.
- Map a stripped firmware image into modules by tracing calls from `main` and
  the monitor loop.
- Locate four corrupted bytes: a covert beacon gate, a logic-bomb arming gate, a
  persistence gate, and an authorization verdict branch.
- Analyze `cbz`, `cbnz`, `beq`, and `bne` condition semantics and branch
  inversion.
- Explain why a periodic magic preamble is a detection opportunity and why a
  trigger can detonate through the actuator path.
- Read CoreDebug `DHCSR`, explain the anti-debug trap, and defeat it under GDB.
- Explain why authentication is not authorization and why a verdict must be
  verified before the actuator moves.

Students must use only the course concepts: ARM registers, stack behavior,
USB-CDC and UART consoles, GDB, Ghidra static analysis and binary patching,
vector tables, reset startup, XIP, Thumb addressing, condition-code analysis,
stateful security, and the Argon2id plus XChaCha20-Poly1305 authenticated
envelope.

---

## Deliverables Checklist

| # | Deliverable | Format | Criterion |
|---|-------------|--------|-----------|
| 1 | Ghidra project screenshot | PNG/JPG | Task 1 |
| 2 | Vector table and boot table | Inside `ACT-III-Answers.md` | Task 1 |
| 3 | `main` and monitor-loop table | Inside `ACT-III-Answers.md` | Task 1 |
| 4 | Module map | Inside `ACT-III-Answers.md` | Task 1 |
| 5 | Beacon evidence and patch | Inside `ACT-III-Answers.md` | Task 2 |
| 6 | Logic bomb evidence and patch | Inside `ACT-III-Answers.md` | Task 3 |
| 7 | Anti-debug GDB proof, persistence evidence, and patch | Inside `ACT-III-Answers.md` | Task 4 |
| 8 | Authorization evidence and patch | Inside `ACT-III-Answers.md` | Task 5 |
| 9 | `ACT-III_fixed.bin` | BIN file | Task 6 |
| 10 | `ACT-III_fixed.uf2` | UF2 file | Task 6 |
| 11 | Hardware proof and reflection | Inside `ACT-III-Answers.md` | Task 6 |

---

## Required Tools and Equipment

| Tool | Purpose |
|------|---------|
| Raspberry Pi Pico 2 | Isolated target node |
| Debug Probe (OpenOCD) | SWD connection for GDB inspection and the anti-debug work |
| arm-none-eabi-gdb | Runtime breakpoints, `DHCSR` clearing, and payload observation |
| Ghidra | Static analysis and binary patching |
| Python 3 with `uf2conv.py` | UF2 conversion and artifact checks |
| DHT11, 1602 I2C LCD, RYLR998, IR receiver, SG90 servo, 3 LEDs, ESTOP button | Breadboard hardware proof |
| `ACT-III.bin` and `ACT-III.uf2` | Supplied compromised artifacts |

Console settings: **USB-CDC virtual COM port, 115200 baud, 8 data bits, no
parity, 1 stop bit**. Radio UART settings: **UART1, 115200, network ID 18**.

---

## Artifact Identity

The instructor-issued artifact hashes are:

```text
ACT-III.bin        a0f9206fdc4a33ecd24db15d179c31c40ec8abbc358489fe61a7d45dcf2d2b48
ACT-III.uf2        aed2e62f127f0ceb9d60621ef02c16850669679d1939f9ec37269cb7bd18aff4
ACT-III_fixed.bin  bac3e278ce9ba9d0c166065b0218e71f3e3eb2ff0f80fee5f439e93ab058fa0c
ACT-III_fixed.uf2  fb53ca66ec00c448bb28f14a8bc9d9bb71161f8b448c8b8c13cd8a9b00ea7653
```

The verifier checks the `ACT-III.bin` and `ACT-III_fixed.bin` hashes
specifically, asserts the four fixed bytes, and requires that only those four
offsets differ between the two `.bin` images. Both `.bin` images are 50,732
bytes and both `.uf2` images are 102,400 bytes.

---

## Grading Rubric - Detailed Breakdown

### Task 1: Setup and Initial Analysis (10 points)

| Criterion | Points | Full credit | Partial credit | No credit |
|-----------|--------|-------------|----------------|-----------|
| **[DOCUMENT]** Ghidra project created with the correct name and settings | 2 | Project `IronVein_Investigation`, raw binary import | One item off | Not set up |
| **[DOCUMENT]** Processor configured as ARM Cortex 32 little endian default | 2 | Screenshot shows the correct processor | Wrong language | Missing |
| **[DOCUMENT]** Base address set to 0x10000000 | 2 | Base `0x10000000` | Wrong base | Missing |
| **[DOCUMENT]** Vector table, initial stack pointer, and reset handler identified | 2 | Base `0x10000000`, initial SP `0x20082000`, reset handler `0x1000015D` | One missing | Not found |
| **[DOCUMENT]** main and the SCADA controller state machine (monitor_step) addresses identified | 1 | `main` `0x10000234`, `monitor_step` `0x1000659C` | One correct | Neither |
| **[DOCUMENT]** Module map identifies the valve, control, valve_auth, implant, and monitor anchors | 1 | At least one correct anchor per module | Partial | Missing |

### Task 2: Bug #1 The Beacon (20 points)

| Criterion | Points | Full credit | Partial credit | No credit |
|-----------|--------|-------------|----------------|-----------|
| **[DOCUMENT]** Located the beacon gate branch at 0x1000A245 | 5 | Address and function identified | Approximate | Not found |
| **[DOCUMENT]** Documented cbz versus cbnz and the every-8-ticks DE AD BE EF beacon | 5 | Correct branch semantics and beacon detail | Partial | Wrong |
| **[DOCUMENT & PATCH]** Patched 0xB9 to 0xB1 so the beacon gate is closed | 7 | Byte `0xB9` changed to `0xB1` | Wrong byte | Not patched |
| **[DOCUMENT]** Explained how to prove the covert beacon stopped | 3 | Periodic magic frame no longer observed | Vague | Missing |

### Task 3: Bug #2 The Logic Bomb (20 points)

| Criterion | Points | Full credit | Partial credit | No credit |
|-----------|--------|-------------|----------------|-----------|
| **[DOCUMENT]** Located the arming gate branch at 0x1000A30B | 5 | Address and function identified | Approximate | Not found |
| **[DOCUMENT]** Documented the FROSTLNE arming magic and the 3-tick detonation | 5 | Correct magic, delay, and detonation path | Partial | Wrong |
| **[DOCUMENT & PATCH]** Patched 0xB9 to 0xB1 so the logic bomb is disarmed | 7 | Byte `0xB9` changed to `0xB1` | Wrong byte | Not patched |
| **[DOCUMENT]** Explained that the bomb closes the valve through the actuator path | 3 | Direct actuator call, no authorization | Vague | Missing |

### Task 4: Bug #3 The Persistence Marker (20 points)

| Criterion | Points | Full credit | Partial credit | No credit |
|-----------|--------|-------------|----------------|-----------|
| **[DOCUMENT]** Located the persistence gate branch at 0x1000A29F | 5 | Address and inlined persist path identified | Approximate | Not found |
| **[DOCUMENT]** Documented the CoreDebug DHCSR anti-debug and how it is defeated under GDB | 5 | `0xE000EDF0`, `C_DEBUGEN` and `C_HALT`, and a real defeat method | Partial | Wrong |
| **[DOCUMENT & PATCH]** Patched 0xD1 to 0xD0 so no marker is written to 0x103FF000 | 7 | Byte `0xD1` changed to `0xD0` | Wrong byte | Not patched |
| **[DOCUMENT]** Explained the write-once marker byte 0xC7 and the Act IV persistence preview | 3 | Marker, reserved sector, write-once latch, persistence lesson | Vague | Missing |

### Task 5: Bug #4 The Valve Command Authorization (20 points)

| Criterion | Points | Full credit | Partial credit | No credit |
|-----------|--------|-------------|----------------|-----------|
| **[DOCUMENT]** Located the authorization branch at 0x100074E9 | 5 | Address and function identified | Approximate | Not found |
| **[DOCUMENT]** Documented the authorization verdict inversion and the branch condition | 5 | Reject when the verdict is false | Partial | Wrong |
| **[DOCUMENT & PATCH]** Patched 0xD1 to 0xD0 so unauthorized and replayed commands are rejected | 7 | Byte `0xD1` changed to `0xD0` | Wrong byte | Not patched |
| **[DOCUMENT]** Explained that unauthenticated and replayed valve commands must be rejected | 3 | The actuator must see only an authorized verdict | Vague | Missing |

### Task 6: Export and Verify (10 points)

| Criterion | Points | Full credit | Partial credit | No credit |
|-----------|--------|-------------|----------------|-----------|
| **[PATCH]** Exported ACT-III_fixed.bin from Ghidra | 2 | Valid patched binary | Corrupt | Not submitted |
| **[PATCH]** Converted to ACT-III_fixed.uf2 with the correct base and family | 2 | `--base 0x10000000 --family 0xe48bff59` | Wrong flags | Not submitted |
| **[DOCUMENT]** scripts/verify_ctf.py passes and hardware proves the correct behavior | 3 | Verifier passes and the hardware proof is shown | Partial proof | No proof |
| **[DOCUMENT]** Reflection maps each of the four defects to a real-world control-system failure | 3 | Specific mapping for all four | Partial | Missing |

---

## Common Pitfalls

| Pitfall | Consequence | Avoidance |
|---------|-------------|-----------|
| Reading the beacon gate backwards | The covert frame keeps transmitting | Accept only on the neutralization branch (`cbz`, `0xB1`) |
| Confusing `cbz` and `cbnz` at `0xA30B` | The `FROSTLNE` magic still arms the bomb | Neutralize only when the gate is clear (`cbz`, `0xB1`) |
| Missing that the persist path is inlined | Cannot find the marker gate | Look inside `implant_tick` at `0x1000A29F` |
| Patching the shipped image before observing the payload | You never prove the marker write | Defeat `DHCSR` under GDB first, then patch the artifact |
| Fabricating the GDB session | Verification fails | Show the command sequence and the real observed code path |
| Treating the anti-debug as a defect to patch | Wasted effort; it is identical in both images | Defeat it in a scratch copy or with GDB, then patch the real defect |
| Missing that the authorization branch is a verdict | Unauthenticated commands still reach the valve | Accept only when the verdict is true (`beq` to reject, `0xD0`) |
| Forgetting UF2 conversion | Raw binary will not flash | Use `uf2conv.py` with family `0xe48bff59` |

---

## How To Breadboard

| Device | Pin on device | Pico 2 GPIO | Notes |
|--------|---------------|-------------|-------|
| DHT11 process sensor | DATA | GP4 | 10 kOhm pull-up to 3.3 V if the module needs it |
| 1602 LCD | SDA | GP2 | I2C1, backpack address `0x27` |
| 1602 LCD | SCL | GP3 | I2C1, 100 kHz |
| 1602 LCD | VCC / GND | VBUS 5 V / GND | The backpack needs 5 V, not 3.3 V |
| RYLR998 | RX | GP8 (Pico TX) | UART1, 115200, network ID 18 |
| RYLR998 | TX | GP9 (Pico RX) | UART1 |
| IR receiver | OUT | GP5 | VS1838B, internal pull-up enabled |
| Servo | signal | GP14 | PWM 50 Hz; 1000 uF bulk cap across servo 5 V and GND |
| Red LED | anode | GP16 | VALVE FAULT, 220 to 330 ohm to GND |
| Yellow LED | anode | GP17 | COMMAND PENDING, 220 to 330 ohm to GND |
| Green LED | anode | GP18 | VALVE NOMINAL, 220 to 330 ohm to GND |
| Emergency-stop button | leg 1 | GP15 | Internal pull-up; leg 2 to GND, never to 3.3 V |
| Onboard LED | built in | GP25 | Heartbeat |
| Debug Probe | SWCLK / SWDIO / GND | debug header | For GDB only |

Use 3.3 V logic on every GPIO. The only 5 V connection is the LCD backpack
supply. Keep the 1000 uF capacitor on the servo rail.

---

## Memory Map Reference

| Region | Address | Purpose |
|--------|---------|---------|
| Bootrom | `0x00000000` | Immutable boot code |
| Flash/XIP | `0x10000000` | Vector table, code, rodata, data image |
| SRAM | `0x20000000` | Stack and writable state |
| CoreDebug `DHCSR` | `0xE000EDF0` | Anti-debug register read by the implant |
| Implant reserved sector | `0x103FF000` | Persistence marker target (sector) |
| Implant tick counter | `0x200136F0` | Incremented once per `implant_tick` |
| Implant arming flag | `0x20013CF0` | Set when `FROSTLNE` arms the bomb |
| Implant beacon gate | `0x20013CF1` | Gates the covert beacon frame |
| Implant trigger tick | `0x200136F4` | Tick at which an armed bomb detonates |
| Implant command gate | `0x20013CEF` | Gates `FROSTLNE` handling |
| Implant persistence gate | `0x20013CF2` | Gates the marker write |
| Implant marker latch | `0x20013CF3` | Write-once latch for `0x103FF000` |

The VA of any file offset is the file offset plus `0x10000000`.

---

## Deadline & Submission

- Create a folder containing the Ghidra screenshot, `ACT-III_fixed.bin`, and
  `ACT-III_fixed.uf2`.
- Write all written answers in `ACT-III-Answers.md` inside that folder.
- Include the output of `python scripts/verify_ctf.py`.
- ZIP the folder as `lastname-firstname-ACT-III.zip`.
- Submit the ZIP before the posted deadline; late submissions lose 10 percent
  per day.

---

## Grade Scale

| Grade | Percentage | Points |
|-------|------------|--------|
| A+ | 97-100% | 97-100 |
| A  | 93-96% | 93-96 |
| A- | 90-92% | 90-92 |
| B+ | 87-89% | 87-89 |
| B  | 84-86% | 84-86 |
| B- | 80-83% | 80-83 |
| C  | 70-79% | 70-79 |
| F  | 0-69% | 0-69 |

---

## Academic Integrity

Use only the supplied Pico 2 and firmware. Do not connect the exercise to an
operational pipeline control system, a pharmaceutical network, a public network,
a military system, or a third-party device. This is a controlled, isolated
educational exercise. All analysis and patches must be your own work; sharing
binaries, addresses, keys, passphrases, or answers is a violation of the
academic integrity policy.

---

## Reference Material

| Topic | Reference |
|-------|-----------|
| ARM Cortex-M33 registers and stack | Course block 1 |
| USB-CDC and UART console capture | Course block 2 |
| Vector tables, reset startup, and XIP | Course block 3 |
| Ghidra static analysis and binary patching | Course block 4 |
| Covert channels and control flow | Course block 5 |
| CoreDebug `DHCSR` and anti-debug | Course block 6 |
| Reserved-flash persistence | Course block 7 |
| Argon2id and XChaCha20-Poly1305 authenticated envelope | Course block 8 |
| Authentication versus authorization and fail-safe policy | Course block 9 |
