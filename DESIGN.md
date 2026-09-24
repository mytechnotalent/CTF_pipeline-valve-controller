# pipeline-valve-controller - Design Blueprint (Act III, IRON VEIN)

Repo: `pipeline-valve-controller`
Companion CTF repo: `CTF_pipeline-valve-controller` (artifact prefix `ACT-III`)
Codename: IRON VEIN
Author: Kevin Thomas (kevin@mytechnotalent.com)

This is the build spine. It is not student-facing. Student-facing artifacts are
`README.md`, `PARTS.md`, `NATION-STATE-REVIEW.md`, and `paper.typ`/`paper.pdf`,
exactly like Acts I and II. The companion CTF ships the canonical
`ACT-III-I.md`, `ACT-III-R.md`, `ACT-III-S.md` plus PDFs, enforced by the
`eh-project-structure` validator.

---

## Act III of the OPERATION COLD IRON saga

Act I was the lie. Act II was the door. Act III is the payload that is already
inside.

WHITEOUT traces the Ministry's tooling to a remote pipeline. The valve
controller is healthy: you can read it and nothing looks broken. That is the
horror. It is not buggy, it is weaponized. A hidden implant beacons over LoRa,
and a logic bomb will slam the valve shut at a trigger and spike the line
pressure. NorthPharma is the Ministry's front; FROSTLINE planted the implant.

This is the first act with a **malware track**. Acts I and II were
vulnerability-only; Act III introduces the implant, and the later acts escalate
one malware concept each.

## Safety contract (real techniques, inert payloads)

- No network, no internet, no host impact. Bare-metal RP2350, no OS, no
  filesystem.
- The beacon targets only the local classroom hub. No external address.
- The logic bomb actuates the servo valve on your own breadboard.
- Synthetic data only.
- A `SANDBOX_ONLY` build guard disables the implant paths in the clean build;
  tests assert the implant cannot act outside its own pins and reserved sector.
- Every act ends in analysis and neutralization.

## Parity contract with Acts I and II

- Same repo layout, same crypto stack (Argon2id + XChaCha20-Poly1305 + BLAKE2b +
  Poly1305 + envelope), same tooling (in-repo harness, audits, 100% coverage),
  same pin map.
- Same document conventions and the telescreen legal disclaimer at the top of
  every markdown file that heads a repo.

## Pin map (identical to Acts I and II, new roles)

| Pin | Act I/II role | Act III role |
| --- | ------------- | ------------ |
| DHT11 GP4 | asset / interlock | line pressure/temperature analog (process sensor) |
| LCD SDA GP2 / SCL GP3 | telemetry / log | SCADA status and alarm readout |
| IR GP5 | door / badge | operator remote (OPEN/CLOSE/ESTOP) |
| Servo GP14 | damper / deadbolt | the valve actuator |
| Red GP16 | breach / DENIED | VALVE FAULT |
| Yellow GP17 | warning / PENDING | COMMAND PENDING |
| Green GP18 | nominal / GRANTED | VALVE NOMINAL |
| Button GP15 | acknowledge / REX | emergency stop (ESTOP) |
| RYLR998 GP8/9 | uplink / auth | SCADA gateway link |
| Debug Probe | analysis | implant analysis (and the anti-debug target) |
| Onboard GP25 | heartbeat | heartbeat |

## Fix track (vulnerabilities)

- Unauthenticated valve angle commands (the ANGLE injection) must be sealed and
  authorized.
- The emergency stop must take priority over any remote command.
- The valve must fail closed (safe) on a lost link or a fault.

## Malware track (the implant, benign)

New module `include/implant.h` + `src/implant.c`, compiled only under
`SANDBOX_ONLY`:

- **Beacon.** Every N ticks, emit a covert LoRa frame with a magic preamble and
  a small synthetic status blob to the local hub.
- **Logic bomb.** Arm on a magic command (a fixed magic value) and actuate the
  valve at the trigger, independent of the operator.
- **Anti-debug.** Read the CoreDebug `DHCSR` (`0xE000EDF0`) and behave benignly
  while a probe is attached, malicious when it is not. This is the dynamic
  analysis trap.
- **Neutralization.** The student disables the beacon, defuses the trigger, and
  removes the implant. Not a one-byte fix.

The implant erases and programs a marker into the reserved flash sector at
`0x103FF000` to preview the persistence lesson of Act IV.

## Companion CTF: ACT-III, four deep tasks

| Task | Points | Objective | Skill |
| ---- | ------ | --------- | ----- |
| 1 | 10 | Setup and analysis | vector table, `main`, module map |
| 2 | 20 | Find and neutralize the beacon | hidden code path, magic preamble |
| 3 | 20 | Defuse the logic bomb | trigger discovery, patch |
| 4 | 20 | Defeat the anti-debug and prove the payload | GDB, `DHCSR` |
| 5 | 20 | Seal the valve command path | fix track |
| 6 | 10 | Export, verify, hardware proof, reflection | `ACT-III_fixed.bin`/`.uf2`, verifier |

Every patch is in-place and same-size, so the shipped artifact can be patched
without moving any address.

## Naming

Project repo `pipeline-valve-controller`; companion `CTF_pipeline-valve-controller`;
CTF artifact prefix `ACT-III`. The banner and paper carry the Act III name.
