"""Wiring the SE052.

Reads: The SE052 on an MCU's I2C bus. SDA (pin 11) and SCL (pin 10) go to the MCU with pull-ups to the bus supply of
1.65 V to 3.6 V, which also feeds VIN (pin 12). VOUT (pin 15) goes to VDD (pin 18) on the board, as Table 2 asks;
Figure 1 shows an optional 22 nF on VIN and an optional 22 nF (or nothing) on VOUT. RST_N (pin 14) goes to a GPIO the
reset port drives low to reset the chip. There is no ENA pin: deep power-down is the S-block 0xDF, and the next I2C
access wakes the chip. CLK (13) is left open or tied to ground, LA and LB are left open, IO1 and IO2 are the chip's own
I2C controller and stay open when it is not used. The pull-up value is not in the data sheet.
"""

from _se052 import PINS

from figkit import Fig

SOURCES = ["docs/diagrams/figures/_se052.py"]


def build(_d):
    names = {p[1] for p in PINS}
    for n in ("SDA", "SCL", "VIN", "VOUT", "VDD", "RST_N", "VSS"):
        if n not in names:
            raise SystemExit(f"figure source drift: {n} not in the SE052 pin table")
    f = Fig("se052-wiring", "Wiring the SE052",
            alt="Schematic in boxes: MCU I2C SDA and SCL with pull-ups to the 1.65 V to 3.6 V bus supply, VIN on that "
                "supply, VOUT to VDD, RST_N on a GPIO, optional 22 nF on VIN and VOUT.",
            width=1200, kicker="SE052", subtitle="SE052 data sheet Rev. 1.5: Figure 1 (p. 6) and Table 2 (p. 4).",
            legend=[("blue", "bus"), ("rose", "supply"), ("teal", "control"), ("slate", "optional part")])
    W = f.body_w
    mcu = f.card(0, 140, 260, "MCU", ["I2C SDA", "I2C SCL", "GPIO (reset port)", "3V3, GND"], tone="slate",
                 accent=True)
    pu = f.card(340, 0, 300, "Pull-ups to the bus supply", ["SDA and SCL, value per bus speed",
                                                            "bus supply 1.65 V to 3.6 V"], tone="blue", accent=True)
    chip = f.card(W - 330, 140, 330, "SE052", ["11 SDA, 10 SCL", "12 VIN: bus supply", "15 VOUT to 18 VDD",
                                             "14 RST_N", "19 VSS"], tone="teal", accent=True)
    cap = f.card(340, 330, 300, "Capacitors (optional)", ["22 nF on VIN", "22 nF or none on VOUT, at most 47 nF"],
                 tone="slate", dashed=True)
    f.connect(mcu, chip, "right", "left", at=0.25, bt=0.25, label="SDA, SCL", tone="blue")
    f.connect(mcu, chip, "right", "left", at=0.6, bt=0.7, label="RST_N", tone="teal")
    f.connect(pu, chip, "right", "top", label="pull-up", tone="blue")
    f.connect(cap, chip, "right", "bottom", label="VIN, VOUT", tone="slate", dashed=True)
    f.note(0, max(chip.b, cap.b) + 30, W, "Unused: CLK (13) open or to ground, LA (17) and LB (1) open, IO1 (3) and "
           "IO2 (16) open when the chip's own I2C controller is not used. The limit of 47 nF on VOUT is Table 6, p. 8.",
           tone="slate", title="Unused pins")
    return f
