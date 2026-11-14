"""SE052 pinout, HVQFN20, top view.

Reads: The SE052 seen from the top in its HVQFN20 package (4 x 4 x 0.85 mm, 0.5 mm pitch, SOT917-7 in the data
sheet). Pin 1 is at the top of the left side and the numbers run counter-clockwise: 1 to 5 down the left side, 6 to
10 along the bottom, 11 to 15 up the right side and 16 to 20 along the top. Each pin card is coloured by the pin's
type as in the HX2QFN20 pinout. The driver uses SDA (11) and SCL (10) for the bus and RST_N (14) through the reset
port; the SE052 has no ENA pin, so deep power-down is a T=1 S-block (0xDF) and the next I2C access wakes it. The
table is SE052 Table 2 (p. 4).
"""

from _se052 import PINS, REF, TONES

from figkit import Fig

SOURCES = ["docs/diagrams/figures/_se052.py"]


def data():
    return {"pins": [list(p) for p in PINS], "ref": REF, "sources": SOURCES}


def build(d):
    f = Fig("se052-pinout", "SE052 pinout, HVQFN20",
            alt="Pinout of the SE052 in HVQFN20, top view: 20 pins with their names, coloured by type; SDA on 11, "
                "SCL on 10, RST_N on 14, VIN on 12, VDD on 18, no ENA pin.",
            width=1200, kicker="SE052", subtitle=d["ref"],
            legend=[("blue", "bus"), ("rose", "power"), ("brown", "power output"), ("teal", "digital in"),
                    ("violet", "digital in/out"), ("magenta", "analog"), ("slate", "ground"),
                    ("stone", "not connected")])
    pins = {p[0]: p for p in d["pins"]}
    W = f.body_w
    cw, ch, gap = 170, 44, 10
    body_x, body_y, body = 300, 110, 536
    f.rect(body_x, body_y, body, body, fill="paper", stroke="line", rx=14)
    f.text(body_x + body / 2, body_y + body / 2 - 6, "SE052", size=22, weight=700, anchor="middle", bg="paper")
    f.text(body_x + body / 2, body_y + body / 2 + 20, "top view", size=14, color="muted", anchor="middle", bg="paper")
    f.circle(body_x + 22, body_y + 22, 6, fill="ink2")
    step = (body - 40) / 5

    def pin_card(n, x, y, w=cw):
        num, name, typ, _fn = pins[n]
        hook = {"SDA": "Write() / Read()", "SCL": "Write() / Read()", "RST_N": "Reset()"}.get(name, "")
        f.card(x, y, w, f"{num}  {name}", [hook] if hook else [], tone=TONES[typ], accent=True)

    for i, n in enumerate(range(1, 6)):  # left, top to bottom
        pin_card(n, body_x - cw - 24, body_y + 20 + i * step)
    for i, n in enumerate(range(11, 16)):  # right, bottom to top
        pin_card(n, body_x + body + 24, body_y + 20 + (4 - i) * step)
    bw = (body - 4 * gap) / 5
    for i, n in enumerate(range(6, 11)):  # bottom, left to right
        pin_card(n, body_x + i * (bw + gap), body_y + body + 24, w=bw)
    for i, n in enumerate(range(16, 21)):  # top, right to left
        pin_card(n, body_x + (4 - i) * (bw + gap), body_y - 24 - 70, w=bw)
    f.note(0, body_y + body + 150, W,
           "No ENA pin: deep power-down is the T=1 S-block 0xDF and the next I2C access wakes the chip, which boots "
           "with no state kept (section 10.3, p. 7). VOUT goes to VDD on the board (Table 2). RST_N low resets the "
           "chip (Table 2).", tone="amber", title="Different from the SE050 and SE051")
    return f
