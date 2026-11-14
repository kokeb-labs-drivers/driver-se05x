"""SE052 package outline, HVQFN20, drawn to scale.

Reads: The SE052 body from above and from the side, to one scale: 4.0 x 4.0 mm, 0.85 mm high, 20 pins at a
0.5 mm pitch, five on each side, pin 1 at the top of the left side (SE052 data sheet section 6, p. 5, and the pin
order of Table 2, p. 4). The terminal and exposed-pad dimensions are in the package drawing SOT917-7, not in the data
sheet, so the pins are drawn as position marks only. The SE050 and SE051 come in the smaller HX2QFN20 (3.0 x 3.0 x
0.32 mm, 0.4 mm pitch).
"""

from _se052 import PINS

from figkit import Fig

SOURCES = ["docs/diagrams/figures/_se052.py"]

BODY_MM = 4.0
HEIGHT_MM = 0.85
PITCH_MM = 0.5
PER_SIDE = 5


def build(_d):
    if len(PINS) != 4 * PER_SIDE:
        raise SystemExit("figure source drift: the SE052 pin table does not have 20 pins")
    f = Fig("se052-outline", "SE052 package outline, HVQFN20",
            alt="Outline of the SE052 in HVQFN20 drawn to scale: a 4.0 x 4.0 mm body from above with five pin marks "
                "per side at a 0.5 mm pitch and pin 1 at the top left, and a side view 0.85 mm high.",
            width=1200, kicker="SE052", subtitle="SE052 data sheet Rev. 1.5: section 6 (p. 5), pin order Table 2 (p. 4)",
            legend=[("teal", "body"), ("slate", "pin position")])
    W = f.body_w
    scale = 90.0  # px per mm
    body = BODY_MM * scale
    x0, y0 = 120, 70
    f.rect(x0, y0, body, body, fill="paper", stroke="line", rx=8)
    f.text(x0 + body / 2, y0 + body / 2 - 8, "SE052", size=22, weight=700, anchor="middle", bg="paper")
    f.text(x0 + body / 2, y0 + body / 2 + 18, "top view", size=14, color="muted", anchor="middle", bg="paper")
    f.circle(x0 + 20, y0 + 20, 6, fill="ink2")
    span = (PER_SIDE - 1) * PITCH_MM * scale
    first = (body - span) / 2
    mark = 14
    for i in range(PER_SIDE):
        off = first + i * PITCH_MM * scale
        f.rect(x0 - mark, y0 + off - 4, mark, 8, fill="ink2", stroke="ink2", rx=1)          # left: 1 to 5
        f.rect(x0 + off - 4, y0 + body, 8, mark, fill="ink2", stroke="ink2", rx=1)          # bottom: 6 to 10
        f.rect(x0 + body, y0 + body - off - 4, mark, 8, fill="ink2", stroke="ink2", rx=1)   # right: 11 to 15
        f.rect(x0 + body - off - 4, y0 - mark, 8, mark, fill="ink2", stroke="ink2", rx=1)   # top: 16 to 20
    f.text(x0 - mark - 8, y0 + first + 4, "1", size=14, anchor="end")
    f.text(x0 + body / 2, y0 + body + mark + 26, f"{BODY_MM:.1f} mm", size=15, anchor="middle")
    f.text(x0 + body + mark + 12, y0 + body / 2, f"{BODY_MM:.1f} mm", size=15)
    f.text(x0 + body / 2, y0 - mark - 14, f"pitch {PITCH_MM:.1f} mm, 5 pins per side", size=14, color="muted",
           anchor="middle")
    sx = x0 + body + 200
    side_h = HEIGHT_MM * scale
    f.rect(sx, y0 + body / 2 - side_h / 2, body, side_h, fill="paper", stroke="line", rx=3)
    f.text(sx + body / 2, y0 + body / 2 - side_h / 2 - 14, "side view", size=14, color="muted", anchor="middle")
    f.text(sx + body + 12, y0 + body / 2 + 5, f"{HEIGHT_MM:.2f} mm", size=15)
    f.text(sx + body / 2, y0 + body / 2 + side_h / 2 + 26, f"{BODY_MM:.1f} mm", size=15, anchor="middle")
    f.note(0, y0 + body + 80, W,
           "Terminal sizes and the exposed pad are in the package drawing SOT917-7, which the data sheet refers to; "
           "use that drawing for the footprint. The SE050 and SE051 HX2QFN20 is 3.0 x 3.0 x 0.32 mm at 0.4 mm.",
           tone="slate", title="Footprint")
    return f
