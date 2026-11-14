"""Which variant, applet and authentication.

Reads: Read top to bottom; take the first question you answer yes. Certification needs come first: FIPS 140-3 Level 3
is the SE052F; FIPS 140-2 with SCP03 mandatory is the SE050F. Then interfaces: NFC commissioning and Matter (PAKE) is
the SE051H, UWB the SE051W. Field update of the applet (SEMS Lite) is the SE051A or C. Otherwise the SE050 by
algorithm set: E for AES-GCM and CCM and Curve448 (applet 7.x), C for ECC and RSA, A for ECC only, B for RSA only,
D for ECC with MIFARE DESFire. The SE051P runs a customer applet and has no IoT applet, so this driver does not apply.
The bottom row is the authentication choice: platform SCP03 whenever the bus can be probed, an ECKey session to bind a
host, a UserID session only under a trusted host OS, since it has no secure messaging. The driver reads the real
capabilities at Open() and never trusts the part name.
"""

from figkit import Fig

SOURCES = ["inc/se05x_types.hpp", "inc/se05x_caps.hpp"]


def build(_d):
    f = Fig("variant-decision", "Choosing a variant, an applet and an authentication",
            alt="Decision tree: FIPS 140-3 leads to SE052F, FIPS 140-2 to SE050F, NFC and Matter to SE051H, UWB to "
                "SE051W, field updates to SE051A or C, else SE050E, C, A, B or D by algorithms; then platform SCP03, "
                "ECKey or UserID sessions.",
            width=1200, kicker="Decide", subtitle="Take the first yes. Capabilities are read from the chip at Open().",
            legend=[("brand", "question"), ("teal", "variant"), ("violet", "authentication")])
    W = f.body_w
    qw, aw, rh = 560, 380, 76
    qs = [("FIPS 140-3 Level 3 needed?", "SE052F", "applet 7.2.22, HVQFN20, no ENA"),
          ("FIPS 140-2, SCP03 always on?", "SE050F", "applet 3.6.0"),
          ("NFC commissioning or Matter PAKE?", "SE051H", "applet 7.x"),
          ("UWB?", "SE051W", "applet 7.x"),
          ("Field update of the applet?", "SE051A or SE051C", "applet 6.0 or 7.2, SEMS Lite"),
          ("AES-GCM or CCM, Curve448?", "SE050E", "applet 7.2, 1 MHz without stretching"),
          ("ECC and RSA, more cloud keys?", "SE050C", "applet 3.x"),
          ("RSA only? DESFire?", "SE050B or SE050D", "applet 3.x"),
          ]
    y = 0
    prev = None
    for q, a, sub in qs:
        qb = f.card(0, y, qw, q, [], tone="brand", accent=True)
        ab = f.card(W - aw, y, aw, a, [sub], tone="teal", accent=True)
        f.connect(qb, ab, "right", "left", label="yes")
        if prev:
            f.connect(prev, qb, "bottom", "top", at=0.15, bt=0.15, label="no")
        prev = qb
        y += rh
    last = f.card(0, y, qw, "Otherwise", [], tone="brand", accent=True)
    f.connect(prev, last, "bottom", "top", at=0.15, bt=0.15, label="no")
    ab = f.card(W - aw, y, aw, "SE050A", ["ECC only, applet 3.x"], tone="teal", accent=True)
    f.connect(last, ab, "right", "left")
    y += rh + 30
    cw = (W - 40) / 3
    for i, (t, lines) in enumerate([("Platform SCP03", ["whenever the I2C bus can be probed"]),
                                    ("ECKey session", ["bind one host to the chip"]),
                                    ("UserID session", ["trusted host OS only: no secure messaging"])]):
        f.card(i * (cw + 20), y, cw, t, lines, tone="violet", accent=True)
    return f
