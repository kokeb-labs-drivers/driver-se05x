"""Trust boundaries.

Reads: Three zones from right to left. Inside the chip: the private keys, the policies, the counters, the RNG and the
attestation key; the chip enforces every access rule. The bus between host and chip carries APDUs in clear unless a
secure channel (platform SCP03, an AESKey or an ECKey session) wraps them; anyone with a probe on SDA and SCL sees and
can inject plain traffic. The host MCU runs this driver, which is a courier: it holds no long-term secret except the
platform SCP03 keys, and those only as handles in the crypto port. The verifier, far left, checks attestations and
signatures with public keys only. Each arrow says what crosses the boundary.
"""

from figkit import Fig

SOURCES = ["inc/se05x_ports.hpp", "inc/se05x_secret.hpp"]


def build(_d):
    f = Fig("trust-boundaries", "Trust boundaries",
            alt="Zones: remote verifier, host MCU with the driver and crypto port, the I2C bus, and the chip with keys, "
                "policies, counters and RNG; arrows show attestations, signatures and wrapped APDUs crossing.",
            width=1200, kicker="Security model", subtitle="The chip is the only place a long-term secret is created "
                                                           "or used.",
            legend=[("teal", "trusted for secrets"), ("amber", "trusted for availability only"),
                    ("rose", "untrusted")])
    W = f.body_w
    zw = (W - 60) / 4
    h = 300
    zones = [("Verifier", "rose", ["public keys only", "checks attestations", "checks signatures"]),
             ("Host MCU", "amber", ["this driver: a courier", "crypto port: SCP03 key handles",
                                    "ephemeral ECKey key, wiped"]),
             ("I2C bus", "rose", ["plain APDUs unless wrapped", "probe can read and inject",
                                  "SCP03 or ECKey session wraps"]),
             ("SE05x", "teal", ["private keys, never exported", "policies enforced on chip",
                                "counters, RNG (DRG.4)", "attestation key"])]
    boxes = []
    for i, (t, tone, lines) in enumerate(zones):
        x = i * (zw + 20)
        f.region(x, 0, zw, h, t, tone=tone)
        boxes.append(f.card(x + 14, f.region_inner_top(0), zw - 28, t, lines, tone=tone))
    f.edge([(boxes[3].x, boxes[3].b + 30), (boxes[0].r, boxes[3].b + 30)], tone="teal",
           label="signatures, attested values (public)")
    return f
