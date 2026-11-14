"""The recovery ladder.

Reads: When an exchange fails the link climbs these rungs in order, read from the Rung enumeration in
inc/se05x_t1.hpp, and stops at the first that works. Each rung is bounded and is never repeated without limit.
Resending the last block keeps everything. A resync and an interface soft reset keep the chip's state but drop the
exchange in progress. Selecting the applet again closes the applet sessions. The chip reset (the NXP-flavour S-block
0xC6, or the reset port in the GP flavour, where 0xC6 means RELEASE) also clears transient objects, and is the only
answer to SW 0x66A6. The power cycle needs the reset port (ENA with VOUT wired to VCC on the SE050 and SE051) and is
the only cure for errata I2C.1. After any rung past the resend, the driver forgets every session and the caller
authenticates again (Error::Resynced).
"""

from _source import T1, enumerators

from figkit import Fig

WHAT = {
    "ResendBlock": ("R-block NAK, resend the last block", "keeps everything", "teal"),
    "Resync": ("S(RESYNC) C0", "the exchange in progress is lost", "teal"),
    "InterfaceReset": ("S(interface soft reset) CF", "protocol context reset; lines high 1 ms", "amber"),
    "Reselect": ("SELECT the IoT applet again", "applet sessions closed", "amber"),
    "ChipReset": ("chip reset: S(0xC6) NXP, reset port GP", "sessions and transient objects lost; ends 0x66A6",
                  "rose"),
    "PowerCycle": ("reset port: supply or ENA off and on", "needs a ResetPort; clears I2C.1", "rose"),
}


def data():
    return {"rungs": enumerators(T1, "Rung"), "sources": [f"{T1}:Rung"]}


def build(d):
    f = Fig("recovery-ladder", "The recovery ladder",
            alt="Six rungs from top to bottom: resend the block, resync, interface soft reset, reselect the applet, "
                "chip reset and power cycle, each with what it costs.",
            width=1200, kicker="Transport", subtitle="Climbed in order, each rung bounded; past the first, sessions are "
                                                       "gone and the caller re-authenticates.",
            legend=[("teal", "state kept"), ("amber", "sessions lost"), ("rose", "chip reset")])
    W = f.body_w
    y = 0
    prev = None
    for i, r in enumerate(d["rungs"]):
        if r not in WHAT:
            raise SystemExit(f"figure source drift: rung {r} has no description")
        how, cost, tone = WHAT[r]
        box = f.card(60 + i * 40, y, W - 60 - 5 * 40, f"{i + 1}. {r}", [how, cost], tone=tone, accent=True)
        if prev:
            f.connect(prev, box, "bottom", "top", at=0.1, bt=0.05, label="still failing")
        prev = box
        y = box.b + 34
    f.note(0, y, W, "Ladder spent: Error::TransportDead and the link is Dead. A rung that needs a port you did not "
           "give is skipped: without a ResetPort the ladder ends at the chip reset.", tone="rose", title="The end")
    return f
