"""The link's states and the S-blocks it handles.

Reads: Each box is a LinkState of t1::Link, read from inc/se05x_t1.hpp. Open() reads the ATR or CIP and selects the
applet, leaving the link Idle. A command makes it InFlight: one I-block per I2C write (chained when the APDU is longer
than IFSC, each part acknowledged by an R-block), then the reply is polled. While in flight the chip may ask for more
time with S(WTX request), which the link answers with S(WTX response), counted against Config::wtx_limit; a bad
block gets an R-block and is resent at most Config::frame_retries times. A reply returns the link to Idle. A rung of
the recovery ladder that resets the chip's context leaves NeedsReselect, which selecting the applet again ends; when
the ladder is spent the link is Dead and only Close() and Open() start it again. The S-block codes are the ones of
inc/se05x_wire.hpp; 0xC6 is a chip reset in the NXP flavour and RELEASE in the GP one.
"""

from _source import T1, WIRE, enumerators, need, read

from figkit import Fig


def data():
    states = enumerators(T1, "LinkState")
    wire = read(WIRE)
    for name in ("kSResync", "kSIfs", "kSAbort", "kSWtx", "kSInterfaceSoftReset", "kUmChipReset", "kGpRelease"):
        need(rf"\b{name}\b", wire, name)
    return {"states": states, "sources": [f"{T1}:LinkState", f"{WIRE}:S-block codes"]}


def build(d):
    s = d["states"]
    if s != ["Closed", "Idle", "InFlight", "NeedsReselect", "Dead"]:
        raise SystemExit(f"figure source drift: LinkState is {s}")
    f = Fig("t1-states", "The T=1 link: states and S-blocks",
            alt="State diagram of t1::Link: Closed, Idle, InFlight, NeedsReselect and Dead, with the S-blocks "
                "handled while a command is in flight.",
            width=1200, kicker="Transport", subtitle="One command in flight at a time (errata I2C.1).",
            legend=[("teal", "normal path"), ("amber", "recovery"), ("rose", "stopped")])
    W = f.body_w
    cw, gap = 230, 72
    xs = [0, cw + gap, 2 * (cw + gap)]
    c = {}
    c["Closed"] = f.card(xs[0], 0, cw, "Closed", ["before Open(), after Close()"], tone="slate", accent=True)
    c["Idle"] = f.card(xs[1], 0, cw, "Idle", ["open, nothing in flight"], tone="teal", accent=True)
    c["InFlight"] = f.card(xs[2], 0, cw, "InFlight", ["one command exchanged"], tone="teal", accent=True)
    c["NeedsReselect"] = f.card(xs[2], 190, cw, "NeedsReselect", ["chip context was reset"], tone="amber",
                                accent=True)
    c["Dead"] = f.card(xs[2], 380, cw, "Dead", ["ladder spent"], tone="rose", accent=True)
    f.connect(c["Closed"], c["Idle"], "right", "left", label="Open()")
    f.connect(c["Idle"], c["InFlight"], "right", "left", at=0.35, bt=0.35, label="I-block")
    f.connect(c["InFlight"], c["Idle"], "left", "right", at=0.75, bt=0.75, label="reply", tone="teal")
    f.connect(c["InFlight"], c["NeedsReselect"], "bottom", "top", label="reset rung", tone="amber")
    f.connect(c["NeedsReselect"], c["Idle"], "left", "bottom", label="select applet", tone="amber")
    f.connect(c["NeedsReselect"], c["Dead"], "bottom", "top", label="ladder spent", tone="rose")
    sx = xs[2] + cw + 40
    sw = W - sx
    f.card(sx, 0, sw, "Handled in flight", [
        "S(WTX) C3 answered E3, counted by wtx_limit",
        "R-block error: resend, at most frame_retries",
        "chaining: M bit, R(N(R)) per part",
        "S(IFS) C1, S(ABORT) C2, S(RESYNC) C0",
        "interface soft reset CF: context reset",
        "0xC6: chip reset (NXP), RELEASE (GP)",
    ], tone="brand", accent=True)
    return f
