"""The T=1 block in its two flavours.

Reads: One block on the I2C bus, in the order its bytes are sent, for each flavour the driver speaks. The NXP flavour
(UM11225) has NAD 0x5A from the host and 0xA5 from the chip, a one-byte LEN and at most 254 bytes of INF. The
GlobalPlatform flavour (GPC_SPE_172) has NAD 0x21 and 0x12, a two-byte big-endian LEN and up to 4089 bytes of INF.
Both end with a CRC-16 over NAD to INF; in the GP flavour it is CRC-16/X-25 sent most significant byte first (the
document's example block ends in BDA4); UM11225 gives neither the polynomial's byte order nor an example, so the link
tries both orders and keeps the first that checks. The PCB byte tells the three kinds of block apart. Every number is
read from inc/se05x_wire.hpp.
"""

from _source import WIRE, constant, frame

from figkit import Fig


def data():
    return {"nxp": frame(WIRE, "kUm11225Frame"), "gp": frame(WIRE, "kGpFrame"),
            "gp_crc": constant(WIRE, "kGpExampleCrc"), "sources": [f"{WIRE}:kUm11225Frame, kGpFrame, kGpExampleCrc"]}


def build(d):
    f = Fig("t1-frame", "One T=1 block on the bus",
            alt="Two rows of fields: the NXP flavour NAD, PCB, one-byte LEN, INF up to 254 bytes, CRC; the GP flavour "
                "NAD, PCB, two-byte LEN, INF up to 4089 bytes, CRC; and the three PCB forms.",
            width=1200, kicker="Transport", subtitle="One block is one I2C write; a reply is read after the chip "
                                                       "stops NAKing its address.",
            legend=[("blue", "prologue"), ("violet", "information field"), ("teal", "epilogue")])
    W = f.body_w
    y = 0
    for key, name, src in (("nxp", "NXP flavour", "UM11225 Table 1, p. 5"),
                           ("gp", "GlobalPlatform flavour", "GPC_SPE_172 Table 4-1, p. 33")):
        fr = d[key]
        f.region(0, y, W, 150, name, tone="slate", sub=src)
        top = f.region_inner_top(y)
        lb = fr["len_bytes"]
        fields = [("NAD", [f"0x{fr['nad_out']:02X} to chip", f"0x{fr['nad_in']:02X} to host"], "blue", 150),
                  ("PCB", ["block type", "sequence bits"], "blue", 150),
                  ("LEN", [f"{lb} byte{'s' if lb > 1 else ''}", "big endian" if lb > 1 else "0 to 254"], "blue", 150),
                  ("INF", [f"0 to {fr['max_inf']} bytes", "an APDU or a part of one"], "violet", 330),
                  ("CRC", ["2 bytes over NAD..INF",
                           f"X-25, MSB first (0x{d['gp_crc']:04X})" if key == "gp" else "order: tried both"],
                   "teal", 270)]
        x = 16
        gap = (W - 32 - sum(w for *_, w in fields)) / (len(fields) - 1)
        for title, lines, tone, w in fields:
            f.card(x, top, w, title, lines, tone=tone, accent=True)
            x += w + gap
        y += 170
    cw = (W - 40) / 3
    for i, (t, lines) in enumerate([("I-block", ["PCB 0 N(S) M 00000", "carries the APDU; M = more to come"]),
                                    ("R-block", ["PCB 100 N(R) 00 EE", "acknowledge (EE 00) or error 01, 10"]),
                                    ("S-block", ["PCB 11 x xxxxx", "control: resync, IFS, abort, WTX, reset"])]):
        f.card(i * (cw + 20), y, cw, t, lines, tone="brand")
    return f
