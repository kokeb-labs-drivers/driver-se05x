"""Opening a platform SCP03 channel.

Reads: Three parties, left to right: the driver's scp03 layer, the crypto port that holds the static platform keys
as handles, and the chip's card manager. The driver sends INITIALIZE UPDATE with a host challenge; the chip answers
with its challenge and card cryptogram. The crypto port derives the session keys from the static keys (the driver
never sees them) and the driver checks the card cryptogram in constant time. EXTERNAL AUTHENTICATE carries the host
cryptogram and the security level; when platform SCP is required the level must be full C-MAC, C-ENC, R-MAC and
R-ENC (AN12543 SetPlatformSCPRequest, p. 75). Every later APDU is wrapped (C-MAC, C-ENC) and every reply checked
(R-MAC, R-ENC); a failed check closes the channel and wipes the keys. The normative SCP03 text is the
GlobalPlatform SCP03 amendment, which is not in this driver's source set: the byte detail follows AN12543 p. 72 and
the middleware oracle.
"""

from _seq import sequence
from _source import enumerators

from figkit import Fig


def data():
    return {"levels": enumerators("inc/se05x_scp03.hpp", "SecurityLevel"),
            "sources": ["inc/se05x_scp03.hpp:SecurityLevel"]}


def build(d):
    f = Fig("scp03-session", "Platform SCP03: opening the channel",
            alt="Sequence diagram: INITIALIZE UPDATE, card cryptogram check in the crypto port, EXTERNAL "
                "AUTHENTICATE, then wrapped commands with MAC and encryption both ways.",
            width=1200, kicker="Secure channel", subtitle="Static keys stay behind KeyRef handles in the crypto port.",
            legend=[("brand", "command"), ("teal", "reply"), ("amber", "check that closes the channel on failure")])
    lanes = [("scp03::Channel", "the driver", "brand"), ("Crypto port", "static keys as KeyRef", "violet"),
             ("SE05x card manager", "ISD, platform keys", "teal")]
    rows = [
        ("msg", 0, 1, "Random(): 8-byte host challenge", False),
        ("msg", 0, 2, "INITIALIZE UPDATE (host challenge)", False),
        ("msg", 2, 0, "card challenge, card cryptogram", True),
        ("msg", 0, 1, "derive S-ENC, S-MAC, S-RMAC (AesCmac)", False),
        ("act", 0, "Compare the card cryptogram in constant time; a mismatch is SecureChannelError.", "amber"),
        ("msg", 0, 2, "EXTERNAL AUTHENTICATE (host cryptogram, level)", False),
        ("msg", 2, 0, "9000: channel open", True),
        ("msg", 0, 2, "wrapped APDU: C-MAC, C-ENC, counter", False),
        ("msg", 2, 0, "reply: R-MAC, R-ENC", True),
        ("act", 0, "Check R-MAC on every reply, short ones too; on failure close and wipe.", "amber"),
    ]
    y = sequence(f, lanes, rows)
    f.note(0, y + 10, f.body_w, "Security levels of the contract: " + ", ".join(d["levels"]) +
           ". Errata JOS.2: on applet 3.x the encryption counter does not advance for a command without data, so "
           "the channel adds data as the vendor does (errata section 3.13, p. 11).", tone="slate", title="Levels")
    return f
