"""Opening an ECKey session.

Reads: The driver's eckey layer, the crypto port and the IoT applet. The driver first reads the chip's ECKA public
key with an attested ReadObject and verifies the attestation. The crypto port makes a fresh ephemeral P-256 key pair
for this session only and signs the request with the host's long-term key, whose public half is the ECKey
authentication object on the chip. ECKeySessionInternalAuthenticate (84 88) carries the parameters (tag A6), the
ephemeral public key (tag 7F49) and the signature (tag 5F37). The chip answers a 16-byte challenge and a 16-byte
receipt. The host computes the shared secret, derives the master key (the first 16 bytes of SHA-256 over a counter,
the secret, the chip's random and the parameters) and the session keys by CMAC, and checks the receipt in constant
time before it trusts the session. The ephemeral private key and the master key are wiped. AN12543 pp. 22-23, 33-34,
72-73; no vector confirms the derivation yet, so it is built behind a flag.
"""

from _seq import sequence

from figkit import Fig

SOURCES = ["inc/se05x_eckey.hpp"]


def build(_d):
    f = Fig("eckey-session", "ECKey session: opening it",
            alt="Sequence diagram: attested read of the chip ECKA key, ephemeral key in the crypto port, "
                "ECKeySessionInternalAuthenticate, challenge and receipt, receipt check, session keys, wipe.",
            width=1200, kicker="Secure channel", subtitle="The host side of the key agreement lives in the crypto port.",
            legend=[("brand", "command"), ("teal", "reply"), ("amber", "check"), ("slate", "wipe")])
    lanes = [("eckey::Session", "the driver", "brand"), ("Crypto port", "ephemeral and host keys", "violet"),
             ("SE05x IoT applet", "ECKey auth object", "teal")]
    rows = [
        ("msg", 0, 2, "attested ReadObject of the ECKA public key", False),
        ("msg", 2, 0, "public key, attestation", True),
        ("act", 0, "Verify the attestation before using the key (AN13030 p. 15).", "amber"),
        ("msg", 0, 1, "GenerateP256(): ephemeral key, one per session", False),
        ("msg", 0, 1, "EcdsaP256Sign(): sign A6 and 7F49", False),
        ("msg", 0, 2, "84 88 00 00: A6, 7F49, 5F37", False),
        ("msg", 2, 0, "85: SE challenge, 86: receipt", True),
        ("msg", 0, 1, "EcdhP256(), SHA-256, AesCmac: master and session keys", False),
        ("act", 0, "Receipt = CMAC(S-RMAC, A6 and 7F49): compare in constant time, else SecureChannelError.",
         "amber"),
        ("act", 1, "Wipe the ephemeral private key and the master key.", "slate"),
        ("msg", 0, 2, "wrapped APDU: counter from 1, IV = AES(counter)", False),
    ]
    y = sequence(f, lanes, rows)
    f.note(0, y + 10, f.body_w, "Config::verify_eckey_receipt is on by default; the receipt is what proves the "
           "chip holds the session keys (AN13030 p. 5 and pp. 156-157).", tone="slate", title="Receipt")
    return f
