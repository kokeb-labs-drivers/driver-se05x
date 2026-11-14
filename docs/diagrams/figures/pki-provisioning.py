"""The device-side PKI provisioning flow.

Reads: Left to right, top row once in the factory, bottom row at every boot. 1. The chip generates the key pair; only
the public key comes out (ReadPublicKey). 2. BuildCsr writes the request and the chip signs its digest
(DeviceSigner); VerifyCsr checks it against its own key. 3. The CA, outside the driver, issues the certificate.
4. StoreCertificate writes the certificate and the CA certificate (the trust anchor) into new binary objects with
read-only policies, in one WriteBinary each, and reads them back. At boot: ReadCertificate and LoadTrustAnchor read
them, VerifyChain checks signature, names, time, constraints and path length with the caller's clock, and the
verified key is the chip's own. The CA, revocation and TLS are outside the driver.
"""

from figkit import Fig

SOURCES = ["inc/se05x_pki_csr.hpp", "inc/se05x_pki_device.hpp", "inc/se05x_pki_verify.hpp"]


def build(_d):
    f = Fig("pki-provisioning", "Device certificates: provision once, verify at boot",
            alt="Factory row: generate the key in the chip, build and sign the CSR on the chip, the CA outside issues "
                "the certificate, store it and the trust anchor read-only. Boot row: read both back and verify the "
                "chain with the caller's time.",
            width=1200, kicker="PKI", subtitle="The private key never leaves the chip; the driver never acts as a CA.",
            legend=[("teal", "inside the chip"), ("brand", "this driver (se05x::pki)"),
                    ("rose", "outside the driver")])
    W = f.body_w
    gap = 40
    cw = (W - 3 * gap) / 4
    factory = [("1. Generate", ["GenerateEcKey (in the chip)", "ReadPublicKey: public half"], "teal"),
               ("2. Request", ["BuildCsr + DeviceSigner", "VerifyCsr: self check"], "brand"),
               ("3. Issue", ["your CA (not the driver)", "returns the certificate"], "rose"),
               ("4. Store", ["StoreCertificate x2", "read-only policy, read back"], "brand")]
    top = [f.card(i * (cw + gap), 0, cw, t, l, tone=tone, accent=True) for i, (t, l, tone) in enumerate(factory)]
    for a, b in zip(top, top[1:]):
        f.connect(a, b, "right", "left")
    y = max(b.b for b in top) + 70
    boot = [("Read", ["ReadCertificate", "LoadTrustAnchor"], "brand"),
            ("Verify", ["VerifyChain(now, anchors)", "signature, names, time, path"], "brand"),
            ("Use", ["the verified key is the chip's", "sign with DeviceSigner"], "teal")]
    bw = (W - 2 * gap) / 3
    bottom = [f.card(i * (bw + gap), y, bw, t, l, tone=tone, accent=True) for i, (t, l, tone) in enumerate(boot)]
    for a, b in zip(bottom, bottom[1:]):
        f.connect(a, b, "right", "left")
    f.edge([(top[3].x + cw / 2, top[3].b), (top[3].x + cw / 2, y - 30), (bottom[0].x + bw / 2, y - 30),
            (bottom[0].x + bw / 2, y)], tone="brand", label="at every boot")
    return f
