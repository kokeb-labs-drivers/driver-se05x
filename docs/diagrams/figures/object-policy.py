"""Secure objects, policies, authentication objects and sessions.

Reads: Every key or data item on the chip is a secure object: a 4-byte identifier, a class (ObjectClass of
inc/se05x_ids.hpp), a lifetime (persistent, or transient: the content is lost at reset or deselect) and an origin
(generated inside, written from outside, or provisioned by the vendor; attestation reports it). At creation the
object gets a policy set: each policy names one authentication object and the operations it may do (the Rule
enumeration of inc/se05x_policy_types.hpp, 9 to 53 bytes per policy; AN12543 Table 63). An authentication object is
itself a secure object (a UserID, an AES key or an EC key); a session opened with it (at most 2 at a time) is what a
policy checks. The policy builder only builds rules valid for the class and generation, and the facade uses the
strict profile only.
"""

from _source import IDS, POLICY, enumerators

from figkit import Fig


def data():
    return {"classes": enumerators(IDS, "ObjectClass"), "origins": enumerators(IDS, "Origin"),
            "lifetimes": enumerators(IDS, "Lifetime"), "rules": enumerators(POLICY, "Rule"),
            "sources": [f"{IDS}:ObjectClass, Origin, Lifetime", f"{POLICY}:Rule"]}


def build(d):
    f = Fig("object-policy", "Objects, policies and sessions",
            alt="An authentication object opens a session; a policy of an object names that authentication object "
                "and the rules it allows; the chip checks the policy on every command.",
            width=1200, kicker="Object model", subtitle="The chip enforces the policy; the host never decides access.",
            legend=[("blue", "secure object"), ("violet", "policy"), ("teal", "session")])
    W = f.body_w
    cw = (W - 200) / 3
    obj = f.card(0, 0, cw, "Secure object", [
        "ObjectId: 4 bytes, big endian",
        "class: " + ", ".join(d["classes"][:5]) + ", ...",
        "lifetime: " + ", ".join(d["lifetimes"]),
        "origin: " + ", ".join(d["origins"]),
    ], tone="blue", accent=True)
    pol = f.card(cw + 100, 0, cw, "Policy set", [
        "per policy: auth object id + 4-byte rule header",
        f"{len(d['rules'])} rules in the contract, e.g. " + ", ".join(d["rules"][:4]),
        "9 to 53 bytes each; built by PolicyBuilder only",
    ], tone="violet", accent=True)
    auth = f.card(2 * (cw + 100), 0, cw, "Authentication object", [
        "UserID, AESKey (SCP03) or ECKey",
        "or a reserved one: Transport, PlatformScp, Feature, FactoryReset",
    ], tone="blue", accent=True)
    ses = f.card(2 * (cw + 100), 240, cw, "Session", ["CreateSession: 8-byte id", "at most 2 open, plus the default"],
                 tone="teal", accent=True)
    cmd = f.card(cw + 100, 240, cw, "Command", ["the chip checks the object's policy",
                                               "for the session's auth object"], tone="slate", accent=True)
    f.connect(obj, pol, "right", "left", label="has")
    f.connect(pol, auth, "right", "left", label="names")
    f.connect(auth, ses, "bottom", "top", label="opens")
    f.connect(ses, cmd, "left", "right", label="runs")
    f.connect(cmd, obj, "left", "bottom", label="on", tone="slate")
    return f
