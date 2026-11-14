"""The chip's lifecycle settings and who may change them.

Reads: The device-wide settings of the IoT applet, each changed by one command that the chip accepts only in a
session opened with one reserved authentication object (the AuthRole of inc/se05x_lifecycle.hpp, checked by
RequiredRole() before anything is sent). Transport lock: SetLockState from a Transport session; while locked the
chip answers only GetVersion, ReadState, the read of the unique id, GetRandom and CreateSession (AN12543 Table 19);
the persistent lock survives resets and is lifted only from a Transport session again. Platform SCP required:
SetPlatformSCPRequest from a PlatformScp session; from then on every command needs full platform SCP03. Restricted
object creation: DisableObjectCreation; the persistent form cannot be undone. Applet features: SetAppletFeatures from
a Feature (ECKey) session. Factory reset: DeleteAll from a FactoryReset session removes every object except the
provisioned ones; its reply is not wrapped and the session ends. ReadState reads the first three at any time. Red
arrows are the operations the driver treats as irreversible: they exist only with SE05X_ENABLE_IRREVERSIBLE and need
a Plan and a Confirmation.
"""

from _source import LIFECYCLE, enumerators, need, read

from figkit import Fig


def data():
    roles = enumerators(LIFECYCLE, "AuthRole")
    text = read(LIFECYCLE)
    for cmd in ("SetLockState", "SetPlatformScpRequest", "SetAppletFeatures", "DeleteAll"):
        need(rf"Command::{cmd}\b", text, f"RequiredRole({cmd})")
    return {"roles": roles, "sources": [f"{LIFECYCLE}:AuthRole", f"{LIFECYCLE}:RequiredRole"]}


def build(d):
    f = Fig("lifecycle", "Lifecycle settings and the roles that change them",
            alt="Central card: the chip in normal use. Around it: transport locked, platform SCP required, object "
                "creation restricted, applet features changed and factory reset, each reached by one command from "
                "one reserved role; irreversible ones in red.",
            width=1200, kicker="Lifecycle", subtitle="Roles: " + ", ".join(d["roles"]),
            legend=[("teal", "reversible"), ("rose", "irreversible: Plan and Confirmation"),
                    ("amber", "ends the session")])
    W = f.body_w
    cw = 300
    mid = f.card((W - cw) / 2, 200, cw, "In use", ["objects per their policies", "ReadState any time"],
                 tone="teal", accent=True)
    lock = f.card(0, 0, cw, "Transport locked", ["Transport role: SetLockState",
                                                 "only 5 commands answered"], tone="slate", accent=True)
    scp = f.card(W - cw, 0, cw, "Platform SCP required", ["PlatformScp role", "full SCP03 from then on"],
                 tone="rose", accent=True)
    restr = f.card(0, 400, cw, "Creation restricted", ["DisableObjectCreation", "persistent: cannot be undone"],
                   tone="rose", accent=True)
    feat = f.card(W - cw, 400, cw, "Features changed", ["Feature role (ECKey)", "SetAppletFeatures"],
                  tone="rose", accent=True)
    fr = f.card((W - cw) / 2, 0, cw, "Factory reset", ["FactoryReset role: DeleteAll", "provisioned objects stay"],
                tone="amber", accent=True)
    f.connect(mid, lock, "left", "bottom", at=0.3, label="lock (transient or persistent)", tone="rose")
    f.connect(lock, mid, "bottom", "left", at=0.2, bt=0.75, label="unlock: Transport role", tone="teal")
    f.connect(mid, scp, "right", "bottom", at=0.3, label="require", tone="rose")
    f.connect(mid, restr, "left", "top", at=0.9, label="restrict", tone="rose")
    f.connect(mid, feat, "right", "top", at=0.9, label="set features", tone="rose")
    f.connect(mid, fr, "top", "bottom", label="DeleteAll", tone="rose")
    return f
