"""The irreversible-operation flow.

Reads: Left to right. The build must define SE05X_ENABLE_IRREVERSIBLE, or none of these calls exists. The caller asks
irreversible::Operations for a Plan of one operation: the Plan sends nothing, checks the arguments, the capabilities
and the role, and says what will change. The caller shows the Plan to a person and builds a Confirmation of the same
operation from its phrase. Apply() takes both; a Plan of another operation, a phrase of another operation or a Plan
that was not prepared is refused before any byte is sent (Error::IrreversibleNotConfirmed). The operation tags are
read from inc/se05x_confirm.hpp; the two PERSO operations live on perso::Perso and follow the same flow.
"""

from _source import CONFIRM, structs_with_phrase

from figkit import Fig


def data():
    return {"ops": structs_with_phrase(CONFIRM), "sources": [f"{CONFIRM}:operation tags"]}


def build(d):
    f = Fig("irreversible-flow", "Irreversible operations: plan, confirm, apply",
            alt="Four steps: build flag, Plan (no I/O), Confirmation from the operation's phrase, Apply; and the list "
                "of the operations that need them.",
            width=1200, kicker="Safety", subtitle="Nothing irreversible is one call away.",
            legend=[("slate", "build time"), ("brand", "no I/O"), ("rose", "sends")])
    W = f.body_w
    gap = 40
    cw = (W - 3 * gap) / 4
    steps = [("1. Build flag", ["SE05X_ENABLE_IRREVERSIBLE", "off by default"], "slate"),
             ("2. Plan<Op>", ["Operations::Plan...()", "checks, says what changes"], "brand"),
             ("3. Confirmation<Op>", ["built from Op::kPhrase", "a person reads the Plan"], "brand"),
             ("4. Apply", ["Apply(plan, confirmation)", "the only call that sends"], "rose")]
    boxes = [f.card(i * (cw + gap), 0, cw, t, l, tone=tone, accent=True) for i, (t, l, tone) in enumerate(steps)]
    for a, b in zip(boxes, boxes[1:]):
        f.connect(a, b, "right", "left")
    y = max(b.b for b in boxes) + 40
    f.region(0, y, W, 60 + 34 * ((len(d["ops"]) + 3) // 4), f"{len(d['ops'])} operations", tone="rose")
    top = f.region_inner_top(y)
    f.chips(16, top, W - 32, d["ops"], tone="rose")
    return f
