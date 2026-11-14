"""A small sequence-diagram layout on figkit: lanes with life lines, messages as arrows, steps as notes."""


def sequence(f, lanes, rows, lane_w=230, row_h=58, top=0):
    """Draw ``lanes`` (title, subtitle, tone) and ``rows``.

    A row is ``("msg", from_lane, to_lane, label, dashed)`` for an arrow or ``("act", lane, text, tone)`` for a step
    a party takes on its own. Returns the y below the last row.
    """
    W = f.body_w
    n = len(lanes)
    gap = (W - n * lane_w) / max(n - 1, 1)
    xs = [i * (lane_w + gap) + lane_w / 2 for i in range(n)]
    heads = []
    for i, (title, sub, tone) in enumerate(lanes):
        heads.append(f.card(xs[i] - lane_w / 2, top, lane_w, title, [sub], tone=tone, accent=True, center=True))
    y = max(h.b for h in heads) + 30
    end_y = y + row_h * len(rows)
    for x in xs:
        f.line([(x, y - 26), (x, end_y)], color="rail", sw=1.2, dash="4 5")
    for r in rows:
        if r[0] == "msg":
            _, a, b, label, dashed = r
            x1, x2 = xs[a], xs[b]
            sgn = 1 if x2 > x1 else -1
            f.edge([(x1 + 6 * sgn, y + 30), (x2 - 6 * sgn, y + 30)], tone="brand" if not dashed else "teal",
                   label=label, dashed=dashed, label_dy=-16)
        else:
            _, a, text, tone = r
            w = lane_w + gap * 0.8
            x = min(max(xs[a] - w / 2, 0), W - w)
            f.note(x, y + 6, w, text, tone=tone)
        y += row_h
    return y
