"""Rendering of the paper's tables from measured results.

Every experiment that corresponds to a table writes three files into its result
directory:  <name>.txt (human readable), <name>.csv (machine readable) and
<name>.tex (the LaTeX body, so the table can be dropped into the paper).
"""

import csv
import json
import os

PAPER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "data", "paper_tables.json")


def paper_tables():
    with open(PAPER) as f:
        return json.load(f)


def render_txt(headers, rows, title=None, notes=()):
    widths = [len(str(h)) for h in headers]
    for r in rows:
        if r is None:                      # horizontal rule
            continue
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(str(c)))
    sep = "-+-".join("-" * w for w in widths)
    out = []
    if title:
        out += [title, "=" * len(title), ""]
    out.append(" | ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers)))
    out.append(sep)
    for r in rows:
        if r is None:                      # horizontal rule
            out.append(sep)
            continue
        out.append(" | ".join(str(c).ljust(widths[i]) for i, c in enumerate(r)))
    if notes:
        out.append("")
        out += [f"note: {n}" for n in notes]
    return "\n".join(out) + "\n"


def render_tex(headers, rows, caption="", label=""):
    cols = "l" + "r" * (len(headers) - 1)
    out = ["\\begin{table}[t]", "\\centering", f"\\begin{{tabular}}{{{cols}}}", "\\toprule"]
    out.append(" & ".join(str(h) for h in headers) + " \\\\")
    out.append("\\midrule")
    for r in rows:
        if r is None:
            out.append("\\midrule")
            continue
        out.append(" & ".join(str(c) for c in r) + " \\\\")
    out += ["\\bottomrule", "\\end{tabular}"]
    if caption:
        out.append(f"\\caption{{{caption}}}")
    if label:
        out.append(f"\\label{{{label}}}")
    out.append("\\end{table}")
    return "\n".join(out) + "\n"


def write(result_dir, name, headers, rows, title=None, notes=(), caption="", label=""):
    os.makedirs(result_dir, exist_ok=True)
    txt = render_txt(headers, rows, title=title, notes=notes)
    with open(os.path.join(result_dir, name + ".txt"), "w") as f:
        f.write(txt)
    with open(os.path.join(result_dir, name + ".csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for r in rows:
            if r is not None:
                w.writerow(r)
    with open(os.path.join(result_dir, name + ".tex"), "w") as f:
        f.write(render_tex(headers, rows, caption=caption, label=label))
    print(txt)
    return txt


def cmp_cell(measured, paper):
    """'measured (paper: X)' - or just the value when they agree."""
    if measured == paper:
        return str(measured)
    return f"{measured} (paper: {paper})"
