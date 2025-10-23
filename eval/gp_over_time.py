data = {
    2015: {
        "kinibi": {"gp": 0, "nongp": 34},
        "qsee": {"gp": 0, "nongp": 11},
        "trustedcore": {"gp": 11, "nongp": 0},
    },
    2020: {
        "kinibi": {"gp": 2, "nongp": 32},
        "qsee": {"gp": 6, "nongp": 47},
        "trustedcore": {"gp": 11, "nongp": 0},
        # "itrustee": {
        #    "gp": 20,
        #    "nongp": 0
        # },
        "teegris": {"gp": 25, "nongp": 0},
        "beanpod": {"gp": 9, "nongp": 0},
    },
    2025: {
        # "itrustee": {
        #    "gp": 20,
        #    "nongp": 0
        # },
        "kinibi": {"gp": 10, "nongp": 31},
        "qsee": {"gp": 3, "nongp": 38},
        "teegris": {"gp": 34, "nongp": 0},
        "beanpod": {"gp": 11, "nongp": 0},
        "mitee": {"gp": 16, "nongp": 0},
        "t6": {"gp": 6, "nongp": 0},
    },
}

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

years = sorted(data.keys())
vendors = sorted({v for year in data.values() for v in year})
gp = {y: [data[y].get(v, {"gp": 0})["gp"] for v in vendors] for y in years}
nongp = {y: [data[y].get(v, {"nongp": 0})["nongp"] for v in vendors] for y in years}

# --- Plot setup ---
fig, ax = plt.subplots(figsize=(6, 6))
x = [0.3, 0.6, 0.9]
bar_width = 0.2

colors = plt.cm.tab20.colors
color_map = {v: colors[i % len(colors)] for i, v in enumerate(vendors)}

for v, c in color_map.items():
    print(f'\\definecolor{{{v}plt}}{{rgb}}{{{",".join(str(a) for a in list(c))}}}')

# --- Draw stacked vertical bars ---
all_tas = 0
for i, year in enumerate(years):
    gp_cum = 0
    nongp_cum = 0
    for v in vendors:
        gpv = gp[year][vendors.index(v)]
        ngpv = nongp[year][vendors.index(v)]
        color = color_map[v]

        # Upward for GP-compliant
        if gpv:
            ax.bar(
                x[i],
                gpv,
                bottom=gp_cum,
                color=color,
                width=bar_width,
                label=v if i == 0 else "",
            )
            gp_cum += gpv

        # Downward for non-GP
        if ngpv:
            ax.bar(
                x[i],
                -ngpv,
                bottom=-nongp_cum,
                color=color,
                width=bar_width,
                label=v if i == 0 else "",
            )
            nongp_cum += ngpv
    all_tas += nongp_cum + gp_cum
    print(f"gp compl: {year} {gp_cum/(gp_cum+nongp_cum)}")

print(f"all TAs: {all_tas}")

# --- Style ---
ax.axhline(0, color="black", linewidth=1.5)
ax.set_xticks(x)
ax.set_xticklabels([])
# ax.set_ylabel("Number of TAs (Down: Non-GP, Up: GP)")
# ax.set_xlabel("Year")
# ax.set_title("GP-Compliant vs Non-Compliant TAs per Year (per TEE Vendor)")
# ax.legend(loc="upper center", ncol=4, bbox_to_anchor=(0.5, -0.15))
# ax.grid(axis="y", linestyle="--", alpha=0.5)
ax.set_yticklabels([])
plt.savefig("gp_over_time.pdf", format="pdf", bbox_inches="tight")
