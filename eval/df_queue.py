import os
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import glob

files = glob.glob("../*/*/*/df_fuzz/*/out/default/queue/*")

times = {}

for f in files:
    t = int(f.split("time:")[-1].split(",")[0])//1000
    print(f,t)
    if t not in times: times[t] = 0
    times[t] += 1

print(times)
keys, values = zip(*sorted(times.items()))

# 2. cumulative sum
cum_values = np.cumsum(values)

# optional: normalize to [0,1] for a true CDF
cum_values = cum_values / cum_values[-1]

matplotlib.rcParams['mathtext.fontset'] = 'custom'
matplotlib.rcParams['mathtext.rm'] = 'Bitstream Vera Sans'
matplotlib.rcParams['mathtext.it'] = 'Bitstream Vera Sans:italic'
matplotlib.rcParams['mathtext.bf'] = 'Bitstream Vera Sans:bold'
matplotlib.rcParams['mathtext.fontset'] = 'stix'
matplotlib.rcParams['font.family'] = 'STIXGeneral'
# 3. plot
plt.figure()
plt.plot(keys, cum_values)
plt.gca().margins(y=0, x=0.005)
#plt.xlabel("Key")
#plt.ylabel("Cumulative fraction")
#plt.title("Cumulative Distribution")
#plt.grid(True)
plt.savefig("cdf.png", dpi=300, bbox_inches="tight")
# plt.show()  # optional
plt.close()
