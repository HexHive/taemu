"""Deployment settings shared by the evaluation scripts.

The scripts originally assumed that the repository lives at
/root/TA_GP_emulator, that the emulator image is called `ta_emu`, and that they
are started from the repository root on the *host*. All three assumptions are
now configurable so the artifact runs from any checkout and from inside the
artifact-evaluation container:

    TAEMU_ROOT    absolute path of the repository on the docker *host*
                  (defaults to the parent directory of this file)
    TAEMU_IMAGE   name of the emulator image (default: ta_emu)

Note that TAEMU_ROOT must always be the path *on the host*, because the
emulator containers are started as siblings (via the docker socket), and the
docker daemon resolves bind mounts on the host filesystem.
"""

import os
import subprocess
import sys

DEFAULT_IMAGE = "ta_emu"


def repo_root():
    root = os.environ.get("TAEMU_ROOT")
    if root:
        return os.path.abspath(root)
    # eval/ lives directly below the repository root
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def image():
    return os.environ.get("TAEMU_IMAGE", DEFAULT_IMAGE)


def to_emulator_rel(path):
    """Rewrite a repository path so the emulator scripts (which run with
    /srv/emulator as their working directory) can use it."""
    rel = os.path.relpath(os.path.abspath(path), repo_root())
    return os.path.join("..", rel)


def emu_prefix():
    """Prefix of the worker container names.

    The workers used to be called emu_0..emu_N globally, so two deduplication
    runs could not proceed at the same time. TAEMU_EMU_PREFIX gives each run its
    own namespace.
    """
    return os.environ.get("TAEMU_EMU_PREFIX", "emu_")


def emu_name(i):
    return f"{emu_prefix()}{i}"


def docker_available():
    try:
        return subprocess.run(
            ["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        ).returncode == 0
    except FileNotFoundError:
        return False


def require_docker():
    """These scripts orchestrate emulator containers, so they need a docker
    daemon. Running them inside the AE container is fine as long as the docker
    socket is forwarded (see ae/ae.sh)."""
    if docker_available():
        return
    print("[-] ERROR! No usable docker daemon.")
    print("    Run on the host, or inside a container started with")
    print("    -v /var/run/docker.sock:/var/run/docker.sock and TAEMU_ROOT set.")
    sys.exit(3)


def emulator_container_cmd(name, extra=()):
    """Command line that starts a long-running emulator container."""
    return (
        f"docker run -d --name {name} --network host -it "
        f"-v {repo_root()}:/srv -w /srv/emulator "
        f"-v /dev/shm:/dev/shm --ipc=host --shm-size=100g "
        f"{' '.join(extra)} {image()} bash"
    )


def running_containers():
    """Names of the currently running containers."""
    try:
        p = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                           capture_output=True)
    except FileNotFoundError:
        return []
    return p.stdout.decode(errors="replace").split()


def emulator_containers_running():
    """Are the emu_N worker containers up?

    Checking `docker ps` for the substring "emu_" is not enough: the *image*
    names (ta_emu_ae, ta_emu_ae_ctl) contain it as well, so the check has to
    look at container names only.
    """
    return any(n.startswith(emu_prefix()) for n in running_containers())


def redis_container_running():
    return any("redis" in n for n in running_containers())


# --------------------------------------------------------------- worker pools
# The evaluation scripts fan out over python worker *processes*. Each worker is
# a full copy of the data it is handed, so an oversized pool does not just
# thrash - it gets a child SIGKILLed by the OOM killer, which surfaces as
#
#   concurrent.futures.process.BrokenProcessPool: A process in the process pool
#   was terminated abruptly while the future was running or pending
#
# with no other diagnostic. Size the pools from the machine, the way ae/ae.sh
# sizes AE_JOBS for the emulator containers.

def _cgroup_limit_mb():
    """Memory ceiling of our cgroup, or None.

    Inside a container /proc/meminfo reports the *host*, so a `--memory` limit
    (or Docker Desktop's VM cap) is invisible there. cgroup v2 first, then v1.
    """
    for path in ("/sys/fs/cgroup/memory.max",
                 "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            raw = open(path).read().strip()
        except OSError:
            continue
        if raw == "max":
            continue
        try:
            v = int(raw)
        except ValueError:
            continue
        # v1 reports a sentinel close to 2**63 when unlimited.
        if 0 < v < (1 << 62):
            return v // (1024 * 1024)
    return None


def available_mb():
    """Memory we may actually use, in MB: min(cgroup limit, MemAvailable)."""
    vals = []
    lim = _cgroup_limit_mb()
    if lim:
        vals.append(lim)
    try:
        for line in open("/proc/meminfo"):
            if line.startswith("MemAvailable:"):
                vals.append(int(line.split()[1]) // 1024)
                break
    except OSError:
        pass
    return min(vals) if vals else 0


def pool_workers(per_worker_mb, n_items=None, env_var=None, reserve_mb=1024):
    """How many worker processes this machine can afford.

    per_worker_mb  peak resident size of one worker, measured generously
    n_items        never start more workers than there is work
    env_var        name of a knob that overrides the calculation outright
    """
    for var in ([env_var] if env_var else []) + ["AE_POOL_WORKERS"]:
        raw = os.environ.get(var)
        if raw:
            try:
                return max(1, int(raw))
            except ValueError:
                pass

    n = os.cpu_count() or 2
    # AE_JOBS is what ae/ae.sh decided this machine can run in parallel; the
    # python pools have no reason to be wider than that.
    try:
        n = min(n, int(os.environ.get("AE_JOBS", n)))
    except ValueError:
        pass

    mem = available_mb()
    if mem > 0:
        n = min(n, max(1, (mem - reserve_mb) // max(1, per_worker_mb)))
    if n_items:
        n = min(n, n_items)
    return max(1, int(n))
