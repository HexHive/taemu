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
