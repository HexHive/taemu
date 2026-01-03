import os


def list_tas(path="/root/TA_GP_emulator"):
    return set([f for f in os.listdir(path) if f.endswith(".ta")])