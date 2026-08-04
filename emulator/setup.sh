#!/bin/sh

if [ ! -d "qiling" ]; then
    echo "[*] Cloning Qiling framework..."
else
    echo "[*] Qiling framework already exists, skipping clone."
    echo "    Do you want to completely re-setup the emulator environment? (y/N)"
    read answer
    if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
        rm -rf qiling
        echo "[*] Removed existing Qiling directory."
        echo "[*] Re-cloning Qiling framework..."
    else
        echo "[*] Skipping re-setup."
        exit 0
    fi
fi

git clone -b dev https://github.com/qilingframework/qiling.git
cd qiling && git checkout 56dd77b6608698bfe54f4bde01981a40609c9532 && git apply ../qiling.diff && git submodule update --init --recursive && pip3 install . && cd ..
pip3 install -r requirements.txt