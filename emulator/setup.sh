#!/bin/sh

git clone -b dev https://github.com/qilingframework/qiling.git
cd qiling && git checkout 56dd77b6608698bfe54f4bde01981a40609c9532 && git apply ../qiling.diff && git submodule update --init --recursive && pip3 install . && cd ..
pip3 install -r requirements.txt

