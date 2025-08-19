# GP TA Emulator 

## Setup

```
./build-docker.sh
```

## Run

```
./run-docker.sh
```

to run the `0811...` beanpod TA:

```
./run.sh ../beanpod/tas/08110000000000000000000000000000.ta
```

to run the `0811...` beanpod TA with the gdb stub:

```
./gdb.sh ../beanpod/tas/08110000000000000000000000000000.ta
```

## Emulation setup

### Run POC against emulator

Start the emulator:
```
make build
make run
```

Compile and run your poc against the emulator:
```
cd template
make docker
```

### Run POC against emulator with gdb

Run emulator with gdb:
```
make gdb
```

(you need to run the poc so the emulator spawns the gdb server)
```
cd template
make docker
```

```
gdb-multiarch -ex "target remote localhost:9999"
```

*qiling's gdb server is a bit broken, stepping etc will break often* 
*blata24 gef works (normal gef doesn't)*

## Run against actual phone

compile for phone:
```
wget https://dl.google.com/android/repository/android-ndk-r27c-linux.zip
unzip android-ndk-r27c-linux.zip
ANDROID_NDK=$(pwd)/android-ndk-r27c make phone
```

go to admin desk and ask for keyinstall phone

interact with phone:
```
#(1) install adb
adb push poc /data/local/tmp
adb shell /data/local/tmp/poc
```
