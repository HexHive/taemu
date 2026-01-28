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
```
gdb-multiarch -ex "target remote localhost:9999"
```

*qiling's gdb server is a bit broken, stepping etc will break often* 
*blata24 gef works (normal gef doesn't)*

To interact with the emulated TA, write a poc (see `example_poc`) and compile with `make` 

### Run POC against actual phone

compile for phone:
```
wget https://dl.google.com/android/repository/android-ndk-r27c-linux.zip
unzip android-ndk-r27c-linux.zip
ANDROID_NDK=$(pwd)/android-ndk-r27c make phone
```

## Fuzzing

setup a folder with the following file in  `<tee>/harness/`

`harness.py`: the callback to place fuzzing input, see `beanpod/harness/0811_test/harness.py` for an example.
`in`: (optional) the input seed directory
symbolic link to the target ta `ln -s ../../tas/<target-ta>.ta .`
symbolic link to the target ta json `ln -s ../../tas/<target-ta>.json .`

afterwards run the fuzzer with: 

`./fuzz.sh <tee>/harness/<harness-folder>`

(fuzz and generate a crash if an api is not implemented:)

`TAEMU_CRASH_NOTIMPL=1 ./fuzz.sh <tee>/harness/<harness-folder>`

replay seeds with:

`./fuzz.sh <tee>/harness/<harness-folder> <path-to-seed>`

for gdb:
`./fuzz.sh <tee>/harness/<harness-folder> <path-to-seed> -g`

