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

# TODO

Bump afl++ / unicornAfl to version with cmplog support
multiple command ids

# Double Fetch Sanity Check

```
./fuzz.sh ../mitee/harness/377e_double_fetch_stackov/ 
# -> meta second entry should be the relevant df
AFL_DEBUG=1 ./df_fuzz.sh ../mitee/harness/377e_double_fetch_stackov/ ../mitee/harness/377e_double_fetch_stackov/in/suspicious_inputs/run\:id\:d3b07384d113edec49eaa6238ad5ff00 205374383998289612021010690897642464208
# different sizes for memmove should be correct
``` 

