.PHONY: emulator docker device clean

# Build for the taemu emulator (talks to the emulator socket on 127.0.0.1:1337).
emulator:
	cd jni && gcc -g3 -O0 -DEMULATE poc.c -o ../poc

# Same, then copy into the running emulator docker container and execute it.
docker: emulator
	docker cp poc emu:/
	docker exec -it emu /poc

# Build a real normal-world CA for the device (links the OP-TEE client, libteec).
# Override CC/sysroot as needed for your aarch64 toolchain.
device:
	cd jni && $(CC) -g -O2 poc.c -o ../poc -ldl

clean:
	$(RM) -f ./poc
