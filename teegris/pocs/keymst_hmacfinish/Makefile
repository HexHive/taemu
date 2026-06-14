.PHONY: phone emulator clean

phone:
ifndef ANDROID_NDK
	$(error ANDROID_NDK is not set. It should be like XX/Android/ndk/26.*)
endif	
	$(ANDROID_NDK)/ndk-build
	cp libs/armeabi-v7a/poc ./poc 
	adb push poc /data/local/tmp/

# NOTE: -Wno-incompatible-pointer-types is the ONLY divergence from the
# verbatim gatekeeper_throttle Makefile. The shared shim jni/repro.h (copied
# byte-identical) has a TEEC_TempMemoryReference*->TEEC_SharedMemory* assignment
# at repro.h:463 that gcc >=14 (this host: gcc 16.1.1) rejects by default; every
# sibling POC's `make emulator` fails identically on it. poc.c itself is clean.
emulator:
	cd jni && gcc -g3 -O0 -DEMULATE -Wno-incompatible-pointer-types poc.c -o ../poc

docker:
	cd jni && gcc -g3 -O0 -DEMULATE -Wno-incompatible-pointer-types poc.c -o ../poc
	docker cp poc emu:/
	docker exec -it emu /poc


clean:
	$(RM) -rf libs/ obj/ ./poc
