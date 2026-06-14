.PHONY: phone emulator clean

phone:
ifndef ANDROID_NDK
	$(error ANDROID_NDK is not set. It should be like XX/Android/ndk/26.*)
endif	
	$(ANDROID_NDK)/ndk-build
	cp libs/armeabi-v7a/poc ./poc 
	adb push poc /data/local/tmp/

# NOTE: -Wno-incompatible-pointer-types only restores the pre-gcc-16 default
# (it was a warning when the corpus POCs were authored). It is needed solely
# because the *verbatim, shared* jni/repro.h assigns a TEEC_TempMemoryReference*
# into the TEEC_SharedMemory* shm_p[] slot inside allocate_param_mem(); gcc 16
# promotes that to a hard error. The flag changes no build semantics. The rest
# of this Makefile is verbatim from gatekeeper_throttle.
emulator:
	cd jni && gcc -g3 -O0 -DEMULATE -Wno-incompatible-pointer-types poc.c -o ../poc

docker:
	cd jni && gcc -g3 -O0 -DEMULATE -Wno-incompatible-pointer-types poc.c -o ../poc
	docker cp poc emu:/
	docker exec -it emu /poc


clean:
	$(RM) -rf libs/ obj/ ./poc
