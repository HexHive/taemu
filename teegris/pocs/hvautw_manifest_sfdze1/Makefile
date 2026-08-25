.PHONY: phone emulator clean

phone:
ifndef ANDROID_NDK
	$(error ANDROID_NDK is not set. It should be like XX/Android/ndk/26.*)
endif	
	$(ANDROID_NDK)/ndk-build
	cp libs/armeabi-v7a/poc ./poc 
	adb push poc /data/local/tmp/

# -Wno-incompatible-pointer-types: the VERBATIM repro.h (copied byte-identical
# from gatekeeper_throttle/jni) assigns a TEEC_TempMemoryReference* into the
# TEEC_SharedMemory* shm_p[] table at repro.h:463. gcc-16 on this host promotes
# -Wincompatible-pointer-types to a hard error by default; the demote keeps the
# 4 headers/mk byte-verbatim while letting the PoC build. Flag added ONLY here.
emulator:
	cd jni && gcc -g3 -O0 -Wno-incompatible-pointer-types -DEMULATE poc.c -o ../poc

docker:
	cd jni && gcc -g3 -O0 -Wno-incompatible-pointer-types -DEMULATE poc.c -o ../poc
	docker cp poc emu:/
	docker exec -it emu /poc


clean:
	$(RM) -rf libs/ obj/ ./poc
