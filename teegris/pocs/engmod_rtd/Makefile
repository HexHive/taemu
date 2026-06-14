.PHONY: phone emulator clean

phone:
ifndef ANDROID_NDK
	$(error ANDROID_NDK is not set. It should be like XX/Android/ndk/26.*)
endif	
	$(ANDROID_NDK)/ndk-build
	cp libs/armeabi-v7a/poc ./poc 
	adb push poc /data/local/tmp/

# -Wno-incompatible-pointer-types: GCC >= 14 promotes this to an error by
# default; the offending assignment is inside the SHARED jni/repro.h helper
# (shm_p[i] = memref;), identical for every POC in this tree. The flag
# restores the pre-GCC16 semantics the campaign's repro.h was authored for.
# poc.c itself is warning-clean.
emulator:
	cd jni && gcc -g3 -O0 -DEMULATE -Wno-incompatible-pointer-types poc.c -o ../poc

docker:
	cd jni && gcc -g3 -O0 -DEMULATE -Wno-incompatible-pointer-types poc.c -o ../poc
	docker cp poc emu:/
	docker exec -it emu /poc


clean:
	$(RM) -rf libs/ obj/ ./poc
