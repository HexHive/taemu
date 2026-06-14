.PHONY: phone emulator clean

phone:
ifndef ANDROID_NDK
	$(error ANDROID_NDK is not set. It should be like XX/Android/ndk/26.*)
endif	
	$(ANDROID_NDK)/ndk-build
	cp libs/armeabi-v7a/poc ./poc 
	adb push poc /data/local/tmp/

# NOTE: -Wno-incompatible-pointer-types is needed only because GCC 14+ promoted
# that warning to a hard error by default, and the *verbatim* shared repro.h
# (copied unchanged from gatekeeper_throttle) assigns a TEEC_TempMemoryReference*
# into a TEEC_SharedMemory* slot in allocate_param_mem (repro.h:463). The flag
# keeps the shared header untouched; on the older gcc the campaign's POCs used,
# the rest of the recipe is byte-identical to gatekeeper_throttle/Makefile.
emulator:
	cd jni && gcc -g3 -O0 -DEMULATE -Wno-incompatible-pointer-types poc.c -o ../poc

docker:
	cd jni && gcc -g3 -O0 -DEMULATE -Wno-incompatible-pointer-types poc.c -o ../poc
	docker cp poc emu:/
	docker exec -it emu /poc


clean:
	$(RM) -rf libs/ obj/ ./poc
