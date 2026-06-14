.PHONY: phone emulator clean

phone:
ifndef ANDROID_NDK
	$(error ANDROID_NDK is not set. It should be like XX/Android/ndk/26.*)
endif	
	$(ANDROID_NDK)/ndk-build
	cp libs/armeabi-v7a/poc ./poc 
	adb push poc /data/local/tmp/

# -Wno-incompatible-pointer-types: this host ships gcc 16, which promotes the
# pre-existing shm_p[] assignment in the VERBATIM shared repro.h (line 463) to a
# hard error. The flag restores the legacy-toolchain default so the unmodified
# repro.h/poc.c build cleanly; it is the only delta from gatekeeper_throttle's
# Makefile.
emulator:
	cd jni && gcc -g3 -O0 -DEMULATE -Wno-incompatible-pointer-types poc.c -o ../poc

docker:
	cd jni && gcc -g3 -O0 -DEMULATE -Wno-incompatible-pointer-types poc.c -o ../poc
	docker cp poc emu:/
	docker exec -it emu /poc


clean:
	$(RM) -rf libs/ obj/ ./poc
