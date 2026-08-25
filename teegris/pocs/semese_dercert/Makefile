.PHONY: phone emulator clean

phone:
ifndef ANDROID_NDK
	$(error ANDROID_NDK is not set. It should be like XX/Android/ndk/26.*)
endif	
	$(ANDROID_NDK)/ndk-build
	cp libs/armeabi-v7a/poc ./poc 
	adb push poc /data/local/tmp/

emulator:
	# -Wno-error=incompatible-pointer-types: the verbatim shared repro.h has a
	# TEEC_TempMemoryReference*->TEEC_SharedMemory* assign that GCC 14+ promotes
	# from warning to error; keep it a warning so the (unmodified) helper builds.
	cd jni && gcc -g3 -O0 -DEMULATE -Wno-error=incompatible-pointer-types poc.c -o ../poc

docker:
	cd jni && gcc -g3 -O0 -DEMULATE poc.c -o ../poc
	docker cp poc emu:/
	docker exec -it emu /poc


clean:
	$(RM) -rf libs/ obj/ ./poc
