.PHONY: phone emulator clean

phone:
ifndef ANDROID_NDK
	$(error ANDROID_NDK is not set. It should be like XX/Android/ndk/26.*)
endif	
	$(ANDROID_NDK)/ndk-build
	cp libs/armeabi-v7a/poc ./poc 
	adb push poc /data/local/tmp/

emulator:
	# -Wno-incompatible-pointer-types: the verbatim shared repro.h assigns a
	# TEEC_TempMemoryReference* into a TEEC_SharedMemory* slot (allocate_param_mem,
	# repro.h:463). GCC 16 on this host promotes that legacy-C mismatch to a hard
	# error by default (older GCCs only warned); downgrade it so the unmodified
	# header still builds. poc.c itself is clean.
	cd jni && gcc -g3 -O0 -DEMULATE -Wno-incompatible-pointer-types poc.c -o ../poc

docker:
	cd jni && gcc -g3 -O0 -DEMULATE poc.c -o ../poc
	docker cp poc emu:/
	docker exec -it emu /poc


clean:
	$(RM) -rf libs/ obj/ ./poc
