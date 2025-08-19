.PHONY: phone emulator clean warn

phone:
ifndef ANDROID_NDK
	$(error ANDROID_NDK is not set. It should be like XX/Android/ndk/26.*)
endif	
	$(ANDROID_NDK)/ndk-build
	cp libs/armeabi-v7a/poc ./poc 
	adb push poc /data/local/tmp/

warn:
	@echo "[!!!] Only the TA's address and the loader's address are accurate in the emulator [!!!]"
	@echo "[!!!] All other memory regions are emulator specific or may be at different addresses [!!!]"

emulator:
	make warn
	cd jni && gcc -g3 -O0 -DEMULATE poc.c -o ../poc
	./poc

docker:
	make warn
	cd jni && gcc -g3 -O0 -DEMULATE poc.c -o ../poc
	docker cp poc emu:/
	docker exec -it emu /poc

clean:
	$(RM) -rf libs/ obj/ ./poc
