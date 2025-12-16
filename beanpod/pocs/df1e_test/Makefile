.PHONY: phone emulator clean

phone:
ifndef ANDROID_NDK
	$(error ANDROID_NDK is not set. It should be like XX/Android/ndk/26.*)
endif	
	$(ANDROID_NDK)/ndk-build
	cp libs/arm64-v8a/poc ./poc 
	adb push poc /data/local/tmp/

emulator:
	cd jni && gcc -g3 -O0 -DEMULATE poc.c -o ../poc

docker:
	cd jni && gcc -g3 -O0 -DEMULATE poc.c -o ../poc
	docker cp poc emu:/
	docker exec -it emu /poc


clean:
	$(RM) -rf libs/ obj/ ./poc
