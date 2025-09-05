.PHONY: phone 

phone:
ifndef ANDROID_NDK
	$(error ANDROID_NDK is not set. It should be like XX/Android/ndk/26.*)
endif	
	$(ANDROID_NDK)/ndk-build
	cp obj/local/arm64-v8a/poc .
	adb push poc /data/local/tmp/

clean:
	$(RM) -rf libs/ obj/ ./poc
