.PHONY: phone

phone:
ifndef ANDROID_NDK
	$(error ANDROID_NDK is not set. It should be like XX/Android/ndk/26.*)
endif	
	$(ANDROID_NDK)/ndk-build
	cp obj/local/arm64-v8a/poc ./poc
	adb push poc /data/local/tmp/
	adb push jni /data/local/tmp
	#adb shell su -c 'cp /data/local/tmp/poc /data/adb/modules/magisk_poc/system/vendor/bin/poc'
	#adb shell su -c reboot

clean:
	$(RM) -rf libs/ obj/ ./poc
