LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := poc
LOCAL_CFLAGS += -std=c99 -ggdb
LOCAL_SRC_FILES := poc.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)
# On-device build resolves libteec at runtime via dlopen (see repro.h #else).
LOCAL_LDLIBS := -ldl

include $(BUILD_EXECUTABLE)
