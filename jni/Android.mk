LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := widevine-spoof
LOCAL_SRC_FILES := module.cpp
LOCAL_LDLIBS := -llog -ldl -landroid
LOCAL_CPPFLAGS := -std=c++17 -fno-exceptions -fno-rtti -O2
include $(BUILD_SHARED_LIBRARY)
