LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := dobby
LOCAL_SRC_FILES := dobby/lib/$(TARGET_ARCH_ABI)/libdobby.a
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := widevine-spoof
LOCAL_SRC_FILES := module.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)
LOCAL_STATIC_LIBRARIES := dobby
LOCAL_LDLIBS := -llog -ldl -landroid -lmediandk
LOCAL_CPPFLAGS := -std=c++17 -fno-exceptions -fno-rtti -O2 -fvisibility=hidden
include $(BUILD_SHARED_LIBRARY)
