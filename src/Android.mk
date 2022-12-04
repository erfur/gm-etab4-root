LOCAL_PATH := $(call my-dir)
 
include $(CLEAR_VARS)
 
LOCAL_MODULE    := exynos-abuse
LOCAL_SRC_FILES := exynos-abuse.c hexdump.c
 
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
 
LOCAL_MODULE    := strtok-test
LOCAL_SRC_FILES := strtok-test.c
 
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
 
LOCAL_MODULE    := root
LOCAL_SRC_FILES := root.c
 
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
 
LOCAL_MODULE    := patch-kallsyms
LOCAL_SRC_FILES := patch-kallsyms.c
 
include $(BUILD_EXECUTABLE)