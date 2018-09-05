# Copyright (C) 2009 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
LOCAL_PATH := $(call my-dir)

#include $(CLEAR_VARS)
#LOCAL_MODULE := libssl
#LOCAL_SRC_FILES := openssl/libs/$(TARGET_ARCH_ABI)/libssl.so
#LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/openssl/include
#include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libcrypto
LOCAL_SRC_FILES := openssl/libs/$(TARGET_ARCH_ABI)/libcrypto.a
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/openssl/include
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libssl
LOCAL_SRC_FILES := openssl/libs/$(TARGET_ARCH_ABI)/libssl.a
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/openssl/include
include $(PREBUILT_STATIC_LIBRARY)


include $(CLEAR_VARS)
LOCAL_CFLAGS := -g -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast
LOCAL_MODULE    := async_tcp
LOCAL_SRC_FILES := async_tcp.c socket.c

#libssl must before libcrypto
LOCAL_STATIC_LIBRARIES :=  libssl libcrypto

LOCAL_LDLIBS = -landroid -llog -lz 

include $(BUILD_SHARED_LIBRARY)
