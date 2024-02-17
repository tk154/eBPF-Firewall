ifndef TARGET
$(error Missing TARGET)
endif


GCC_VERSION := 12.3.0

TOOLCHAIN_DIR := $(shell set -- $(OPENWRT_DIR)/staging_dir/toolchain-$(TARGET)*_gcc-$(GCC_VERSION)_musl; echo "$$1")
TARGET_DIR    := $(shell set -- $(OPENWRT_DIR)/staging_dir/target-$(TARGET)*_musl; echo "$$1")

CC  := $(TOOLCHAIN_DIR)/bin/$(TARGET)-openwrt-linux-musl-gcc
CXX := $(TOOLCHAIN_DIR)/bin/$(TARGET)-openwrt-linux-musl-g++

CPPFLAGS += -I$(TARGET_DIR)/usr/include
LDFLAGS  += -L$(TARGET_DIR)/usr/lib

export STAGING_DIR = $(TOOLCHAIN_DIR):$(TARGET_DIR)/usr
