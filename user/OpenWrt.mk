ARCH ?= $(shell uname -m)
GCC  ?= 14.1.0

TOOLCHAIN_DIR := $(wildcard $(OPENWRT_DIR)/staging_dir/toolchain-$(ARCH)_*gcc-$(GCC)_musl*)
TARGET_DIR    := $(wildcard $(OPENWRT_DIR)/staging_dir/target-$(ARCH)_*musl*)

export PATH 	   := $(PATH):$(TOOLCHAIN_DIR)/bin
export STAGING_DIR := $(TOOLCHAIN_DIR):$(TARGET_DIR)/usr

CC := $(notdir $(wildcard $(TOOLCHAIN_DIR)/bin/$(ARCH)-openwrt-linux-musl*-gcc))

CFLAGS 	+= -I$(TARGET_DIR)/usr/include
LDFLAGS += -L$(TARGET_DIR)/usr/lib
