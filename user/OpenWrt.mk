ARCH ?= $(shell uname -m)

TOOLCHAIN_DIR := $(lastword $(wildcard $(OPENWRT_DIR)/staging_dir/toolchain-$(ARCH)_*gcc-*_musl*))
TARGET_DIR    :=            $(wildcard $(OPENWRT_DIR)/staging_dir/target-$(ARCH)_*musl*)

ifndef TOOLCHAIN_DIR
$(error "No toolchain directory found in $(OPENWRT_DIR)/staging_dir for arch $(ARCH)")
endif

CC := $(notdir $(wildcard $(TOOLCHAIN_DIR)/bin/$(ARCH)-openwrt-linux-musl*-gcc))
CFLAGS 	+= -I$(TARGET_DIR)/usr/include
LDFLAGS += -L$(TARGET_DIR)/usr/lib

export PATH 	   := $(PATH):$(TOOLCHAIN_DIR)/bin
export STAGING_DIR := $(TOOLCHAIN_DIR):$(TARGET_DIR)/usr
