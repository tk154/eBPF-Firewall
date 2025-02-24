LIBC ?= musl
ARCH ?= $(shell uname -m)
SUFFIX ?= *

TOOLCHAIN_DIR := $(lastword $(wildcard $(OPENWRT_DIR)/staging_dir/toolchain-$(ARCH)_$(SUFFIX)_gcc-*_$(LIBC)*))
TARGET_DIR    := $(lastword $(wildcard $(OPENWRT_DIR)/staging_dir/target-$(ARCH)_$(SUFFIX)_$(LIBC)*))
CC			  := $(notdir   $(wildcard $(TOOLCHAIN_DIR)/bin/$(ARCH)*-openwrt-linux-musl*-gcc))

ifndef TOOLCHAIN_DIR
$(error "'$(OPENWRT_DIR)/staging_dir/toolchain-$(ARCH)_$(SUFFIX)' not found")
endif

ifndef CC
$(error "GCC compiler '$(TOOLCHAIN_DIR)/bin/$(ARCH)*-openwrt-linux-musl*' not found")
endif

CFLAGS 	+= -I$(TARGET_DIR)/usr/include
LDFLAGS += -L$(TARGET_DIR)/usr/lib

export PATH 	   := $(PATH):$(TOOLCHAIN_DIR)/bin
export STAGING_DIR := $(TOOLCHAIN_DIR):$(TARGET_DIR)/usr
