ifndef TARGET
$(error Missing TARGET)
endif


GCC_VERSION := 12.3.0

CC := $(OPENWRT_DIR)/staging_dir/toolchain-$(TARGET)_gcc-$(GCC_VERSION)_musl/bin/$(TARGET)-openwrt-linux-musl-gcc
CXX := $(OPENWRT_DIR)/staging_dir/toolchain-$(TARGET)_gcc-$(GCC_VERSION)_musl/bin/$(TARGET)-openwrt-linux-musl-g++
CPPFLAGS += -I$(OPENWRT_DIR)/staging_dir/target-$(TARGET)_musl/usr/include
LDFLAGS += -L$(OPENWRT_DIR)/staging_dir/target-$(TARGET)_musl/usr/lib

STAGING_DIR = $(OPENWRT_DIR)/staging_dir/toolchain-$(TARGET)_gcc-$(GCC_VERSION)_musl:$(OPENWRT_DIR)/staging_dir/target-$(TARGET)_musl/usr
export STAGING_DIR
