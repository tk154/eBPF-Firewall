ifndef TARGET
$(error Missing TARGET)
endif

define first_wildcard_match
	$(shell set -- $(1); echo "$$1")
endef


GCC_VERSION := 13.3.0

TOOLCHAIN_DIR := $(call first_wildcard_match,$(OPENWRT_DIR)/staging_dir/toolchain-$(TARGET)*_gcc-$(GCC_VERSION)_musl*)
TARGET_DIR    := $(call first_wildcard_match,$(OPENWRT_DIR)/staging_dir/target-$(TARGET)*_musl*)

CC  := $(call first_wildcard_match,$(TOOLCHAIN_DIR)/bin/$(TARGET)-openwrt-linux-musl*-gcc)
CXX := $(call first_wildcard_match,$(TOOLCHAIN_DIR)/bin/$(TARGET)-openwrt-linux-musl*-g++)

CPPFLAGS += -I$(TARGET_DIR)/usr/include
LDFLAGS  += -L$(TARGET_DIR)/usr/lib

export STAGING_DIR = $(TOOLCHAIN_DIR):$(TARGET_DIR)/usr
