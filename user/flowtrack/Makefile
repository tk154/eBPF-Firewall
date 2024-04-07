ifdef OPENWRT_DIR
include ../OpenWrt.mk
endif

LDLIBS := -lbpf -lelf -lz

OUT_DIR := bin/$(TARGET)
OUT_BIN := $(OUT_DIR)/flowtrack

MAIN_SRC := main.c


$(OUT_BIN): $(MAIN_SRC) | $(OUT_DIR)
	$(CC) $(CPPFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

$(OUT_DIR):
	@mkdir -p $(OUT_DIR)

clean:
	@rm -rf $(OUT_DIR)
