ifdef OPENWRT_DIR
include OpenWrt.mk
endif

LDLIBS := -lbpf -lelf -lz -lnetfilter_conntrack -lnfnetlink -lmnl

OUT_DIR := bin/$(TARGET)
OUT_BIN := $(OUT_DIR)/bpfw

SOURCE_DIRS := bpf_loader conntrack

SOURCES := 
$(foreach dir,$(SOURCE_DIRS),$(eval SOURCES += $(wildcard $(dir)/*.c)))

OBJECTS := $(patsubst %.c,$(OUT_DIR)/%.o,$(notdir $(SOURCES)))

$(OUT_BIN): main.c $(OBJECTS) | $(OUT_DIR)
	$(CC) $(CPPFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(OUT_DIR)/%.o: */%.c | $(OUT_DIR)
	$(CC) $(CPPFLAGS) -c $< -o $@

$(OUT_DIR):
	@mkdir -p $(OUT_DIR)

clean:
	@rm -rf $(OUT_DIR)
