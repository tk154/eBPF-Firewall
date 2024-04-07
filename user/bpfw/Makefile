ifdef OPENWRT_DIR
include ../OpenWrt.mk
endif

LDLIBS := -lbpf -lelf -lz -lnetfilter_conntrack -lnfnetlink -lmnl

OUT_DIR := bin/$(TARGET)
OUT_BIN := $(OUT_DIR)/bpfw

MAIN_SRC := main.c

SOURCES := $(shell find -name "*.c" ! -name $(MAIN_SRC))
OBJECTS := $(patsubst %.c,$(OUT_DIR)/%.o,$(notdir $(SOURCES)))

vpath %.c $(dir $(SOURCES))


$(OUT_BIN): $(MAIN_SRC) $(OBJECTS)
	$(CC) $(CPPFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(OUT_DIR)/%.o: %.c | $(OUT_DIR)
	$(CC) $(CPPFLAGS) -c $< -o $@

$(OUT_DIR):
	@mkdir -p $(OUT_DIR)

clean:
	@rm -rf $(OUT_DIR)
